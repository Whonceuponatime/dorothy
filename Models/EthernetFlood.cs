using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using NLog;
using System.Diagnostics;

namespace Dorothy.Models
{
    public class EthernetFlood : IDisposable
    {
        private readonly PacketParameters _parameters;
        private readonly CancellationToken _cancellationToken;
        private readonly EthernetPacketType _packetType;
        private readonly bool _useIPv6;
        private LibPcapLiveDevice? _device;
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private const int PacketSize = 1400; // Standard size for good throughput
        private const int MICRO_BATCH_SIZE = 10; // Send packets in small batches for better rate control
        public event EventHandler<PacketEventArgs>? PacketSent;

        public enum EthernetPacketType
        {
            Unicast,
            Multicast,
            Broadcast
        }

        public EthernetFlood(PacketParameters parameters, EthernetPacketType packetType, CancellationToken cancellationToken, bool useIPv6 = false)
        {
            _parameters = parameters;
            _packetType = packetType;
            _cancellationToken = cancellationToken;
            _useIPv6 = useIPv6 || parameters.SourceIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        public async Task StartAsync()
        {
            try
            {
                var allDevices = CaptureDeviceList.Instance;
                _device = allDevices.OfType<LibPcapLiveDevice>()
                    .FirstOrDefault(d => d.Interface.Addresses
                        .Any(a => a.Addr?.ipAddress?.ToString() == _parameters.SourceIp.ToString()));

                if (_device == null)
                {
                    throw new Exception("No suitable network interface found");
                }

                _device.Open();
                Logger.Info($"Started Ethernet {_packetType} flood attack ({(_useIPv6 ? "IPv6" : "IPv4")})");

                // Create a sample packet to get actual size
                var samplePacket = CreatePacket();
                int totalPacketSize = samplePacket.Bytes.Length;
                
                // For pcap injection, use actual Ethernet frame size + 4 bytes FCS for wire size
                int wirePacketSize = totalPacketSize + 4; // Add FCS for wire size
                long targetBytesPerSecond = _parameters.BytesPerSecond;
                double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                Logger.Info($"Ethernet {_packetType} ({(_useIPv6 ? "IPv6" : "IPv4")}) wire packet size: {wirePacketSize} bytes, Target rate: {targetMbps:F2} Mbps");

                // Pre-generate packet pool for better performance
                var packetPool = new Packet[MICRO_BATCH_SIZE];
                for (int i = 0; i < MICRO_BATCH_SIZE; i++)
                {
                    packetPool[i] = CreatePacket();
                }

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    int poolIndex = 0;
                    
                    // Byte-budget rate control: track bytes sent vs time elapsed
                    long bytesSent = 0;
                    
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
                                    // Regenerate packet periodically for randomization
                                    if (poolIndex % 100 == 0)
                                    {
                                        packetPool[poolIndex] = CreatePacket();
                                    }
                                    
                                    // Send single packet
                                    var packet = packetPool[poolIndex];
                                    _device.SendPacket(packet);
                                    var packetBytes = packet.Bytes;
                                    OnPacketSent(packetBytes, _parameters.SourceIp, _parameters.DestinationIp, _parameters.DestinationPort);
                                    
                                    bytesSent += wirePacketSize;
                                    poolIndex = (poolIndex + 1) % MICRO_BATCH_SIZE;
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
                                
                                Logger.Info($"Ethernet {_packetType} ({(_useIPv6 ? "IPv6" : "IPv4")}) rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");
                                
                                // Reset measurement window
                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error($"Error sending packet: {ex.Message}");
                            throw;
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error($"Ethernet flood attack failed: {ex.Message}");
                throw;
            }
        }

        private Packet CreatePacket()
        {
            var ethernetPacket = CreateEthernetPacket();
            Packet ipPacket;
            
            if (_useIPv6)
            {
                ipPacket = CreateIPv6Packet();
            }
            else
            {
                ipPacket = CreateIPv4Packet();
            }
            
            ethernetPacket.PayloadPacket = ipPacket;
            return ethernetPacket;
        }

        private EthernetPacket CreateEthernetPacket()
        {
            PhysicalAddress destMac = _packetType switch
            {
                EthernetPacketType.Unicast => new PhysicalAddress(_parameters.DestinationMac),
                EthernetPacketType.Multicast => _useIPv6 
                    ? PhysicalAddress.Parse("33-33-00-00-00-01") // IPv6 multicast
                    : PhysicalAddress.Parse("01-00-5E-00-00-01"), // IPv4 multicast
                EthernetPacketType.Broadcast => PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                _ => throw new ArgumentException("Invalid Ethernet packet type")
            };

            var etherType = _useIPv6 ? EthernetType.IPv6 : EthernetType.IPv4;

            return new EthernetPacket(
                new PhysicalAddress(_parameters.SourceMac),
                destMac,
                etherType);
        }

        private IPv4Packet CreateIPv4Packet()
        {
            var payload = new byte[PacketSize];
            Random.Shared.NextBytes(payload);

            return new IPv4Packet(_parameters.SourceIp, _parameters.DestinationIp)
            {
                Protocol = ProtocolType.Raw,
                PayloadData = payload,
                TimeToLive = _parameters.Ttl
            };
        }

        private IPv6Packet CreateIPv6Packet()
        {
            var payload = new byte[PacketSize];
            Random.Shared.NextBytes(payload);

            return new IPv6Packet(_parameters.SourceIp, _parameters.DestinationIp)
            {
                PayloadData = payload,
                HopLimit = _parameters.Ttl
            };
        }

        public void Dispose()
        {
            if (_device != null)
            {
                if (_device.Opened)
                {
                    _device.Close();
                }
                _device.Dispose();
                Logger.Info("Ethernet flood device closed and disposed");
            }
        }
    }
} 