using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Services
{
    public class ArpSeenEventArgs : EventArgs
    {
        public string Ip { get; set; } = string.Empty;
        public string Mac { get; set; } = string.Empty;
    }

    public class FlowSeenEventArgs : EventArgs
    {
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;
        public string? Protocol { get; set; }
        public int PacketBytes { get; set; }
    }

    public class PassiveCaptureService : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly object _lock = new object();
        private LibPcapLiveDevice? _device;
        private int _isRunning;

        public event EventHandler<ArpSeenEventArgs>? ArpSeen;
        public event EventHandler<FlowSeenEventArgs>? FlowSeen;

        public bool IsRunning => Volatile.Read(ref _isRunning) == 1;

        public void Start(string? deviceDescriptionOrName = null)
        {
            if (Interlocked.CompareExchange(ref _isRunning, 1, 0) != 0)
                throw new InvalidOperationException("Passive capture already running.");

            try
            {
                var devices = LibPcapLiveDeviceList.Instance;
                if (devices == null || devices.Count == 0)
                    throw new InvalidOperationException("No capture devices available — ensure Npcap is installed.");

                LibPcapLiveDevice? selected = null;
                if (!string.IsNullOrWhiteSpace(deviceDescriptionOrName))
                {
                    selected = devices.FirstOrDefault(d =>
                        (d.Description != null && d.Description.IndexOf(deviceDescriptionOrName!, StringComparison.OrdinalIgnoreCase) >= 0)
                        || string.Equals(d.Name, deviceDescriptionOrName, StringComparison.OrdinalIgnoreCase));
                }
                selected ??= devices.FirstOrDefault(d =>
                    !string.IsNullOrWhiteSpace(d.Description)
                    && d.Description!.IndexOf("loopback", StringComparison.OrdinalIgnoreCase) < 0);
                selected ??= devices[0];

                _device = selected;
                _device.Open(DeviceModes.Promiscuous, 1000);
                try { _device.Filter = "ip or arp"; }
                catch (Exception ex) { Logger.Debug(ex, "Passive capture BPF filter rejected"); }
                _device.OnPacketArrival += OnPacketArrival;
                _device.StartCapture();

                Logger.Info($"Passive capture started on {_device.Description ?? _device.Name}");
            }
            catch
            {
                Interlocked.Exchange(ref _isRunning, 0);
                CleanupDevice();
                throw;
            }
        }

        public void Stop()
        {
            if (Interlocked.CompareExchange(ref _isRunning, 0, 1) != 1) return;
            CleanupDevice();
        }

        public void Dispose() => Stop();

        private void CleanupDevice()
        {
            lock (_lock)
            {
                if (_device == null) return;
                try { _device.OnPacketArrival -= OnPacketArrival; } catch { }
                try { _device.StopCapture(); } catch { }
                try { _device.Close(); } catch { }
                _device = null;
            }
        }

        private void OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var raw = e.GetPacket();
                var data = raw.Data;
                if (data == null || data.Length == 0) return;

                var packet = Packet.ParsePacket(raw.LinkLayerType, data);
                if (packet == null) return;

                try
                {
                    var arp = packet.Extract<ArpPacket>();
                    if (arp != null)
                    {
                        var senderIp = arp.SenderProtocolAddress?.ToString();
                        var senderMac = FormatMac(arp.SenderHardwareAddress);
                        if (!string.IsNullOrWhiteSpace(senderIp)
                            && !string.IsNullOrWhiteSpace(senderMac)
                            && senderIp != "0.0.0.0"
                            && senderMac != "00:00:00:00:00:00")
                        {
                            ArpSeen?.Invoke(this, new ArpSeenEventArgs { Ip = senderIp!, Mac = senderMac! });
                        }

                        var targetIp = arp.TargetProtocolAddress?.ToString();
                        var targetMac = FormatMac(arp.TargetHardwareAddress);
                        if (!string.IsNullOrWhiteSpace(targetIp)
                            && !string.IsNullOrWhiteSpace(targetMac)
                            && targetIp != "0.0.0.0"
                            && targetMac != "00:00:00:00:00:00")
                        {
                            ArpSeen?.Invoke(this, new ArpSeenEventArgs { Ip = targetIp!, Mac = targetMac! });
                        }
                    }
                }
                catch (Exception ex) { Logger.Debug(ex, "ARP parse failed"); }

                try
                {
                    var ipv4 = packet.Extract<IPv4Packet>();
                    if (ipv4 != null)
                    {
                        FlowSeen?.Invoke(this, new FlowSeenEventArgs
                        {
                            SourceIp = ipv4.SourceAddress?.ToString() ?? string.Empty,
                            DestinationIp = ipv4.DestinationAddress?.ToString() ?? string.Empty,
                            Protocol = ipv4.Protocol.ToString(),
                            PacketBytes = data.Length
                        });
                    }
                }
                catch (Exception ex) { Logger.Debug(ex, "IPv4 parse failed"); }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Packet parse outer failure");
            }
        }

        private static string? FormatMac(PhysicalAddress? addr)
        {
            if (addr == null) return null;
            var bytes = addr.GetAddressBytes();
            if (bytes == null || bytes.Length == 0) return null;
            return string.Join(":", bytes.Select(b => b.ToString("x2")));
        }
    }
}
