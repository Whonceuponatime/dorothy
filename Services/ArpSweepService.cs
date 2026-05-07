using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Services
{
    public class ArpSweepResult
    {
        public string Ip { get; set; } = string.Empty;
        public string Mac { get; set; } = string.Empty;
    }

    public class ArpSweepService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int BatchSize = 50;
        private const int BatchSpacingMs = 10;
        // Stealth: small batches with longer inter-batch gaps so ARP traffic
        // looks ambient rather than a sweep. 2 packets per batch + 100ms gap
        // ≈ 20 ARPs/sec, well below most IDS sweep-detection thresholds.
        private const int StealthBatchSize = 2;
        private const int StealthBatchSpacingMs = 100;
        private const int ListenTailMs = 2000;
        private const int MinAllowedPrefix = 16;

        public async Task<List<ArpSweepResult>> SweepAsync(
            string subnetCidr,
            string sourceIp,
            string? deviceDescriptionOrName,
            Action<ArpSweepResult>? onReplyReceived,
            CancellationToken cancellationToken,
            bool stealthMode = false)
        {
            if (string.IsNullOrWhiteSpace(subnetCidr))
                throw new ArgumentException("Subnet CIDR is required.", nameof(subnetCidr));

            var slash = subnetCidr.IndexOf('/');
            if (slash <= 0) throw new ArgumentException("Expected CIDR like 10.0.0.0/24.", nameof(subnetCidr));
            if (!int.TryParse(subnetCidr.Substring(slash + 1), out var prefix))
                throw new ArgumentException("Invalid CIDR prefix.", nameof(subnetCidr));
            if (prefix < MinAllowedPrefix)
                throw new ArgumentException(
                    $"Refusing ARP sweep on prefix /{prefix} — too large (minimum allowed is /{MinAllowedPrefix}).",
                    nameof(subnetCidr));
            if (prefix > 32)
                throw new ArgumentException("Invalid CIDR prefix.", nameof(subnetCidr));

            var baseIpStr = subnetCidr.Substring(0, slash);
            if (!IPAddress.TryParse(baseIpStr, out var baseIp) || baseIp.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Invalid base IP.", nameof(subnetCidr));
            if (!IPAddress.TryParse(sourceIp, out var srcIp) || srcIp.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Source IP must be IPv4.", nameof(sourceIp));

            var (nic, srcMacBytes) = ResolveNicAndMac(srcIp);
            if (nic == null || srcMacBytes == null || srcMacBytes.Length != 6)
                throw new InvalidOperationException("Could not resolve a NIC with MAC for the given source IP.");
            var srcMac = new PhysicalAddress(srcMacBytes);

            var devices = LibPcapLiveDeviceList.Instance;
            if (devices == null || devices.Count == 0)
                throw new InvalidOperationException("No capture devices available — ensure Npcap is installed.");

            LibPcapLiveDevice? device = null;
            if (!string.IsNullOrWhiteSpace(deviceDescriptionOrName))
            {
                device = devices.FirstOrDefault(d =>
                    (d.Description != null && d.Description.IndexOf(deviceDescriptionOrName!, StringComparison.OrdinalIgnoreCase) >= 0)
                    || string.Equals(d.Name, deviceDescriptionOrName, StringComparison.OrdinalIgnoreCase));
            }

            if (device == null && !string.IsNullOrWhiteSpace(nic.Description))
            {
                device = devices.FirstOrDefault(d =>
                    d.Description != null
                    && d.Description.IndexOf(nic.Description, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            if (device == null)
                throw new InvalidOperationException("Could not find a matching pcap device for the source IP.");

            var bytes = baseIp.GetAddressBytes();
            uint baseAddr = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
            uint network = baseAddr & mask;
            uint broadcast = network | ~mask;

            uint start = network;
            uint end = broadcast;
            if (prefix < 31)
            {
                start = network + 1;
                end = broadcast - 1;
            }

            var repliesLock = new object();
            var replies = new Dictionary<string, string>(StringComparer.Ordinal);

            try
            {
                device.Open(DeviceModes.Promiscuous, 500);
                try { device.Filter = "arp"; } catch { }

                void OnArrival(object sender, PacketCapture e)
                {
                    try
                    {
                        var raw = e.GetPacket();
                        var data = raw.Data;
                        if (data == null || data.Length == 0) return;

                        var packet = Packet.ParsePacket(raw.LinkLayerType, data);
                        var arp = packet?.Extract<ArpPacket>();
                        if (arp == null) return;
                        if (arp.Operation != ArpOperation.Response) return;

                        var senderIp = arp.SenderProtocolAddress?.ToString();
                        var senderHw = arp.SenderHardwareAddress?.GetAddressBytes();
                        if (string.IsNullOrWhiteSpace(senderIp) || senderHw == null || senderHw.Length == 0) return;

                        var macStr = string.Join(":", senderHw.Select(b => b.ToString("x2")));
                        bool isNew;
                        lock (repliesLock)
                        {
                            isNew = !replies.ContainsKey(senderIp);
                            replies[senderIp] = macStr;
                        }

                        if (isNew)
                        {
                            try { onReplyReceived?.Invoke(new ArpSweepResult { Ip = senderIp!, Mac = macStr }); }
                            catch (Exception ex) { Logger.Debug(ex, "ARP reply callback failed"); }
                        }
                    }
                    catch (Exception ex) { Logger.Debug(ex, "ARP reply parse failure"); }
                }

                device.OnPacketArrival += OnArrival;
                device.StartCapture();

                try
                {
                    int batchSize = stealthMode ? StealthBatchSize : BatchSize;
                    int batchSpacing = stealthMode ? StealthBatchSpacingMs : BatchSpacingMs;

                    // Build IP list, optionally shuffle for stealth so the
                    // packet trace doesn't show monotonic IP increments.
                    var ipList = new List<uint>();
                    for (uint v = start; v <= end && v >= start; v++)
                    {
                        ipList.Add(v);
                        if (v == uint.MaxValue) break;
                    }
                    if (stealthMode)
                    {
                        var rng = new Random();
                        for (int i = ipList.Count - 1; i > 0; i--)
                        {
                            int j = rng.Next(i + 1);
                            (ipList[i], ipList[j]) = (ipList[j], ipList[i]);
                        }
                        Logger.Info($"[NI-STEALTH] ARP sweep: stealth mode, batch={batchSize}, spacing={batchSpacing}ms, shuffled");
                    }

                    int sentInBatch = 0;
                    foreach (var v in ipList)
                    {
                        if (cancellationToken.IsCancellationRequested) break;

                        var targetBytes = new byte[]
                        {
                            (byte)((v >> 24) & 0xFF),
                            (byte)((v >> 16) & 0xFF),
                            (byte)((v >> 8) & 0xFF),
                            (byte)(v & 0xFF)
                        };
                        var targetIp = new IPAddress(targetBytes);

                        try
                        {
                            var bytesToSend = BuildArpRequest(srcMac, srcIp, targetIp);
                            device.SendPacket(bytesToSend);
                        }
                        catch (Exception ex) { Logger.Debug(ex, "ARP send failed"); }

                        sentInBatch++;
                        if (sentInBatch >= batchSize)
                        {
                            sentInBatch = 0;
                            try { await Task.Delay(batchSpacing, cancellationToken).ConfigureAwait(false); }
                            catch (OperationCanceledException) { break; }
                        }
                    }

                    try { await Task.Delay(ListenTailMs, cancellationToken).ConfigureAwait(false); }
                    catch (OperationCanceledException) { }
                }
                finally
                {
                    try { device.StopCapture(); } catch { }
                    try { device.OnPacketArrival -= OnArrival; } catch { }
                    try { device.Close(); } catch { }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "ARP sweep failed");
            }

            lock (repliesLock)
            {
                return replies.Select(kv => new ArpSweepResult { Ip = kv.Key, Mac = kv.Value }).ToList();
            }
        }

        private static (NetworkInterface? nic, byte[]? mac) ResolveNicAndMac(IPAddress srcIp)
        {
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    var props = nic.GetIPProperties();
                    foreach (var addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        if (addr.Address.Equals(srcIp))
                        {
                            return (nic, nic.GetPhysicalAddress()?.GetAddressBytes());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "ARP sweep NIC resolution failed");
            }
            return (null, null);
        }

        private static byte[] BuildArpRequest(PhysicalAddress srcMac, IPAddress srcIp, IPAddress targetIp)
        {
            var broadcast = PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF");
            var unknown = PhysicalAddress.Parse("00-00-00-00-00-00");

            var ethernet = new EthernetPacket(srcMac, broadcast, EthernetType.Arp);
            var arp = new ArpPacket(
                ArpOperation.Request,
                unknown,
                targetIp,
                srcMac,
                srcIp);
            ethernet.PayloadPacket = arp;
            return ethernet.Bytes;
        }
    }
}
