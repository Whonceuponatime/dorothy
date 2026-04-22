using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using NLog;

namespace Dorothy.Services
{
    public class IpRouteEntry
    {
        public string DestNetwork { get; set; } = string.Empty;
        public string NextHop { get; set; } = string.Empty;
        public int? IfIndex { get; set; }
    }

    public class ArpEntry
    {
        public string IpAddress { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
    }

    public class CdpNeighbor
    {
        public string? DeviceId { get; set; }
        public string? IpAddress { get; set; }
        public string? Platform { get; set; }
    }

    public class LldpNeighbor
    {
        public string? SystemName { get; set; }
        public string? PortId { get; set; }
        public string? SystemDescription { get; set; }
    }

    public class GatewayTopology
    {
        public List<IpRouteEntry> Routes { get; } = new List<IpRouteEntry>();
        public List<ArpEntry> Arps { get; } = new List<ArpEntry>();
        public List<CdpNeighbor> Cdp { get; } = new List<CdpNeighbor>();
        public List<LldpNeighbor> Lldp { get; } = new List<LldpNeighbor>();
    }

    public record SnmpInterface(
        int Index,
        string? Descr,
        long SpeedBps,
        long? HighSpeedMbps,
        int AdminStatus,
        int OperStatus,
        bool? FullDuplex);

    public record SnmpRoute(
        string Destination,
        int PrefixLen,
        string NextHop,
        int IfIndex);

    public record SnmpArpEntry(
        string Ip,
        string Mac,
        int IfIndex);

    public record SnmpWalkNeighbor(
        string? SysName,
        string? PortId,
        string? ManagementIp,
        string Source);

    public record SnmpGatewayWalkResult(
        bool Reachable,
        string? SysName,
        string? SysDescr,
        string? SysLocation,
        List<SnmpInterface>? Interfaces,
        List<SnmpWalkNeighbor>? Neighbors,
        List<SnmpRoute>? Routes,
        List<SnmpArpEntry>? ArpEntries);

    public class SnmpGatewayService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int Port = 161;
        private const int TimeoutMs = 2000;
        private const int PerSubtreeMaxRows = 200;
        private const int PerSubtreeWallClockMs = 15000;

        public async Task<GatewayTopology> ProbeGatewayAsync(string gatewayIp, string community, CancellationToken token)
        {
            var topology = new GatewayTopology();
            if (!IPAddress.TryParse(gatewayIp, out var ip)) return topology;
            var endpoint = new IPEndPoint(ip, Port);
            var communityObject = new OctetString(string.IsNullOrWhiteSpace(community) ? "public" : community);

            await Task.Run(() =>
            {
                topology.Routes.AddRange(WalkIpRoutes(endpoint, communityObject, token));
                if (token.IsCancellationRequested) return;
                topology.Arps.AddRange(WalkArpCache(endpoint, communityObject, token));
                if (token.IsCancellationRequested) return;
                topology.Cdp.AddRange(WalkCdp(endpoint, communityObject, token));
                if (token.IsCancellationRequested) return;
                topology.Lldp.AddRange(WalkLldp(endpoint, communityObject, token));
            }, token).ConfigureAwait(false);

            return topology;
        }

        private static List<IpRouteEntry> WalkIpRoutes(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var dests = WalkTable(ep, community, "1.3.6.1.2.1.4.21.1.1", token);
            var hops = WalkTable(ep, community, "1.3.6.1.2.1.4.21.1.7", token);
            var ifs = WalkTable(ep, community, "1.3.6.1.2.1.4.21.1.2", token);

            var list = new List<IpRouteEntry>();
            foreach (var kv in dests)
            {
                var entry = new IpRouteEntry
                {
                    DestNetwork = kv.Value,
                    NextHop = hops.TryGetValue(kv.Key, out var nh) ? nh : string.Empty
                };
                if (ifs.TryGetValue(kv.Key, out var ifx) && int.TryParse(ifx, out var ifi))
                    entry.IfIndex = ifi;
                list.Add(entry);
            }
            return list;
        }

        private static List<ArpEntry> WalkArpCache(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var phys = WalkTable(ep, community, "1.3.6.1.2.1.4.22.1.2", token);
            var ips = WalkTable(ep, community, "1.3.6.1.2.1.4.22.1.3", token);

            var list = new List<ArpEntry>();
            foreach (var kv in ips)
            {
                if (!phys.TryGetValue(kv.Key, out var mac)) continue;
                list.Add(new ArpEntry { IpAddress = kv.Value, MacAddress = mac });
            }
            return list;
        }

        private static List<CdpNeighbor> WalkCdp(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var addrs = WalkTable(ep, community, "1.3.6.1.4.1.9.9.23.1.2.1.1.4", token);
            var ids = WalkTable(ep, community, "1.3.6.1.4.1.9.9.23.1.2.1.1.6", token);
            var plats = WalkTable(ep, community, "1.3.6.1.4.1.9.9.23.1.2.1.1.8", token);

            var list = new List<CdpNeighbor>();
            var keys = addrs.Keys.Union(ids.Keys).Union(plats.Keys).Distinct().ToList();
            foreach (var k in keys)
            {
                list.Add(new CdpNeighbor
                {
                    DeviceId = ids.TryGetValue(k, out var id) ? id : null,
                    IpAddress = addrs.TryGetValue(k, out var a) ? a : null,
                    Platform = plats.TryGetValue(k, out var p) ? p : null
                });
            }
            return list;
        }

        private static List<LldpNeighbor> WalkLldp(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var names = WalkTable(ep, community, "1.0.8802.1.1.2.1.4.1.1.9", token);
            var ports = WalkTable(ep, community, "1.0.8802.1.1.2.1.4.1.1.7", token);
            var descs = WalkTable(ep, community, "1.0.8802.1.1.2.1.4.1.1.10", token);

            var list = new List<LldpNeighbor>();
            var keys = names.Keys.Union(ports.Keys).Union(descs.Keys).Distinct().ToList();
            foreach (var k in keys)
            {
                list.Add(new LldpNeighbor
                {
                    SystemName = names.TryGetValue(k, out var n) ? n : null,
                    PortId = ports.TryGetValue(k, out var p) ? p : null,
                    SystemDescription = descs.TryGetValue(k, out var d) ? d : null
                });
            }
            return list;
        }

        private static Dictionary<string, string> WalkTable(IPEndPoint ep, OctetString community, string oid, CancellationToken token)
        {
            return WalkTableBounded(ep, community, oid, PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
        }

        private static Dictionary<string, string> WalkTableBounded(
            IPEndPoint ep, OctetString community, string oid,
            int maxRows, int wallClockMs, CancellationToken token)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            var sw = Stopwatch.StartNew();
            try
            {
                var list = new List<Variable>();
                Messenger.Walk(
                    VersionCode.V2,
                    ep,
                    community,
                    new ObjectIdentifier(oid),
                    list,
                    TimeoutMs,
                    WalkMode.WithinSubtree);

                int added = 0;
                foreach (var v in list)
                {
                    if (token.IsCancellationRequested) break;
                    if (sw.ElapsedMilliseconds > wallClockMs) break;
                    if (added >= maxRows) break;
                    var fullId = v.Id?.ToString() ?? string.Empty;
                    var val = v.Data?.ToString() ?? string.Empty;
                    string key = fullId;
                    if (fullId.Length > oid.Length + 1 && fullId.StartsWith(oid, StringComparison.Ordinal))
                    {
                        key = fullId.Substring(oid.Length + 1);
                    }
                    result[key] = val;
                    added++;
                }
                Logger.Info($"[SNMP] walk {oid} @ {ep.Address}: rows={added} elapsed={sw.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"SNMP walk failed for {oid}");
            }
            return result;
        }

        public Task<SnmpGatewayWalkResult> WalkBoundedAsync(string gatewayIp, string community, CancellationToken token)
        {
            return Task.Run(() => WalkBounded(gatewayIp, community, token), token);
        }

        private static SnmpGatewayWalkResult WalkBounded(string gatewayIp, string community, CancellationToken token)
        {
            if (!IPAddress.TryParse(gatewayIp, out var ip))
                return new SnmpGatewayWalkResult(false, null, null, null, null, null, null, null);

            var ep = new IPEndPoint(ip, Port);
            var communityObject = new OctetString(string.IsNullOrWhiteSpace(community) ? "public" : community);

            // Scalar system OIDs — if these fail, SNMP is unavailable.
            string? sysDescr = null, sysName = null, sysLocation = null;
            try
            {
                var scalars = new List<Variable>
                {
                    new Variable(new ObjectIdentifier("1.3.6.1.2.1.1.1.0")),
                    new Variable(new ObjectIdentifier("1.3.6.1.2.1.1.5.0")),
                    new Variable(new ObjectIdentifier("1.3.6.1.2.1.1.6.0"))
                };
                var reply = Messenger.Get(VersionCode.V2, ep, communityObject, scalars, TimeoutMs);
                if (reply != null && reply.Count >= 3)
                {
                    sysDescr    = reply[0].Data?.ToString();
                    sysName     = reply[1].Data?.ToString();
                    sysLocation = reply[2].Data?.ToString();
                }
                else
                {
                    return new SnmpGatewayWalkResult(false, null, null, null, null, null, null, null);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"SNMP scalar GET failed for {gatewayIp}");
                return new SnmpGatewayWalkResult(false, null, null, null, null, null, null, null);
            }

            if (token.IsCancellationRequested)
                return new SnmpGatewayWalkResult(true, sysName, sysDescr, sysLocation, null, null, null, null);

            var routes = WalkRoutes(ep, communityObject, token);
            if (token.IsCancellationRequested)
                return new SnmpGatewayWalkResult(true, sysName, sysDescr, sysLocation, null, null, routes, null);

            var arp = WalkArp(ep, communityObject, token);
            if (token.IsCancellationRequested)
                return new SnmpGatewayWalkResult(true, sysName, sysDescr, sysLocation, null, null, routes, arp);

            var ifs = WalkInterfaces(ep, communityObject, token);
            if (token.IsCancellationRequested)
                return new SnmpGatewayWalkResult(true, sysName, sysDescr, sysLocation, ifs, null, routes, arp);

            var neighbors = new List<SnmpWalkNeighbor>();
            neighbors.AddRange(WalkLldpWithMgmtIp(ep, communityObject, token));
            if (!token.IsCancellationRequested)
                neighbors.AddRange(WalkCdpWithMgmtIp(ep, communityObject, token));

            return new SnmpGatewayWalkResult(true, sysName, sysDescr, sysLocation, ifs, neighbors, routes, arp);
        }

        private static List<SnmpRoute> WalkRoutes(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var dests = WalkTableBounded(ep, community, "1.3.6.1.2.1.4.21.1.1", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var hops  = WalkTableBounded(ep, community, "1.3.6.1.2.1.4.21.1.7", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var masks = WalkTableBounded(ep, community, "1.3.6.1.2.1.4.21.1.11", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var ifs   = WalkTableBounded(ep, community, "1.3.6.1.2.1.4.21.1.2", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);

            var result = new List<SnmpRoute>();
            foreach (var kv in dests)
            {
                var dest    = kv.Value;
                var nextHop = hops.TryGetValue(kv.Key, out var nh) ? nh : "0.0.0.0";
                var mask    = masks.TryGetValue(kv.Key, out var m) ? m : "";
                int prefix  = MaskToPrefixLen(mask);
                int ifIndex = ifs.TryGetValue(kv.Key, out var ifx) && int.TryParse(ifx, out var i) ? i : 0;
                result.Add(new SnmpRoute(dest, prefix, nextHop, ifIndex));
            }
            return result;
        }

        private static List<SnmpArpEntry> WalkArp(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var phys = WalkTableBounded(ep, community, "1.3.6.1.2.1.4.22.1.2", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var ips  = WalkTableBounded(ep, community, "1.3.6.1.2.1.4.22.1.3", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);

            var result = new List<SnmpArpEntry>();
            foreach (var kv in ips)
            {
                if (!phys.TryGetValue(kv.Key, out var mac)) continue;
                int ifIndex = 0;
                var keyParts = kv.Key.Split('.');
                if (keyParts.Length > 0 && int.TryParse(keyParts[0], out var ix)) ifIndex = ix;
                result.Add(new SnmpArpEntry(kv.Value, mac, ifIndex));
            }
            return result;
        }

        private static List<SnmpInterface> WalkInterfaces(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var descrs = WalkTableBounded(ep, community, "1.3.6.1.2.1.2.2.1.2", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var speeds = WalkTableBounded(ep, community, "1.3.6.1.2.1.2.2.1.5", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var admin  = WalkTableBounded(ep, community, "1.3.6.1.2.1.2.2.1.7", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var oper   = WalkTableBounded(ep, community, "1.3.6.1.2.1.2.2.1.8", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var highSp = WalkTableBounded(ep, community, "1.3.6.1.2.1.31.1.1.1.15", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);

            var result = new List<SnmpInterface>();
            foreach (var kv in descrs)
            {
                if (!int.TryParse(kv.Key, out var idx)) continue;
                long spd = speeds.TryGetValue(kv.Key, out var s) && long.TryParse(s, out var sp) ? sp : 0;
                long? hiSp = highSp.TryGetValue(kv.Key, out var h) && long.TryParse(h, out var hv) ? hv : null;
                int adm = admin.TryGetValue(kv.Key, out var a) && int.TryParse(a, out var ai) ? ai : 0;
                int opr = oper.TryGetValue(kv.Key, out var o) && int.TryParse(o, out var oi) ? oi : 0;
                result.Add(new SnmpInterface(idx, kv.Value, spd, hiSp, adm, opr, null));
            }
            return result;
        }

        private static List<SnmpWalkNeighbor> WalkLldpWithMgmtIp(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var names = WalkTableBounded(ep, community, "1.0.8802.1.1.2.1.4.1.1.9",  PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var ports = WalkTableBounded(ep, community, "1.0.8802.1.1.2.1.4.1.1.7",  PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var manAddrs = WalkTableBounded(ep, community, "1.0.8802.1.1.2.1.4.2.1.5", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);

            string? PickMgmtIp(string lldpIndex)
            {
                foreach (var kv in manAddrs)
                {
                    if (!kv.Key.StartsWith(lldpIndex, StringComparison.Ordinal)) continue;
                    var key = kv.Key;
                    var parts = key.Split('.');
                    if (parts.Length >= 4)
                    {
                        var last4 = string.Join(".", parts[^4..]);
                        if (IPAddress.TryParse(last4, out _)) return last4;
                    }
                }
                return null;
            }

            var result = new List<SnmpWalkNeighbor>();
            var keys = names.Keys.Union(ports.Keys).Distinct().ToList();
            foreach (var k in keys)
            {
                var sysName = names.TryGetValue(k, out var n) ? n : null;
                var portId  = ports.TryGetValue(k, out var p) ? p : null;
                var mgmtIp  = PickMgmtIp(k);
                result.Add(new SnmpWalkNeighbor(sysName, portId, mgmtIp, "lldp"));
            }
            return result;
        }

        private static List<SnmpWalkNeighbor> WalkCdpWithMgmtIp(IPEndPoint ep, OctetString community, CancellationToken token)
        {
            var addrs = WalkTableBounded(ep, community, "1.3.6.1.4.1.9.9.23.1.2.1.1.4", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);
            var ids   = WalkTableBounded(ep, community, "1.3.6.1.4.1.9.9.23.1.2.1.1.6", PerSubtreeMaxRows, PerSubtreeWallClockMs, token);

            var result = new List<SnmpWalkNeighbor>();
            var keys = addrs.Keys.Union(ids.Keys).Distinct().ToList();
            foreach (var k in keys)
            {
                var sysName = ids.TryGetValue(k, out var id) ? id : null;
                var mgmtIp  = addrs.TryGetValue(k, out var a) ? NormalizeHexIp(a) : null;
                result.Add(new SnmpWalkNeighbor(sysName, null, mgmtIp, "cdp"));
            }
            return result;
        }

        private static string? NormalizeHexIp(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            if (IPAddress.TryParse(raw, out _)) return raw;
            var hex = raw.Replace(" ", "").Replace(":", "");
            if (hex.Length == 8)
            {
                try
                {
                    var bytes = new byte[4];
                    for (int i = 0; i < 4; i++)
                        bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                    return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
                }
                catch { return null; }
            }
            return null;
        }

        private static int MaskToPrefixLen(string mask)
        {
            if (!IPAddress.TryParse(mask, out var ip)) return 0;
            var bytes = ip.GetAddressBytes();
            int bits = 0;
            foreach (var b in bytes)
            {
                byte v = b;
                while (v != 0) { bits += v & 1; v >>= 1; }
            }
            return bits;
        }
    }
}
