using System.Collections.Generic;

namespace Dorothy.Models
{
    public enum NodeType
    {
        Self,
        Host,
        Gateway,
        RemoteHost,
        SubnetCloud,
        UnknownHop
    }

    public class TopologyNode
    {
        public string Id { get; set; } = string.Empty;
        public NodeType Type { get; set; } = NodeType.Host;
        public string? IpAddress { get; set; }
        public string? MacAddress { get; set; }
        public string? Hostname { get; set; }
        public string? Vendor { get; set; }
        public string? SysName { get; set; }
        public string? SysDescr { get; set; }
        public int? OpenPortCount { get; set; }
        public long? LastSeenUnixMs { get; set; }
        public Dictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

        public Dictionary<string, object?> ToCytoscapeData()
        {
            var data = new Dictionary<string, object?>
            {
                ["id"] = Id,
                ["type"] = Type.ToString(),
                ["ip"] = IpAddress,
                ["mac"] = MacAddress,
                ["hostname"] = Hostname,
                ["vendor"] = Vendor,
                ["sysName"] = SysName,
                ["sysDescr"] = SysDescr,
                ["openPortCount"] = OpenPortCount,
                ["lastSeen"] = LastSeenUnixMs,
                ["label"] = ComputeLabel(),
                ["stale"] = Attributes.TryGetValue("stale", out var st) && st == "true"
            };

            // Compound-node parent — when a host has been assigned to a known
            // SubnetCloud via AssignParentSubnet, cytoscape renders this node
            // visually nested inside its parent box.
            if (Attributes.TryGetValue("parentSubnet", out var parent)
                && !string.IsNullOrWhiteSpace(parent))
            {
                data["parent"] = parent;
            }

            foreach (var kv in Attributes)
            {
                if (!data.ContainsKey(kv.Key)) data[kv.Key] = kv.Value;
            }
            return data;
        }

        private string ComputeLabel()
        {
            if (Type == NodeType.SubnetCloud)
            {
                if (Attributes.TryGetValue("isInternet", out var iiFlag) && iiFlag == "true")
                {
                    return "Internet\n(public hops)";
                }

                var cidr = Attributes.TryGetValue("subnet", out var s) ? s
                    : Attributes.TryGetValue("network", out var n) ? n
                    : Id;
                var source = Attributes.TryGetValue("discoverySource", out var src) ? src : "";
                var status = Attributes.TryGetValue("scanStatus", out var stat) ? stat : "pending";

                var statusGlyph = status switch
                {
                    "scanning" => "⟳",
                    "done"     => "✓",
                    "failed"   => "✗",
                    _          => "·"
                };

                var sourceText = string.IsNullOrWhiteSpace(source) ? "" : source + " ";
                var label = $"{cidr}\n{sourceText}{statusGlyph}";

                // Live scan progress on subnet labels: "12/254 hosts"
                var seenCount = Attributes.TryGetValue("seenHostCount", out var sc) ? sc : null;
                var totalCount = Attributes.TryGetValue("totalHostCount", out var tc) ? tc : null;
                if (!string.IsNullOrWhiteSpace(seenCount) && !string.IsNullOrWhiteSpace(totalCount))
                    label += $"\n{seenCount}/{totalCount} hosts";
                else if (!string.IsNullOrWhiteSpace(seenCount))
                    label += $"\n{seenCount} hosts seen";

                return label;
            }
            if (Type == NodeType.UnknownHop)
            {
                var hop = Attributes.TryGetValue("traceHop",   out var h) ? h : "?";
                var rtt = Attributes.TryGetValue("traceRttMs", out var r) ? r : "?";
                return $"hop {hop}\n{IpAddress ?? Id}\n{rtt}ms";
            }

            // Host / Self / Gateway: prefer a friendly device name when known.
            // Two-line format renders the name on top with the IP underneath
            // so users can scan the canvas by name.
            string? smbName    = Attributes.TryGetValue("smbComputerName", out var smb) ? smb : null;
            string? netBios    = Attributes.TryGetValue("netBiosName",     out var nb)  ? nb  : null;
            string? hostnameDns = !string.IsNullOrWhiteSpace(Hostname) ? StripDnsSuffix(Hostname!) : null;

            var deviceName =
                !string.IsNullOrWhiteSpace(smbName)     ? smbName :
                !string.IsNullOrWhiteSpace(hostnameDns) ? hostnameDns :
                !string.IsNullOrWhiteSpace(netBios)     ? netBios :
                !string.IsNullOrWhiteSpace(SysName)     ? SysName :
                null;

            if (!string.IsNullOrEmpty(deviceName)
                && !string.Equals(deviceName, IpAddress, System.StringComparison.OrdinalIgnoreCase))
            {
                return string.IsNullOrWhiteSpace(IpAddress)
                    ? deviceName!
                    : $"{deviceName}\n{IpAddress}";
            }

            if (!string.IsNullOrWhiteSpace(IpAddress)) return IpAddress!;
            return Id;
        }

        // "DESKTOP-HER186U.local" → "DESKTOP-HER186U"
        // "myserver.example.com" → "myserver"
        private static string StripDnsSuffix(string hostname)
        {
            var dot = hostname.IndexOf('.');
            return dot > 0 ? hostname.Substring(0, dot) : hostname;
        }
    }
}
