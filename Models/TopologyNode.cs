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
                return $"{cidr}\n{sourceText}{statusGlyph}";
            }
            if (!string.IsNullOrWhiteSpace(Hostname)) return Hostname!;
            if (!string.IsNullOrWhiteSpace(SysName)) return SysName!;
            if (!string.IsNullOrWhiteSpace(IpAddress)) return IpAddress!;
            return Id;
        }
    }
}
