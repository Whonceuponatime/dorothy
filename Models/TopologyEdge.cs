using System.Collections.Generic;

namespace Dorothy.Models
{
    public enum EdgeType
    {
        Flow,
        ArpSeen,
        TraceroutePath,
        SnmpNeighbor
    }

    public class TopologyEdge
    {
        public string Id { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public EdgeType Type { get; set; } = EdgeType.Flow;
        public long Packets { get; set; }
        public long Bytes { get; set; }
        public string? Protocol { get; set; }
        public long? LastSeenUnixMs { get; set; }
        public Dictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

        public static string BuildId(string source, string target, EdgeType type) => $"{source}|{target}|{type}";

        public Dictionary<string, object?> ToCytoscapeData()
        {
            var data = new Dictionary<string, object?>
            {
                ["id"] = Id,
                ["source"] = Source,
                ["target"] = Target,
                ["type"] = Type.ToString(),
                ["packets"] = Packets,
                ["bytes"] = Bytes,
                ["protocol"] = Protocol,
                ["lastSeen"] = LastSeenUnixMs
            };
            foreach (var kv in Attributes)
            {
                if (!data.ContainsKey(kv.Key)) data[kv.Key] = kv.Value;
            }
            return data;
        }
    }
}
