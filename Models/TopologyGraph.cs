using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace Dorothy.Models
{
    public class TopologyGraph
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, TopologyNode> _nodes = new Dictionary<string, TopologyNode>(StringComparer.Ordinal);
        private readonly Dictionary<string, TopologyEdge> _edges = new Dictionary<string, TopologyEdge>(StringComparer.Ordinal);

        public TopologyNode UpsertNode(TopologyNode node)
        {
            if (node == null) throw new ArgumentNullException(nameof(node));
            if (string.IsNullOrWhiteSpace(node.Id)) throw new ArgumentException("Node Id is required.", nameof(node));

            lock (_lock)
            {
                if (_nodes.TryGetValue(node.Id, out var existing))
                {
                    if (!string.IsNullOrWhiteSpace(node.IpAddress)) existing.IpAddress = node.IpAddress;
                    if (!string.IsNullOrWhiteSpace(node.MacAddress)) existing.MacAddress = node.MacAddress;
                    if (!string.IsNullOrWhiteSpace(node.Hostname)) existing.Hostname = node.Hostname;
                    if (!string.IsNullOrWhiteSpace(node.Vendor)) existing.Vendor = node.Vendor;
                    if (!string.IsNullOrWhiteSpace(node.SysName)) existing.SysName = node.SysName;
                    if (!string.IsNullOrWhiteSpace(node.SysDescr)) existing.SysDescr = node.SysDescr;
                    if (node.OpenPortCount.HasValue) existing.OpenPortCount = node.OpenPortCount;
                    if (node.LastSeenUnixMs.HasValue) existing.LastSeenUnixMs = node.LastSeenUnixMs;
                    if (existing.Type == NodeType.Host && node.Type != NodeType.Host) existing.Type = node.Type;
                    foreach (var kv in node.Attributes) existing.Attributes[kv.Key] = kv.Value;
                    return existing;
                }

                _nodes[node.Id] = node;
                return node;
            }
        }

        public TopologyEdge UpsertEdge(TopologyEdge edge)
        {
            if (edge == null) throw new ArgumentNullException(nameof(edge));
            if (string.IsNullOrWhiteSpace(edge.Id))
                edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);

            lock (_lock)
            {
                if (_edges.TryGetValue(edge.Id, out var existing))
                {
                    existing.Packets += edge.Packets;
                    existing.Bytes += edge.Bytes;
                    if (!string.IsNullOrWhiteSpace(edge.Protocol)) existing.Protocol = edge.Protocol;
                    if (edge.LastSeenUnixMs.HasValue) existing.LastSeenUnixMs = edge.LastSeenUnixMs;
                    foreach (var kv in edge.Attributes) existing.Attributes[kv.Key] = kv.Value;
                    return existing;
                }

                _edges[edge.Id] = edge;
                return edge;
            }
        }

        public TopologyNode? GetNode(string id)
        {
            lock (_lock) { return _nodes.TryGetValue(id, out var node) ? node : null; }
        }

        public IReadOnlyList<TopologyNode> Nodes
        {
            get { lock (_lock) { return _nodes.Values.ToList(); } }
        }

        public IReadOnlyList<TopologyEdge> Edges
        {
            get { lock (_lock) { return _edges.Values.ToList(); } }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _nodes.Clear();
                _edges.Clear();
            }
        }

        public string ToCytoscapeJson()
        {
            List<Dictionary<string, object?>> nodeElements;
            List<Dictionary<string, object?>> edgeElements;
            lock (_lock)
            {
                nodeElements = _nodes.Values
                    .Select(n => new Dictionary<string, object?> { ["data"] = n.ToCytoscapeData() })
                    .ToList();
                edgeElements = _edges.Values
                    .Select(e => new Dictionary<string, object?> { ["data"] = e.ToCytoscapeData() })
                    .ToList();
            }

            var payload = new Dictionary<string, object?>
            {
                ["nodes"] = nodeElements,
                ["edges"] = edgeElements
            };
            return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = false });
        }

        public string NodeUpdateJson(string nodeId)
        {
            TopologyNode? node;
            lock (_lock) { _nodes.TryGetValue(nodeId, out node); }
            if (node == null) return "{}";
            return JsonSerializer.Serialize(node.ToCytoscapeData(), new JsonSerializerOptions { WriteIndented = false });
        }
    }
}
