using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services
{
    public class DiagnosticExportService
    {
        private readonly DatabaseService _db;
        private readonly DiscoveryOrchestrator? _orchestrator;

        public DiagnosticExportService(
            DatabaseService db,
            DiscoveryOrchestrator? orchestrator = null)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _orchestrator = orchestrator;
        }

        public async Task<string> GenerateAsync(
            IEnumerable<HostProbeResult> currentResults,
            string sourceIp,
            string sourceNic,
            string targetRaw,
            TopologyGraph? topologyGraph = null)
        {
            var sb = new StringBuilder();

            sb.AppendLine("# SEACURE(TOOL) Diagnostic Export");
            sb.AppendLine($"Generated:   {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Version:     {GetAssemblyVersion()}");
            sb.AppendLine($"OS:          {Environment.OSVersion}");
            sb.AppendLine($"Machine:     {Environment.MachineName}");
            sb.AppendLine($"Source IP:   {sourceIp}");
            sb.AppendLine($"Source NIC:  {sourceNic}");
            sb.AppendLine($"Target:      {targetRaw}");
            sb.AppendLine();

            sb.AppendLine("## Current Run Results");
            foreach (var host in currentResults)
            {
                sb.AppendLine($"### {host.IpAddress} — {host.Status}");
                sb.AppendLine($"Summary:    {host.Summary}");
                sb.AppendLine($"Route:      {host.RouteExplanation}");
                sb.AppendLine($"ICMP:       {host.IcmpExplanation}");

                if (host.TracerouteHops.Any())
                {
                    sb.AppendLine("Path:");
                    foreach (var hop in host.TracerouteHops)
                        sb.AppendLine($"  {hop.Display}");
                }

                if (host.TcpPorts.Any())
                {
                    sb.AppendLine("TCP ports:");
                    foreach (var kv in host.TcpPorts.OrderBy(k => k.Key))
                        sb.AppendLine($"  {kv.Key,5}: {kv.Value,-10}  {HostProbeResult.PortStatusExplanation(kv.Value)}");
                }

                if (host.SnmpResponded)
                {
                    sb.AppendLine("SNMP:");
                    foreach (var kv in host.SnmpValues)
                        sb.AppendLine($"  {kv.Key}: {kv.Value}");
                }

                sb.AppendLine($"Started:    {host.StartedAt:HH:mm:ss}");
                sb.AppendLine($"Completed:  {host.CompletedAt:HH:mm:ss}");
                sb.AppendLine();
            }

#if !LITE_EDITION
            var graph = topologyGraph ?? _orchestrator?.Graph;
            sb.AppendLine("## Probed Hosts");
            if (graph != null)
            {
                var probedHosts = graph.Nodes
                    .Where(n => n.Type == NodeType.Host
                        && n.Attributes.ContainsKey("lastProbeUnixMs"))
                    .OrderBy(n => n.IpAddress)
                    .ToList();

                if (probedHosts.Count == 0)
                {
                    sb.AppendLine("(no hosts have been deep-probed yet)");
                }
                else
                {
                    sb.AppendLine($"{probedHosts.Count} host(s) deep-probed:");
                    foreach (var node in probedHosts)
                    {
                        sb.AppendLine();
                        sb.AppendLine($"### {node.IpAddress}");
                        if (!string.IsNullOrEmpty(node.Hostname))
                            sb.AppendLine($"  Hostname: {node.Hostname}");
                        if (node.Attributes.TryGetValue("osFamily", out var os))
                        {
                            var osVer = node.Attributes.TryGetValue("osVersion", out var v) ? v : "";
                            var osConf = node.Attributes.TryGetValue("osConfidence", out var c) ? c : "";
                            sb.AppendLine($"  OS: {os} {osVer}".TrimEnd() +
                                (string.IsNullOrEmpty(osConf) ? "" : $"  (confidence={osConf})"));
                        }
                        if (!string.IsNullOrEmpty(node.SysDescr))
                            sb.AppendLine($"  SysDescr: {node.SysDescr}");
                        if (!string.IsNullOrEmpty(node.Vendor))
                            sb.AppendLine($"  Vendor (OUI): {node.Vendor}");
                        if (node.OpenPortCount.HasValue)
                            sb.AppendLine($"  Open TCP ports: {node.OpenPortCount.Value}");
                        if (long.TryParse(node.Attributes["lastProbeUnixMs"], out var probedMs))
                        {
                            var probedAt = DateTimeOffset.FromUnixTimeMilliseconds(probedMs).LocalDateTime;
                            sb.AppendLine($"  Last probed: {probedAt:yyyy-MM-dd HH:mm:ss}");
                        }
                        else
                        {
                            sb.AppendLine($"  Last probed: {node.Attributes["lastProbeUnixMs"]}");
                        }
                        sb.AppendLine($"  Status: " +
                            $"{(node.Attributes.TryGetValue("lastProbeStatus", out var ls) ? ls : "unknown")}");
                    }
                }
            }
            else
            {
                sb.AppendLine("(topology graph unavailable)");
            }
            sb.AppendLine();
#endif

            sb.AppendLine("## Recent Run History");
            try
            {
                var runs = await _db.GetReachabilityRunsAsync(limit: 10);
                foreach (var run in runs)
                {
                    sb.AppendLine($"- [{run.StartedAt:yyyy-MM-dd HH:mm}] " +
                        $"{run.Label} — " +
                        $"{run.HostsTested} tested, " +
                        $"{run.HostsReachable} reachable, " +
                        $"{run.HostsPartial} partial, " +
                        $"{run.HostsUnreachable} unreachable, " +
                        $"{run.HostsNoRoute} no route");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(run history unavailable: {ex.Message})");
            }
            sb.AppendLine();

            sb.AppendLine("## Application Log (last 200 lines)");
            try
            {
                var logPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SEACURE(TOOL)", "logs");

                string? logFile = null;
                if (Directory.Exists(logPath))
                {
                    logFile = Directory.GetFiles(logPath, "*.log")
                        .OrderByDescending(f => f)
                        .FirstOrDefault();
                }

                if (logFile != null)
                {
                    var lines = await ReadLogTailAsync(logFile, 200);
                    foreach (var line in lines)
                        sb.AppendLine(line);
                }
                else
                {
                    sb.AppendLine("(no log file found)");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(log read failed: {ex.Message})");
            }
            sb.AppendLine();

            sb.AppendLine("## Network Interfaces");
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up))
                {
                    sb.AppendLine($"- {nic.Name} [{nic.NetworkInterfaceType}] speed={nic.Speed / 1_000_000}Mbps");
                    foreach (var addr in nic.GetIPProperties().UnicastAddresses
                        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork))
                        sb.AppendLine($"    IP: {addr.Address}/{addr.IPv4Mask}");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(interface enumeration failed: {ex.Message})");
            }
            sb.AppendLine();

            sb.AppendLine("## OS Routing Table");
            try
            {
                var psi = new ProcessStartInfo("route", "print -4")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi)!;
                var output = await proc.StandardOutput.ReadToEndAsync();
                sb.AppendLine(output);
            }
            catch (Exception ex)
            {
                sb.AppendLine($"(route print failed: {ex.Message})");
            }
            sb.AppendLine();

#if !LITE_EDITION
            // SECTION 7 — Topology snapshot
            sb.AppendLine("## Topology Snapshot");


            if (graph == null || graph.Nodes.Count == 0)
            {
                sb.AppendLine("(no topology data — run discovery first)");
            }
            else
            {
                var nodes = graph.Nodes;
                var edges = graph.Edges;

                sb.AppendLine($"Nodes: {nodes.Count}");
                sb.AppendLine($"Edges: {edges.Count}");
                sb.AppendLine($"Flows: {edges.Count(e => e.Type == EdgeType.Flow)}");
                sb.AppendLine();

                sb.AppendLine("### Nodes");
                sb.AppendLine(
                    $"{"IP / Subnet",-20} {"Type",-14} {"MAC",-19} " +
                    $"{"Vendor",-20} {"Hostname",-24} {"Last seen",-10}");
                sb.AppendLine(new string('-', 108));

                foreach (var node in nodes
                    .OrderBy(n => n.Type)
                    .ThenBy(n => n.IpAddress ?? NodeDisplayKey(n)))
                {
                    sb.AppendLine(
                        $"{NodeDisplayKey(node),-20} " +
                        $"{node.Type,-14} " +
                        $"{(node.MacAddress ?? ""),-19} " +
                        $"{(node.Vendor ?? ""),-20} " +
                        $"{(node.Hostname ?? ""),-24} " +
                        $"{FormatUnixMs(node.LastSeenUnixMs),-10}");

                    if (!string.IsNullOrWhiteSpace(node.SysName))
                        sb.AppendLine($"  snmp.sysName:  {node.SysName}");
                    if (!string.IsNullOrWhiteSpace(node.SysDescr))
                        sb.AppendLine($"  snmp.sysDescr: {node.SysDescr}");

                    if (node.OpenPortCount.HasValue && node.OpenPortCount.Value > 0)
                        sb.AppendLine($"  open ports: {node.OpenPortCount.Value}");
                }
                sb.AppendLine();

                // Flow edges — cap at 50 keeps the diagnostic file pasteable into chat.
                var flows = edges
                    .Where(e => e.Type == EdgeType.Flow)
                    .OrderByDescending(e => e.Bytes)
                    .Take(50)
                    .ToList();

                if (flows.Any())
                {
                    sb.AppendLine("### Top flows (by bytes, max 50)");
                    sb.AppendLine(
                        $"{"Source",-18} {"Destination",-18} " +
                        $"{"Protocol",-10} {"Bytes",-12} {"Packets",-10} " +
                        $"{"Last seen",-10}");
                    sb.AppendLine(new string('-', 82));

                    foreach (var flow in flows)
                    {
                        sb.AppendLine(
                            $"{flow.Source,-18} {flow.Target,-18} " +
                            $"{(flow.Protocol ?? ""),-10} {flow.Bytes,-12:N0} " +
                            $"{flow.Packets,-10:N0} " +
                            $"{FormatUnixMs(flow.LastSeenUnixMs),-10}");
                    }
                    sb.AppendLine();
                }

                var structural = edges
                    .Where(e => e.Type != EdgeType.Flow)
                    .OrderBy(e => e.Type)
                    .ToList();

                if (structural.Any())
                {
                    sb.AppendLine("### Structural edges");
                    foreach (var edge in structural)
                        sb.AppendLine(
                            $"  {edge.Type,-16} {edge.Source} → {edge.Target}");
                    sb.AppendLine();
                }

                var subnets = nodes
                    .Where(n => n.Type == NodeType.SubnetCloud)
                    .ToList();

                if (subnets.Any())
                {
                    sb.AppendLine("### Discovered subnets");
                    foreach (var s in subnets)
                    {
                        var cidr = s.Attributes.TryGetValue("network", out var n) && !string.IsNullOrWhiteSpace(n)
                            ? n
                            : s.Id;
                        var expanded = s.Attributes.TryGetValue("expanded", out var v) &&
                                       string.Equals(v, "true", StringComparison.OrdinalIgnoreCase);
                        sb.AppendLine($"  {cidr,-20} {(expanded ? "expanded" : "unexplored")}");
                    }
                    sb.AppendLine();
                }
            }
#endif

            return sb.ToString();
        }

        private static string NodeDisplayKey(TopologyNode node)
        {
            if (!string.IsNullOrWhiteSpace(node.IpAddress)) return node.IpAddress!;
            if (node.Attributes.TryGetValue("network", out var cidr) && !string.IsNullOrWhiteSpace(cidr)) return cidr;
            if (node.Attributes.TryGetValue("subnet", out var subnet) && !string.IsNullOrWhiteSpace(subnet)) return subnet;
            return node.Id;
        }

        private static string FormatUnixMs(long? unixMs) =>
            unixMs.HasValue
                ? DateTimeOffset.FromUnixTimeMilliseconds(unixMs.Value).LocalDateTime.ToString("HH:mm:ss")
                : "";

        private static async Task<IEnumerable<string>> ReadLogTailAsync(string path, int tailLines)
        {
            // Open shared so a running NLog writer doesn't block us.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);

            var buffer = new Queue<string>(tailLines + 1);
            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                buffer.Enqueue(line);
                if (buffer.Count > tailLines) buffer.Dequeue();
            }
            return buffer;
        }

        private static string GetAssemblyVersion() =>
            Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyFileVersionAttribute>()
                ?.Version ?? "unknown";
    }
}
