using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services
{
    public class TopologyNodeChangedEventArgs : EventArgs
    {
        public TopologyNode Node { get; set; } = new TopologyNode();
    }

    public class TopologyEdgeChangedEventArgs : EventArgs
    {
        public TopologyEdge Edge { get; set; } = new TopologyEdge();
    }

    public class DiscoveryStatusEventArgs : EventArgs
    {
        public string Phase { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool IsError { get; set; }
    }

    public class DiscoveryOrchestrator : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly TopologyGraph _graph = new TopologyGraph();
        private readonly PassiveCaptureService _capture = new PassiveCaptureService();
        private readonly ArpSweepService _arpSweep = new ArpSweepService();
        private readonly SnmpGatewayService _snmp = new SnmpGatewayService();
        private readonly ReachabilityProbeService _probe;

        private CancellationTokenSource? _phase1Cts;
        private int _isPhase1Running;
        private string? _sourceIp;
        private string? _nicDescription;
        private string? _community;
        private TopologyNode? _gatewayNode;
        private long _currentScanId = 0;

        public TopologyGraph Graph => _graph;
        public bool IsPhase1Running => Volatile.Read(ref _isPhase1Running) == 1;

        public event EventHandler<TopologyNodeChangedEventArgs>? NodeChanged;
        public event EventHandler<TopologyEdgeChangedEventArgs>? EdgeChanged;
        public event EventHandler<DiscoveryStatusEventArgs>? StatusChanged;

        public DiscoveryOrchestrator(ReachabilityProbeService probe)
        {
            _probe = probe ?? throw new ArgumentNullException(nameof(probe));
            _capture.ArpSeen += OnArpSeen;
            _capture.FlowSeen += OnFlowSeen;
        }

        public async Task StartDiscoveryAsync(
            string sourceIp,
            string? nicDescription,
            string community,
            CancellationToken cancellationToken)
        {
            if (Interlocked.CompareExchange(ref _isPhase1Running, 1, 0) != 0)
                throw new InvalidOperationException("Discovery Phase 1 already running.");

            _sourceIp = sourceIp;
            _nicDescription = nicDescription;
            _community = string.IsNullOrWhiteSpace(community) ? "public" : community;
            _phase1Cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var token = _phase1Cts.Token;
            _currentScanId = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            try
            {
                RaiseStatus("Phase1", $"Discovery starting… (scanId={_currentScanId})");

                var (selfNode, gatewayNode, subnetCidr) = SeedSelfAndGateway(sourceIp);
                _gatewayNode = gatewayNode;

                try
                {
                    _capture.Start(nicDescription);
                    RaiseStatus("Phase1", "Passive capture started.");
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "Passive capture could not start");
                    RaiseStatus("Phase1", $"Passive capture failed: {ex.Message}", true);
                }

                // Recursive SNMP-driven walk from primary gateway.
                // Subnets and neighbor gateways are discovered breadth-first,
                // each connected to whichever gateway announced them.
                if (gatewayNode != null && !string.IsNullOrWhiteSpace(gatewayNode.IpAddress))
                {
                    var visited = new HashSet<string>(StringComparer.Ordinal);
                    await WalkGatewayRecursiveAsync(
                        gatewayIp: gatewayNode.IpAddress!,
                        parentNodeId: sourceIp,
                        depth: 0,
                        maxDepth: 3,
                        visited: visited,
                        token: token).ConfigureAwait(false);
                }

                // ARP sweep is now scoped: only subnets reachable at L2 from
                // this NIC (the local subnet) get ARP-swept. Subnets beyond
                // the local broadcast domain are not reachable via ARP —
                // SNMP told us they exist; deep probing handles hosts in them.
                await ArpSweepReachableSubnetsAsync(subnetCidr, token).ConfigureAwait(false);

                try { await Task.Delay(2000, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { }

                MarkStaleNodesAfterScan();

                RaiseStatus("Phase1", "Discovery complete.");
            }
            catch (OperationCanceledException)
            {
                RaiseStatus("Phase1", "Discovery cancelled.", true);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Discovery failed");
                RaiseStatus("Phase1", $"Discovery error: {ex.Message}", true);
            }
            finally
            {
                Interlocked.Exchange(ref _isPhase1Running, 0);
            }
        }

        public void StopPassiveCapture()
        {
            try { _capture.Stop(); } catch (Exception ex) { Logger.Debug(ex, "Stop capture failed"); }
        }

        public void UpdateSourceIp(string newSourceIp)
        {
            if (string.IsNullOrWhiteSpace(newSourceIp)) return;
            _sourceIp = newSourceIp;
            Logger.Info($"Source IP updated to {newSourceIp} (topology preserved)");
        }

        public void CancelPhase1()
        {
            try { _phase1Cts?.Cancel(); } catch { }
        }

        public void AddManualSubnet(string cidr)
        {
            if (string.IsNullOrWhiteSpace(cidr)) return;

            if (!string.IsNullOrEmpty(_sourceIp))
            {
                try
                {
                    var parts = cidr.Split('/');
                    var (status, _) = TargetIpExpander.DetermineRoute(parts[0], _sourceIp!);
                    if (status == RouteStatus.Local) return;
                }
                catch { }
            }

            var node = new TopologyNode
            {
                Id = cidr,
                Type = NodeType.SubnetCloud,
                LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
            node.Attributes["subnet"] = cidr;
            node.Attributes["discoverySource"] = "manual";
            node.Attributes["expanded"] = "false";

            UpsertAndRaiseNode(node);
            RaiseStatus("Manual", $"Manual subnet added: {cidr}");
        }

        public async Task<List<ArpSweepResult>> ExpandSubnetAsync(string subnetCidr, CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(_sourceIp))
                throw new InvalidOperationException("StartDiscoveryAsync must run first.");

            var subnetNode = _graph.GetNode(subnetCidr) ?? _graph.GetNode($"subnet:{subnetCidr}");
            if (subnetNode != null)
            {
                subnetNode.Attributes["scanStatus"] = "scanning";
                UpsertAndRaiseNode(subnetNode);
            }

            RaiseStatus("Phase2", $"Expanding subnet {subnetCidr}…");
            try
            {
                var replies = await _arpSweep.SweepAsync(
                    subnetCidr,
                    _sourceIp!,
                    _nicDescription,
                    reply => OnArpReply(reply, subnetCidr),
                    token).ConfigureAwait(false);
                RaiseStatus("Phase2", $"Subnet expansion found {replies.Count} hosts.");

                if (subnetNode != null)
                {
                    subnetNode.Attributes["scanStatus"] = "done";
                    subnetNode.Attributes["expanded"] = "true";
                    UpsertAndRaiseNode(subnetNode);
                }
                return replies;
            }
            catch
            {
                if (subnetNode != null)
                {
                    subnetNode.Attributes["scanStatus"] = "failed";
                    UpsertAndRaiseNode(subnetNode);
                }
                throw;
            }
        }

        public async Task<HostProbeResult> DeepProbeHostAsync(
            string ip,
            List<int>? tcpPorts,
            CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(_sourceIp))
                throw new InvalidOperationException("StartDiscoveryAsync must run first.");

            var ports = (tcpPorts != null && tcpPorts.Count > 0)
                ? tcpPorts
                : PortLists.Top100Ports.ToList();

            var target = new ProbeTarget
            {
                Raw = ip,
                ExpandedIps = new List<string> { ip },
                RunRouteCheck = true,
                RunIcmpPing = true,
                RunTraceroute = true,
                RunTcpTraceroute = false,
                RunTcpScan = true,
                TcpPorts = ports,
                RunSnmpProbe = true,
                SnmpCommunity = _community ?? "public"
            };

            HostProbeResult? captured = null;
            RaiseStatus("Phase3", $"Deep probing {ip} (top-{ports.Count} ports)…");

            var enrichSvc = new Probes.HostEnrichmentService();
            var enrichTask = enrichSvc.EnrichAsync(ip, _community ?? "public", token);

            await _probe.StartRunAsync(
                target,
                _sourceIp,
                _nicDescription,
                $"deep:{ip}",
                host =>
                {
                    captured = host;
                    UpsertHostFromProbe(host);
                },
                _ => { },
                token).ConfigureAwait(false);

            var result = captured ?? new HostProbeResult { IpAddress = ip };

            Probes.HostEnrichmentService.EnrichmentResult? enrichment = null;
            try { enrichment = await enrichTask.ConfigureAwait(false); }
            catch (Exception ex) { Logger.Debug(ex, "Host enrichment failed"); }

            if (enrichment != null)
            {
                if (string.IsNullOrWhiteSpace(result.Hostname) && !string.IsNullOrWhiteSpace(enrichment.ReverseDnsHostname))
                    result.Hostname = enrichment.ReverseDnsHostname;
                result.NetBiosName = enrichment.NetBiosName;
                result.NetBiosWorkgroup = enrichment.NetBiosWorkgroup;

                if (!string.IsNullOrWhiteSpace(enrichment.SnmpSysDescr))
                    result.SnmpValues["sysDescr"] = enrichment.SnmpSysDescr!;
                if (!string.IsNullOrWhiteSpace(enrichment.SnmpSysName))
                    result.SnmpValues["sysName"] = enrichment.SnmpSysName!;
                if (!string.IsNullOrWhiteSpace(enrichment.SnmpSysContact))
                    result.SnmpValues["sysContact"] = enrichment.SnmpSysContact!;
                if (!string.IsNullOrWhiteSpace(enrichment.SnmpSysLocation))
                    result.SnmpValues["sysLocation"] = enrichment.SnmpSysLocation!;
            }

            var openPorts = result.TcpPorts
                .Where(kv => kv.Value == PortStatus.Open)
                .Select(kv => kv.Key)
                .ToList();

            if (openPorts.Count > 0)
            {
                try
                {
                    var banners = await new Probes.BannerGrabberService()
                        .GrabBannersAsync(ip, openPorts, token)
                        .ConfigureAwait(false);
                    result.Banners = banners;
                }
                catch (Exception ex) { Logger.Debug(ex, "Banner grab failed"); }
            }

            try
            {
                var sysDescr = result.SnmpValues.TryGetValue("sysDescr", out var sd) ? sd : null;
                var fp = new Probes.OsFingerprintService().Fingerprint(sysDescr, result.Banners, openPorts);
                result.OsFamily = fp.OsFamily;
                result.OsVersion = fp.OsVersion;
                result.OsConfidence = fp.Confidence;
            }
            catch (Exception ex) { Logger.Debug(ex, "OS fingerprint failed"); }

            EnrichTopologyNodeFromResult(ip, result);

            RaiseStatus("Phase3", $"Deep probe of {ip} complete. {openPorts.Count} ports open. OS={result.OsFamily ?? "Unknown"}");
            return result;
        }

        private void EnrichTopologyNodeFromResult(string ipAddress, HostProbeResult result)
        {
            if (_graph.GetNode(ipAddress) is not { } node) return;

            if (!string.IsNullOrWhiteSpace(result.Hostname))
                node.Hostname = result.Hostname;
            else if (!string.IsNullOrWhiteSpace(result.NetBiosName))
                node.Hostname = result.NetBiosName;

            if (!string.IsNullOrWhiteSpace(result.OsFamily))
                node.Attributes["osFamily"] = result.OsFamily!;
            if (!string.IsNullOrWhiteSpace(result.OsVersion))
                node.Attributes["osVersion"] = result.OsVersion!;
            node.Attributes["osConfidence"] = result.OsConfidence.ToString("0.00");

            if (result.SnmpValues.TryGetValue("sysDescr", out var sd) && !string.IsNullOrWhiteSpace(sd))
                node.SysDescr = sd;
            if (result.SnmpValues.TryGetValue("sysName", out var sn) && !string.IsNullOrWhiteSpace(sn))
                node.SysName = sn;

            node.OpenPortCount = result.TcpPorts.Count(p => p.Value == PortStatus.Open);
            node.Attributes["stale"] = "false";

            UpsertAndRaiseNode(node);
        }

        private (TopologyNode self, TopologyNode? gateway, string? subnetCidr) SeedSelfAndGateway(string sourceIp)
        {
            var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var selfNode = new TopologyNode
            {
                Id = sourceIp,
                Type = NodeType.Self,
                IpAddress = sourceIp,
                LastSeenUnixMs = nowMs
            };

            string? gatewayIp = null;
            string? subnetCidr = null;

            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    var props = nic.GetIPProperties();
                    var matched = props.UnicastAddresses
                        .FirstOrDefault(a =>
                            a.Address.AddressFamily == AddressFamily.InterNetwork
                            && a.Address.ToString() == sourceIp);
                    if (matched == null) continue;

                    var macBytes = nic.GetPhysicalAddress()?.GetAddressBytes();
                    if (macBytes != null && macBytes.Length > 0)
                    {
                        selfNode.MacAddress = string.Join(":", macBytes.Select(b => b.ToString("x2")));
                        var vendor = OuiLookup.LookupOui(selfNode.MacAddress);
                        if (!string.IsNullOrWhiteSpace(vendor)) selfNode.Vendor = vendor;
                    }

                    int prefixLen = matched.PrefixLength;
                    if (prefixLen <= 0 || prefixLen > 32)
                    {
                        var maskBytes = matched.IPv4Mask?.GetAddressBytes();
                        if (maskBytes != null && maskBytes.Length == 4)
                        {
                            uint maskVal = ((uint)maskBytes[0] << 24) | ((uint)maskBytes[1] << 16) | ((uint)maskBytes[2] << 8) | maskBytes[3];
                            prefixLen = CountBits(maskVal);
                        }
                    }

                    var bytes = matched.Address.GetAddressBytes();
                    uint addr = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
                    uint mask = prefixLen == 0 ? 0u : 0xFFFFFFFFu << (32 - prefixLen);
                    uint network = addr & mask;
                    subnetCidr = $"{(network >> 24) & 0xFF}.{(network >> 16) & 0xFF}.{(network >> 8) & 0xFF}.{network & 0xFF}/{prefixLen}";

                    foreach (var gw in props.GatewayAddresses)
                    {
                        if (gw.Address == null) continue;
                        if (gw.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        var gs = gw.Address.ToString();
                        if (gs == "0.0.0.0") continue;
                        gatewayIp = gs;
                        break;
                    }
                    break;
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Seed: NIC enumeration failed");
            }

            UpsertAndRaiseNode(selfNode);

            TopologyNode? gatewayNode = null;
            if (!string.IsNullOrWhiteSpace(gatewayIp))
            {
                gatewayNode = new TopologyNode
                {
                    Id = gatewayIp!,
                    IpAddress = gatewayIp,
                    Type = NodeType.Gateway,
                    LastSeenUnixMs = nowMs
                };
                UpsertAndRaiseNode(gatewayNode);

                var edge = new TopologyEdge
                {
                    Source = selfNode.Id,
                    Target = gatewayNode.Id,
                    Type = EdgeType.TraceroutePath,
                    LastSeenUnixMs = nowMs
                };
                edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
                UpsertAndRaiseEdge(edge);
            }

            return (selfNode, gatewayNode, subnetCidr);
        }

        private static int CountBits(uint mask)
        {
            int n = 0;
            while (mask != 0) { n += (int)(mask & 1); mask >>= 1; }
            return n;
        }

        private void OnArpSeen(object? sender, ArpSeenEventArgs e)
        {
            try
            {
                var node = new TopologyNode
                {
                    Id = e.Ip,
                    IpAddress = e.Ip,
                    MacAddress = e.Mac,
                    Type = NodeType.Host,
                    LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                var vendor = OuiLookup.LookupOui(e.Mac);
                if (!string.IsNullOrWhiteSpace(vendor)) node.Vendor = vendor;
                UpsertAndRaiseNode(node);

                if (!string.IsNullOrEmpty(_sourceIp) && _sourceIp != e.Ip)
                {
                    var arpEdge = new TopologyEdge
                    {
                        Source = _sourceIp!,
                        Target = e.Ip,
                        Type = EdgeType.ArpSeen,
                        LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    arpEdge.Id = TopologyEdge.BuildId(arpEdge.Source, arpEdge.Target, arpEdge.Type);
                    UpsertAndRaiseEdge(arpEdge);
                }
            }
            catch (Exception ex) { Logger.Debug(ex, "OnArpSeen failed"); }
        }

        private void OnFlowSeen(object? sender, FlowSeenEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(e.SourceIp) || string.IsNullOrWhiteSpace(e.DestinationIp)) return;

                var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (_graph.GetNode(e.SourceIp) == null)
                {
                    UpsertAndRaiseNode(new TopologyNode
                    {
                        Id = e.SourceIp,
                        IpAddress = e.SourceIp,
                        Type = ClassifyIp(e.SourceIp),
                        LastSeenUnixMs = nowMs
                    });
                }
                if (_graph.GetNode(e.DestinationIp) == null)
                {
                    UpsertAndRaiseNode(new TopologyNode
                    {
                        Id = e.DestinationIp,
                        IpAddress = e.DestinationIp,
                        Type = ClassifyIp(e.DestinationIp),
                        LastSeenUnixMs = nowMs
                    });
                }

                var edge = new TopologyEdge
                {
                    Source = e.SourceIp,
                    Target = e.DestinationIp,
                    Type = EdgeType.Flow,
                    Protocol = e.Protocol,
                    Packets = 1,
                    Bytes = e.PacketBytes,
                    LastSeenUnixMs = nowMs
                };
                edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
                UpsertAndRaiseEdge(edge);
            }
            catch (Exception ex) { Logger.Debug(ex, "OnFlowSeen failed"); }
        }

        private void OnArpReply(ArpSweepResult reply, string subnetCidr)
        {
            try
            {
                var node = new TopologyNode
                {
                    Id = reply.Ip,
                    IpAddress = reply.Ip,
                    MacAddress = reply.Mac,
                    Type = NodeType.Host,
                    LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                var vendor = OuiLookup.LookupOui(reply.Mac);
                if (!string.IsNullOrWhiteSpace(vendor)) node.Vendor = vendor;
                node.Attributes["subnet"] = subnetCidr;
                UpsertAndRaiseNode(node);

                if (!string.IsNullOrEmpty(_sourceIp) && _sourceIp != reply.Ip)
                {
                    var arpEdge = new TopologyEdge
                    {
                        Source = _sourceIp!,
                        Target = reply.Ip,
                        Type = EdgeType.ArpSeen,
                        LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    arpEdge.Id = TopologyEdge.BuildId(arpEdge.Source, arpEdge.Target, arpEdge.Type);
                    UpsertAndRaiseEdge(arpEdge);
                }
            }
            catch (Exception ex) { Logger.Debug(ex, "OnArpReply failed"); }
        }

        private void IntegrateGatewayTopology(TopologyNode gatewayNode, GatewayTopology topology)
        {
            var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            foreach (var arp in topology.Arps)
            {
                if (string.IsNullOrWhiteSpace(arp.IpAddress)) continue;
                var node = new TopologyNode
                {
                    Id = arp.IpAddress,
                    IpAddress = arp.IpAddress,
                    MacAddress = arp.MacAddress,
                    Type = NodeType.Host,
                    LastSeenUnixMs = nowMs
                };
                var vendor = OuiLookup.LookupOui(arp.MacAddress);
                if (!string.IsNullOrWhiteSpace(vendor)) node.Vendor = vendor;
                UpsertAndRaiseNode(node);
            }

            foreach (var route in topology.Routes)
            {
                if (string.IsNullOrWhiteSpace(route.NextHop) || route.NextHop == "0.0.0.0") continue;
                if (string.IsNullOrWhiteSpace(route.DestNetwork)) continue;

                var cloudId = $"subnet:{route.DestNetwork}";
                var cloudNode = new TopologyNode
                {
                    Id = cloudId,
                    Type = NodeType.SubnetCloud,
                    LastSeenUnixMs = nowMs
                };
                cloudNode.Attributes["network"] = route.DestNetwork;
                UpsertAndRaiseNode(cloudNode);

                var edge = new TopologyEdge
                {
                    Source = gatewayNode.Id,
                    Target = cloudId,
                    Type = EdgeType.SnmpNeighbor,
                    Protocol = "ip-route",
                    LastSeenUnixMs = nowMs
                };
                edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
                UpsertAndRaiseEdge(edge);
            }

            foreach (var neighbor in topology.Cdp)
            {
                if (string.IsNullOrWhiteSpace(neighbor.IpAddress)) continue;
                UpsertAndRaiseNode(new TopologyNode
                {
                    Id = neighbor.IpAddress!,
                    IpAddress = neighbor.IpAddress,
                    SysName = neighbor.DeviceId,
                    SysDescr = neighbor.Platform,
                    Type = NodeType.Host,
                    LastSeenUnixMs = nowMs
                });

                var edge = new TopologyEdge
                {
                    Source = gatewayNode.Id,
                    Target = neighbor.IpAddress!,
                    Type = EdgeType.SnmpNeighbor,
                    Protocol = "cdp",
                    LastSeenUnixMs = nowMs
                };
                edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
                UpsertAndRaiseEdge(edge);
            }

            foreach (var neighbor in topology.Lldp)
            {
                if (string.IsNullOrWhiteSpace(neighbor.SystemName)) continue;
                var id = $"lldp:{neighbor.SystemName}";
                var node = new TopologyNode
                {
                    Id = id,
                    SysName = neighbor.SystemName,
                    SysDescr = neighbor.SystemDescription,
                    Type = NodeType.Host,
                    LastSeenUnixMs = nowMs
                };
                if (!string.IsNullOrWhiteSpace(neighbor.PortId))
                    node.Attributes["lldpPort"] = neighbor.PortId!;
                UpsertAndRaiseNode(node);

                var edge = new TopologyEdge
                {
                    Source = gatewayNode.Id,
                    Target = id,
                    Type = EdgeType.SnmpNeighbor,
                    Protocol = "lldp",
                    LastSeenUnixMs = nowMs
                };
                edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
                UpsertAndRaiseEdge(edge);
            }
        }

        private void UpsertHostFromProbe(HostProbeResult host)
        {
            if (string.IsNullOrWhiteSpace(host.IpAddress)) return;

            var node = new TopologyNode
            {
                Id = host.IpAddress,
                IpAddress = host.IpAddress,
                Hostname = host.Hostname,
                Type = NodeType.Host,
                LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                OpenPortCount = host.TcpPorts.Values.Count(v => v == PortStatus.Open)
            };
            if (host.SnmpValues.TryGetValue("sysName", out var sysName)) node.SysName = sysName;
            if (host.SnmpValues.TryGetValue("sysDescr", out var sysDescr)) node.SysDescr = sysDescr;
            UpsertAndRaiseNode(node);
        }

        private static NodeType ClassifyIp(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr)) return NodeType.Host;
            if (addr.AddressFamily != AddressFamily.InterNetwork) return NodeType.Host;
            var bytes = addr.GetAddressBytes();
            if (bytes[0] == 10) return NodeType.Host;
            if (bytes[0] == 192 && bytes[1] == 168) return NodeType.Host;
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return NodeType.Host;
            if (bytes[0] == 169 && bytes[1] == 254) return NodeType.Host;
            return NodeType.RemoteHost;
        }

        private async Task WalkGatewayRecursiveAsync(
            string gatewayIp,
            string parentNodeId,
            int depth,
            int maxDepth,
            HashSet<string> visited,
            CancellationToken token)
        {
            if (depth > maxDepth) return;
            if (token.IsCancellationRequested) return;
            if (!visited.Add(gatewayIp)) return;

            RaiseStatus("Discovery", $"SNMP walk {gatewayIp} (depth {depth})");

            SnmpGatewayWalkResult? result = null;
            try
            {
                result = await _snmp.WalkBoundedAsync(gatewayIp, _community ?? "public", token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                Logger.Warn(ex, $"SNMP walk failed for {gatewayIp}");
                RaiseStatus("Discovery", $"{gatewayIp} SNMP walk error: {ex.Message}", true);
                return;
            }

            if (result == null || !result.Reachable)
            {
                RaiseStatus("Discovery", $"{gatewayIp} did not respond to SNMP");
                return;
            }

            var gwNode = _graph.GetNode(gatewayIp) ?? new TopologyNode
            {
                Id = gatewayIp,
                IpAddress = gatewayIp,
                Type = NodeType.Gateway
            };
            if (!string.IsNullOrWhiteSpace(result.SysName)) gwNode.SysName = result.SysName;
            if (!string.IsNullOrWhiteSpace(result.SysDescr)) gwNode.SysDescr = result.SysDescr;
            gwNode.Attributes["snmpReachable"] = "true";
            if (result.Interfaces != null && result.Interfaces.Count > 0)
            {
                try
                {
                    gwNode.Attributes["ifTable"] = System.Text.Json.JsonSerializer.Serialize(result.Interfaces);
                }
                catch { }
            }
            UpsertAndRaiseNode(gwNode);

            if (!string.Equals(parentNodeId, gatewayIp, StringComparison.Ordinal))
            {
                UpsertEdge(parentNodeId, gatewayIp, EdgeType.SnmpNeighbor, "snmp-parent");
            }

            if (result.Routes != null)
            {
                foreach (var route in result.Routes)
                {
                    if (token.IsCancellationRequested) return;
                    if (string.IsNullOrWhiteSpace(route.Destination)) continue;
                    if (route.Destination == "0.0.0.0" || route.Destination.StartsWith("127.", StringComparison.Ordinal)) continue;
                    if (route.PrefixLen <= 0 || route.PrefixLen > 32) continue;

                    var cidr = $"{route.Destination}/{route.PrefixLen}";
                    var subnetNode = UpsertSubnetCloud(cidr, $"snmp:{gatewayIp}", gatewayIp);

                    UpsertEdge(gatewayIp, subnetNode.Id, EdgeType.SnmpNeighbor, "ip-route");

                    if (!string.IsNullOrEmpty(route.NextHop)
                        && route.NextHop != "0.0.0.0"
                        && route.NextHop != gatewayIp)
                    {
                        var nextGw = _graph.GetNode(route.NextHop);
                        if (nextGw != null)
                        {
                            UpsertEdge(nextGw.Id, subnetNode.Id, EdgeType.SnmpNeighbor, "ip-route-owner");
                        }
                    }
                }
            }

            if (result.ArpEntries != null)
            {
                var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                foreach (var arp in result.ArpEntries)
                {
                    if (string.IsNullOrWhiteSpace(arp.Ip)) continue;
                    if (_graph.GetNode(arp.Ip) != null) continue;

                    var host = new TopologyNode
                    {
                        Id = arp.Ip,
                        IpAddress = arp.Ip,
                        MacAddress = arp.Mac,
                        Type = NodeType.Host,
                        LastSeenUnixMs = nowMs
                    };
                    var vendor = OuiLookup.LookupOui(arp.Mac);
                    if (!string.IsNullOrWhiteSpace(vendor)) host.Vendor = vendor;
                    host.Attributes["learnedVia"] = $"snmp.arp@{gatewayIp}";
                    UpsertAndRaiseNode(host);
                }
            }

            if (result.Neighbors != null)
            {
                foreach (var neighbor in result.Neighbors)
                {
                    if (token.IsCancellationRequested) return;

                    if (!string.IsNullOrEmpty(neighbor.ManagementIp))
                    {
                        var neighborNode = _graph.GetNode(neighbor.ManagementIp) ?? new TopologyNode
                        {
                            Id = neighbor.ManagementIp,
                            IpAddress = neighbor.ManagementIp,
                            Type = NodeType.Gateway
                        };
                        if (string.IsNullOrWhiteSpace(neighborNode.SysName) && !string.IsNullOrWhiteSpace(neighbor.SysName))
                            neighborNode.SysName = neighbor.SysName;
                        neighborNode.Attributes["discoverySource"] = neighbor.Source;
                        UpsertAndRaiseNode(neighborNode);

                        UpsertEdge(gatewayIp, neighbor.ManagementIp, EdgeType.SnmpNeighbor, neighbor.Source);

                        await WalkGatewayRecursiveAsync(
                            neighbor.ManagementIp, gatewayIp,
                            depth + 1, maxDepth, visited, token).ConfigureAwait(false);
                    }
                    else if (!string.IsNullOrWhiteSpace(neighbor.SysName))
                    {
                        var id = $"lldp:{neighbor.SysName}";
                        var partialNode = _graph.GetNode(id) ?? new TopologyNode
                        {
                            Id = id,
                            SysName = neighbor.SysName,
                            Type = NodeType.Host
                        };
                        partialNode.Attributes["noMgmtIp"] = "true";
                        partialNode.Attributes["discoverySource"] = neighbor.Source;
                        UpsertAndRaiseNode(partialNode);
                        UpsertEdge(gatewayIp, id, EdgeType.SnmpNeighbor, neighbor.Source);
                    }
                }
            }
        }

        private async Task ArpSweepReachableSubnetsAsync(string? localSubnetCidr, CancellationToken token)
        {
            if (!string.IsNullOrWhiteSpace(localSubnetCidr))
            {
                try
                {
                    RaiseStatus("Phase1", $"ARP sweeping local subnet {localSubnetCidr}");
                    var replies = await _arpSweep.SweepAsync(
                        localSubnetCidr!,
                        _sourceIp!,
                        _nicDescription,
                        reply => OnArpReply(reply, localSubnetCidr!),
                        token).ConfigureAwait(false);
                    RaiseStatus("Phase1", $"ARP sweep found {replies.Count} hosts on {localSubnetCidr}.");
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "ARP sweep failed");
                    RaiseStatus("Phase1", $"ARP sweep failed: {ex.Message}", true);
                }
            }
        }

        private TopologyNode UpsertSubnetCloud(string cidr, string discoverySource, string? gatewayHint)
        {
            var id = $"subnet:{cidr}";
            var existing = _graph.GetNode(id);
            var node = existing ?? new TopologyNode
            {
                Id = id,
                Type = NodeType.SubnetCloud
            };
            node.Attributes["subnet"] = cidr;
            node.Attributes["network"] = cidr;
            node.Attributes["discoverySource"] = discoverySource;
            if (existing == null) node.Attributes["expanded"] = "false";
            if (!string.IsNullOrWhiteSpace(gatewayHint))
                node.Attributes["gatewayHint"] = gatewayHint!;
            UpsertAndRaiseNode(node);
            return node;
        }

        private void UpsertEdge(string sourceId, string targetId, EdgeType type, string? protocol = null)
        {
            if (string.IsNullOrWhiteSpace(sourceId) || string.IsNullOrWhiteSpace(targetId)) return;
            if (string.Equals(sourceId, targetId, StringComparison.Ordinal)) return;
            var edge = new TopologyEdge
            {
                Source = sourceId,
                Target = targetId,
                Type = type,
                Protocol = protocol,
                LastSeenUnixMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            };
            edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
            UpsertAndRaiseEdge(edge);
        }

        private void UpsertAndRaiseNode(TopologyNode node)
        {
            var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var scanIdStr = _currentScanId.ToString();

            if (_currentScanId != 0)
            {
                node.Attributes["lastScanId"] = scanIdStr;
            }
            node.Attributes["stale"] = "false";
            node.LastSeenUnixMs = nowMs;

            var stored = _graph.UpsertNode(node);

            if (_currentScanId != 0)
            {
                stored.Attributes["lastScanId"] = scanIdStr;
            }
            stored.Attributes["stale"] = "false";
            stored.LastSeenUnixMs = nowMs;

            try
            {
                Logger.Info($"UpsertAndRaiseNode: id={stored.Id} type={stored.Type} " +
                            $"stale={(stored.Attributes.TryGetValue("stale", out var __s) ? __s : "MISSING")} " +
                            $"lastScanId={(stored.Attributes.TryGetValue("lastScanId", out var __l) ? __l : "MISSING")} " +
                            $"currentScanId={_currentScanId}");
                NodeChanged?.Invoke(this, new TopologyNodeChangedEventArgs { Node = stored });
            }
            catch (Exception ex) { Logger.Debug(ex, "NodeChanged listener failed"); }
        }

        private void MarkStaleNodesAfterScan()
        {
            var currentId = _currentScanId.ToString();
            var allNodes = _graph.Nodes;
            Logger.Info($"MarkStaleNodesAfterScan: currentScanId={_currentScanId}, totalNodes={allNodes.Count}, sourceIp={_sourceIp}");

            var staled = 0;
            foreach (var node in allNodes)
            {
                if (node.Type == NodeType.Self || node.Type == NodeType.SubnetCloud) continue;

                var nodeScanId = node.Attributes.TryGetValue("lastScanId", out var sid) ? sid : "MISSING";
                var refreshed = nodeScanId == currentId;

                if (refreshed)
                {
                    if (node.Attributes.TryGetValue("stale", out var s) && s == "true")
                    {
                        node.Attributes["stale"] = "false";
                        try { NodeChanged?.Invoke(this, new TopologyNodeChangedEventArgs { Node = node }); }
                        catch (Exception ex) { Logger.Debug(ex, "NodeChanged listener failed"); }
                    }
                    Logger.Info($"  Node {node.Id} (type={node.Type}): lastScanId={nodeScanId}, refreshed");
                    continue;
                }

                bool inScope = IsInCurrentScanScope(node);
                Logger.Info($"  Node {node.Id} (type={node.Type}): lastScanId={nodeScanId}, refreshed=false, inScope={inScope}");

                if (!inScope) continue;

                node.Attributes["stale"] = "true";
                try { NodeChanged?.Invoke(this, new TopologyNodeChangedEventArgs { Node = node }); }
                catch (Exception ex) { Logger.Debug(ex, "NodeChanged listener failed"); }
                staled++;
            }
            RaiseStatus("Discovery", $"Marked {staled} stale node(s).");
        }

        private bool IsInCurrentScanScope(TopologyNode node)
        {
            if (node.Type == NodeType.Gateway) return true;
            if (string.IsNullOrEmpty(node.IpAddress)) return false;
            if (string.IsNullOrEmpty(_sourceIp)) return false;
            try
            {
                var (status, _) = TargetIpExpander.DetermineRoute(node.IpAddress!, _sourceIp!);
                return status == RouteStatus.Local;
            }
            catch { return false; }
        }

        public void ClearTopology()
        {
            _graph.Clear();
            RaiseStatus("Topology", "Topology cleared by user");
        }

        private void UpsertAndRaiseEdge(TopologyEdge edge)
        {
            var stored = _graph.UpsertEdge(edge);
            try { EdgeChanged?.Invoke(this, new TopologyEdgeChangedEventArgs { Edge = stored }); }
            catch (Exception ex) { Logger.Debug(ex, "EdgeChanged listener failed"); }
        }

        private void RaiseStatus(string phase, string message, bool isError = false)
        {
            try
            {
                StatusChanged?.Invoke(this, new DiscoveryStatusEventArgs
                {
                    Phase = phase,
                    Message = message,
                    IsError = isError
                });
            }
            catch (Exception ex) { Logger.Debug(ex, "StatusChanged listener failed"); }
        }

        public void Dispose()
        {
            try { _capture.ArpSeen -= OnArpSeen; } catch { }
            try { _capture.FlowSeen -= OnFlowSeen; } catch { }
            try { _capture.Dispose(); } catch { }
            try { _phase1Cts?.Dispose(); } catch { }
        }
    }
}
