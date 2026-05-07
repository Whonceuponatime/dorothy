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

    public class BulkProbeProgressEventArgs : EventArgs
    {
        public int Total { get; set; }
        public int Succeeded { get; set; }
        public int Failed { get; set; }
        public int InProgress { get; set; }
        public string? CurrentIp { get; set; }
        public ProbeLevel Level { get; set; }
    }

    public class DiscoveryOrchestrator : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly TopologyGraph _graph = new TopologyGraph();
        private readonly PassiveCaptureService _capture = new PassiveCaptureService();
        private readonly ArpSweepService _arpSweep = new ArpSweepService();
        private readonly SnmpGatewayService _snmp = new SnmpGatewayService();
        // ReachabilityProbeService is now constructed per-call inside
        // ProbeHostAsync — sharing one instance caused bulk-probe contention
        // on its singleton-run CAS guard (only 1 of N hosts could probe at
        // a time; the rest threw InvalidOperationException). DatabaseService
        // is held instead so each per-call probe can persist runs.
        private readonly DatabaseService _database;
        // Optional — when injected, ProbeHostAsync and traceroute short-
        // circuit on public targets while internet is unreachable so the
        // user gets a fast skip instead of a 60-second timeout.
        private readonly ConnectivityMonitorService? _connectivity;

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
        // Scan lifecycle. MainWindow brackets these to BeginBatch/EndBatch on
        // the canvas so live discovery doesn't trigger a cola relayout per
        // host arrival (which collapsed nodes to a single point on 89+ host
        // scans). Fired around StartDiscoveryAsync / BulkProbeAsync /
        // ExpandSubnetAsync — anything that emits a burst of NodeChanged.
        public event EventHandler? ScanStarted;
        public event EventHandler? ScanCompleted;

        private void RaiseScanStarted()
        {
            try { ScanStarted?.Invoke(this, EventArgs.Empty); }
            catch (Exception ex) { Logger.Debug(ex, "ScanStarted listener failed"); }
        }

        private void RaiseScanCompleted()
        {
            try { ScanCompleted?.Invoke(this, EventArgs.Empty); }
            catch (Exception ex) { Logger.Debug(ex, "ScanCompleted listener failed"); }
        }
        // Fired during ProbeHostAsync at each phase boundary so the UI
        // can surface human-readable progress (e.g. "Scanning 100 TCP ports…").
        public event EventHandler<string>? ProbeStageChanged;
        // Fired during BulkProbeAsync as each per-host probe starts and finishes.
        public event EventHandler<BulkProbeProgressEventArgs>? BulkProbeProgress;

        // Per-IP probe result cache. Click handlers in the NI tab read from here
        // so navigating the canvas doesn't require re-probing nodes that have
        // already been probed in this session.
        private readonly Dictionary<string, HostProbeResult> _probeResultCache = new();
        private readonly object _probeResultCacheLock = new();

        public HostProbeResult? GetCachedProbeResult(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return null;
            lock (_probeResultCacheLock)
            {
                return _probeResultCache.TryGetValue(ip, out var r) ? r : null;
            }
        }

        private void RaiseStage(string stage)
        {
            Logger.Info($"[PROBE] Stage: {stage}");
            try { ProbeStageChanged?.Invoke(this, stage); }
            catch (Exception ex) { Logger.Debug(ex, "ProbeStageChanged listener failed"); }
        }

        // Stealth mode toggle. When true, every discovery path scales back:
        //   concurrency cap of 2 (vs 4-6), 50-200ms random jitter between
        //   probes, randomised host order, and no retries on missed
        //   responses. Surveyors enable this on production ICS networks
        //   to reduce firewall-trigger and IDS-alert footprint.
        // Defaults to false so the existing fast behaviour is preserved on
        // upgrade. NiSettings persists the toggle across launches; MainWindow
        // pushes the persisted value into UpdateStealthMode at construction.
        private volatile bool _stealthMode;
        private static readonly Random _stealthRng = new Random();

        public bool StealthMode => _stealthMode;

        public void UpdateStealthMode(bool enabled)
        {
            _stealthMode = enabled;
            Logger.Info($"[ORCH] Stealth mode set to {(enabled ? "ENABLED" : "DISABLED")}");
        }

        private async Task StealthJitterAsync(CancellationToken ct)
        {
            int delayMs;
            lock (_stealthRng) { delayMs = _stealthRng.Next(50, 201); }
            try { await Task.Delay(delayMs, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* shutting down */ }
        }

        private static List<T> ShuffleStealth<T>(IEnumerable<T> source)
        {
            var list = source.ToList();
            lock (_stealthRng)
            {
                for (int i = list.Count - 1; i > 0; i--)
                {
                    int j = _stealthRng.Next(i + 1);
                    (list[i], list[j]) = (list[j], list[i]);
                }
            }
            return list;
        }

        // Debounced topology persist: rolling 1s timer flushes the in-memory
        // graph to TopologyNodes/Edges/Subnets so a close+reopen reloads the
        // surveyor's offline scan rather than starting from blank canvas.
        private readonly object _persistTimerLock = new object();
        private System.Threading.Timer? _persistTimer;
        private const int PersistDebounceMs = 1000;

        public DiscoveryOrchestrator(
            DatabaseService database,
            ConnectivityMonitorService? connectivity = null)
        {
            _database = database ?? throw new ArgumentNullException(nameof(database));
            _connectivity = connectivity;
            _capture.ArpSeen += OnArpSeen;
            _capture.FlowSeen += OnFlowSeen;
        }

        /// <summary>
        /// Reload the unsubmitted slice of TopologyNodes/Edges/Subnets so the
        /// canvas renders prior offline scans on app launch. Idempotent — calling
        /// twice just re-upserts the same content.
        /// </summary>
        public async Task LoadPersistedTopologyAsync()
        {
            try
            {
                var (rowNodes, rowEdges, rowSubnets) =
                    await _database.LoadUnsubmittedTopologyAsync().ConfigureAwait(false);

                Logger.Info(
                    $"[TOPOLOGY] Reloading from DB: {rowNodes.Count} nodes, " +
                    $"{rowEdges.Count} edges, {rowSubnets.Count} subnets");

                // Hydrate the in-memory graph WITHOUT firing per-row
                // NodeChanged / EdgeChanged events. Each event used to
                // dispatch one canvas UpsertElements call; before WebView2
                // finished navigating, the canvas's single-slot pre-init
                // buffer overwrote each call with the next, so all but the
                // last (typically a TraceroutePath edge) were dropped — the
                // surviving edge then hit cytoscape with no nodes and threw
                // "Can not create edge with nonexistant source".
                //
                // The canvas now receives the whole snapshot in a single
                // InitGraph call after this method returns (see the
                // MainWindow caller + GetCytoscapeSnapshot below).
                foreach (var rn in rowNodes)
                {
                    if (!Enum.TryParse<NodeType>(rn.NodeType, out var ntype))
                        ntype = NodeType.Host;
                    var node = new TopologyNode
                    {
                        Id = rn.NodeId,
                        Type = ntype,
                        IpAddress = rn.Ip,
                        MacAddress = rn.Mac,
                        Vendor = rn.Vendor,
                        Hostname = rn.Hostname
                    };
                    if (!string.IsNullOrWhiteSpace(rn.AttributesJson))
                    {
                        try
                        {
                            using var doc = System.Text.Json.JsonDocument.Parse(rn.AttributesJson);
                            foreach (var prop in doc.RootElement.EnumerateObject())
                            {
                                node.Attributes[prop.Name] = prop.Value.ToString() ?? string.Empty;
                            }
                        }
                        catch { /* legacy / corrupt blob — skip the bag */ }
                    }
                    _graph.UpsertNode(node);
                }

                foreach (var re in rowEdges)
                {
                    if (!Enum.TryParse<EdgeType>(re.EdgeType, out var etype))
                        etype = EdgeType.SnmpNeighbor;
                    var edge = new TopologyEdge
                    {
                        Source = re.SourceNodeId,
                        Target = re.TargetNodeId,
                        Type = etype
                    };
                    edge.Id = TopologyEdge.BuildId(edge.Source, edge.Target, edge.Type);
                    _graph.UpsertEdge(edge);
                }
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[TOPOLOGY] LoadPersistedTopologyAsync failed (non-fatal)");
            }
        }

        /// <summary>
        /// Returns the current in-memory graph as one cytoscape envelope
        /// (`{nodes:[...], edges:[...]}`). Callers push this once into
        /// TopologyCanvasControl.InitGraph after restore so cytoscape
        /// receives nodes and edges in a single ordered batch — no
        /// pre-init queue overwrites and no orphan-source errors.
        /// </summary>
        public string GetCytoscapeSnapshot()
        {
            return _graph.ToCytoscapeJson();
        }

        // Schedule a debounced flush. Each call resets the timer so a burst of
        // discovery only produces one DB write at the end.
        private void SchedulePersistTopology()
        {
            lock (_persistTimerLock)
            {
                _persistTimer ??= new System.Threading.Timer(
                    _ => _ = FlushTopologyAsync(),
                    state: null,
                    dueTime: System.Threading.Timeout.Infinite,
                    period: System.Threading.Timeout.Infinite);
                _persistTimer.Change(PersistDebounceMs, System.Threading.Timeout.Infinite);
            }
        }

        private async Task FlushTopologyAsync()
        {
            try
            {
                var nodes = _graph.Nodes;
                var edges = _graph.Edges;

                var rowNodes = new List<DatabaseService.TopologyNodeRow>(nodes.Count);
                foreach (var n in nodes)
                {
                    string? attrJson = null;
                    if (n.Attributes.Count > 0)
                    {
                        try { attrJson = System.Text.Json.JsonSerializer.Serialize(n.Attributes); }
                        catch { /* best-effort */ }
                    }
                    rowNodes.Add(new DatabaseService.TopologyNodeRow
                    {
                        NodeId = n.Id,
                        NodeType = n.Type.ToString(),
                        Ip = n.IpAddress,
                        Mac = n.MacAddress,
                        Vendor = n.Vendor,
                        Hostname = n.Hostname,
                        AttributesJson = attrJson
                    });
                }

                var rowEdges = new List<DatabaseService.TopologyEdgeRow>(edges.Count);
                foreach (var e in edges)
                {
                    string? attrJson = null;
                    if (e.Attributes.Count > 0)
                    {
                        try { attrJson = System.Text.Json.JsonSerializer.Serialize(e.Attributes); }
                        catch { }
                    }
                    rowEdges.Add(new DatabaseService.TopologyEdgeRow
                    {
                        SourceNodeId = e.Source,
                        TargetNodeId = e.Target,
                        EdgeType = e.Type.ToString(),
                        AttributesJson = attrJson
                    });
                }

                // Subnets are tracked as TopologyNodes with Type=SubnetCloud;
                // also persist a flat row in TopologySubnets for fast queries.
                var rowSubnets = new List<DatabaseService.TopologySubnetRow>();
                foreach (var n in nodes)
                {
                    if (n.Type != NodeType.SubnetCloud) continue;
                    if (!n.Attributes.TryGetValue("subnet", out var cidr)
                        && !n.Attributes.TryGetValue("network", out cidr)) continue;
                    bool isInternet = n.Attributes.TryGetValue("isInternet", out var ii) && ii == "true";
                    rowSubnets.Add(new DatabaseService.TopologySubnetRow
                    {
                        SubnetCidr = cidr ?? string.Empty,
                        Network = cidr,
                        IsLocal = !isInternet,
                        IsInternet = isInternet
                    });
                }

                await _database.UpsertTopologyAsync(rowNodes, rowEdges, rowSubnets).ConfigureAwait(false);
                EngagementContext.NotifyActivityChanged();
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[TOPOLOGY] FlushTopologyAsync failed (non-fatal)");
            }
        }

        /// <summary>
        /// Settings → "Clear all local scan data" wipes the in-memory graph too,
        /// so the canvas reflects the on-disk state.
        /// </summary>
        public void ClearGraphInMemory() => _graph.Clear();

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

            // Open the canvas batch window before any node/edge events fire,
            // so live discovery accumulates in the buffer instead of triggering
            // a per-arrival cola relayout. Closed in the finally block below.
            RaiseScanStarted();
            try
            {
                RaiseStatus("Phase1", $"Discovery starting… (scanId={_currentScanId})");

                // Seed the local subnet FIRST (before Self / gateway / ARP)
                // so every subsequent host upsert can immediately compound-parent
                // into it via AssignParentSubnet inside UpsertAndRaiseNode.
                SeedLocalSubnet(sourceIp);

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
                // Flush all buffered upserts to the canvas in one envelope.
                // Cola runs once, layout settles, no per-arrival seizure.
                RaiseScanCompleted();
            }
        }

        public void StopPassiveCapture()
        {
            try { _capture.Stop(); } catch (Exception ex) { Logger.Debug(ex, "Stop capture failed"); }
        }

        public void UpdateSourceIp(string newSourceIp)
        {
            if (string.IsNullOrWhiteSpace(newSourceIp)) return;

            var oldSourceIp = _sourceIp;
            _sourceIp = newSourceIp;

            if (!string.IsNullOrEmpty(oldSourceIp) && oldSourceIp != newSourceIp)
            {
                // Self.NodeId == sourceIp at the time SeedSelfAndGateway ran,
                // so the old node's id IS the old IP. Removing it cascades
                // to every edge keyed on it (ArpSeen, TraceroutePath, Flow);
                // otherwise those edges would persist with a missing source
                // and re-trigger the same "nonexistant source" error on the
                // next snapshot push. Caller is responsible for re-rendering
                // the canvas after this returns (see MainWindow nic handler).
                _graph.RemoveNode(oldSourceIp);
                Logger.Info(
                    $"[TOPOLOGY] Source IP changed {oldSourceIp} -> {newSourceIp}: " +
                    "removed old Self node and orphaned edges");
            }
            else
            {
                Logger.Info($"Source IP set to {newSourceIp}");
            }

            // SeedSelfAndGateway will re-seed Self at the new IP on the next
            // StartPhase1Async — the gateway also changes with the NIC, so
            // we don't pre-seed here.
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
            RaiseScanStarted();
            try
            {
                var replies = await _arpSweep.SweepAsync(
                    subnetCidr,
                    _sourceIp!,
                    _nicDescription,
                    reply => OnArpReply(reply, subnetCidr),
                    token,
                    stealthMode: _stealthMode).ConfigureAwait(false);
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
            finally
            {
                RaiseScanCompleted();
            }
        }

        /// <summary>
        /// User-triggered traceroute that renders each hop as a node on the
        /// canvas, chained by amber TraceroutePath edges from Self → hop → ...
        /// → target. Hops not in any known subnet appear as UnknownHop nodes;
        /// hops whose IPs fall in a known SubnetCloud parent automatically.
        /// </summary>
        public async Task RunInteractiveTracerouteAsync(
            string targetIp,
            string displayName,
            CancellationToken ct)
        {
            // Fast-skip public targets when we already know internet is down —
            // every TTL hop would otherwise wait the full 2s timeout × 30 hops.
            if (IsPublicIp(targetIp)
                && _connectivity?.CurrentState == ConnectivityState.LocalOnly)
            {
                RaiseStatus("Traceroute",
                    $"Cannot traceroute to {displayName} — internet is offline",
                    isError: true);
                return;
            }

            RaiseStatus("Traceroute", $"Running traceroute to {displayName} ({targetIp})...");

            using var ping = new System.Net.NetworkInformation.Ping();
            const int maxHops = 30;
            const int timeoutMs = 2000;
            var probe = new byte[32];

            string? previousHopId = _sourceIp;
            int discoveredCount = 0;

            for (int ttl = 1; ttl <= maxHops; ttl++)
            {
                if (ct.IsCancellationRequested) break;

                var options = new System.Net.NetworkInformation.PingOptions(ttl, true);
                long rttMs = 0;
                string? hopIp = null;

                try
                {
                    var sw = System.Diagnostics.Stopwatch.StartNew();
                    var reply = await ping.SendPingAsync(targetIp, timeoutMs, probe, options).ConfigureAwait(false);
                    sw.Stop();
                    rttMs = sw.ElapsedMilliseconds;

                    if (reply.Status == System.Net.NetworkInformation.IPStatus.TtlExpired
                        || reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                    {
                        hopIp = reply.Address?.ToString();
                    }
                    else if (reply.Status == System.Net.NetworkInformation.IPStatus.TimedOut)
                    {
                        // Silent hop — skip but keep walking TTL.
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, $"[TRACEROUTE] Hop {ttl} threw");
                    continue;
                }

                if (string.IsNullOrEmpty(hopIp)) continue;

                // Upsert the hop node. Reuse an existing node if we already
                // know this IP from another source (ARP, SNMP, prior probe);
                // otherwise create a fresh UnknownHop.
                var existing = _graph.GetNode(hopIp);
                var hopNode = existing ?? new TopologyNode
                {
                    Id = hopIp,
                    IpAddress = hopIp,
                    Type = (hopIp == targetIp) ? NodeType.Host : NodeType.UnknownHop
                };

                // Don't downgrade a known Host/Gateway to UnknownHop just
                // because we traced through it — only annotate.
                if (existing == null && hopIp == targetIp)
                {
                    hopNode.Type = NodeType.Host;
                }

                hopNode.Attributes["traceHop"] = ttl.ToString();
                hopNode.Attributes["traceRttMs"] = rttMs.ToString();
                if (hopIp == targetIp)
                {
                    hopNode.Attributes["traceTarget"] = displayName;
                }

                UpsertAndRaiseNode(hopNode);
                discoveredCount++;

                // After the first upsert UpsertAndRaiseNode has already tried
                // to AssignParentSubnet. If the hop's IP is public AND no
                // private subnet matched, parent it to the synthetic Internet
                // cloud (lazily seeded the first time a public hop is seen).
                var stored = _graph.GetNode(hopIp);
                if (stored != null
                    && !stored.Attributes.ContainsKey("parentSubnet")
                    && IsPublicIp(stored.IpAddress))
                {
                    EnsureInternetCloud();
                    stored.Attributes["parentSubnet"] = "internet";
                    UpsertAndRaiseNode(stored);
                }

                if (!string.IsNullOrEmpty(previousHopId)
                    && !string.Equals(previousHopId, hopIp, StringComparison.Ordinal))
                {
                    UpsertEdge(previousHopId!, hopIp, EdgeType.TraceroutePath);
                }

                RaiseStatus("Traceroute", $"Hop {ttl}: {hopIp} ({rttMs}ms)");
                previousHopId = hopIp;

                if (string.Equals(hopIp, targetIp, StringComparison.Ordinal)) break;
            }

            RaiseStatus("Traceroute", $"Complete: {discoveredCount} hop(s) to {displayName}");
        }

        // Hard per-host time budgets. Linked with the caller's token, whichever
        // fires first wins. Spec: Simple 30s, Advanced 5min.
        private const int SimpleProbeBudgetMs   =  30_000;
        private const int AdvancedProbeBudgetMs = 300_000;

        /// <summary>
        /// Single entry point for both right-click and detail-panel triggered
        /// host probes. Two tiers:
        ///   Simple   — top-100 TCP, ICMP, banner grab, DNS/NetBIOS/SNMP, OS fingerprint
        ///   Advanced — Simple + top-1000 TCP, UDP top-20, TLS inspect, HTTP paths, SMB
        /// </summary>
        public async Task<HostProbeResult> ProbeHostAsync(
            string ip,
            ProbeLevel level,
            CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(_sourceIp))
                throw new InvalidOperationException("StartDiscoveryAsync must run first.");

            // Fast skip: target is on the public internet but our connectivity
            // monitor knows the internet is down. Without this guard the probe
            // would burn the full 30s/5min budget on TCP connect timeouts.
            if (IsPublicIp(ip)
                && _connectivity?.CurrentState == ConnectivityState.LocalOnly)
            {
                Logger.Warn($"[PROBE] Skipping {ip} — public IP and internet is offline");
                RaiseStage($"[{ip}] Skipped — internet offline");
                RaiseStatus("Phase3", $"Skipped {ip} — internet offline");
                return new HostProbeResult
                {
                    IpAddress  = ip,
                    Level      = level,
                    StartedAt  = DateTime.Now,
                    CompletedAt = DateTime.Now,
                    SkipReason = "Internet offline"
                };
            }

            Logger.Info($"[PROBE] Starting {level} probe on {ip}");

            // Survey is a fundamentally different shape from Simple/Advanced
            // (no TCP port scan, vendor-blessed identification queries only,
            // gated by SNMP sysObjectID hint or open-port confirmation).
            // Branch off to a dedicated path so the Simple/Advanced flow stays
            // simple to read.
            if (level == ProbeLevel.Survey)
            {
                return await SurveyHostAsync(ip, token).ConfigureAwait(false);
            }

            using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            budgetCts.CancelAfter(level == ProbeLevel.Advanced
                ? AdvancedProbeBudgetMs
                : SimpleProbeBudgetMs);
            var ct = budgetCts.Token;

            var ports = level == ProbeLevel.Advanced
                ? PortLists.Top1000Ports.ToList()
                : PortLists.Top100Ports.ToList();

            var target = new ProbeTarget
            {
                Raw = ip,
                ExpandedIps = new List<string> { ip },
                RunRouteCheck = true,
                RunIcmpPing = true,
                RunTraceroute = level == ProbeLevel.Advanced,
                RunTcpTraceroute = false,
                RunTcpScan = true,
                TcpPorts = ports,
                RunSnmpProbe = true,
                SnmpCommunity = _community ?? "public"
            };

            HostProbeResult? captured = null;
            RaiseStatus("Phase3", $"{level} probing {ip} (top-{ports.Count} TCP)…");

            var enrichSvc = new Probes.HostEnrichmentService();
            var enrichTask = enrichSvc.EnrichAsync(ip, _community ?? "public", ct);

            // ReachabilityProbeService.StartRunAsync is a monolithic
            // ICMP + TCP-scan + SNMP run, so we surface a combined stage
            // label rather than splitting it. New instance per call —
            // its singleton-run CAS guard would otherwise serialize bulk probes.
            RaiseStage($"[{ip}] Pinging + scanning top-{ports.Count} TCP ports…");
            var probe = new ReachabilityProbeService(_database) { StealthMode = _stealthMode };
            try
            {
                await probe.StartRunAsync(
                    target,
                    _sourceIp,
                    _nicDescription,
                    $"probe:{ip}",
                    host =>
                    {
                        captured = host;
                        UpsertHostFromProbe(host);
                    },
                    _ => { },
                    ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // time-budget hit — keep partial result
            }

            var result = captured ?? new HostProbeResult { IpAddress = ip };
            result.Level = level;

            RaiseStage($"[{ip}] Querying DNS / NetBIOS / SNMP…");
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
                RaiseStage($"[{ip}] Banner grabbing {openPorts.Count} open ports…");
                try
                {
                    var banners = await new Probes.BannerGrabberService()
                        .GrabBannersAsync(ip, openPorts, ct)
                        .ConfigureAwait(false);
                    result.Banners = banners;
                }
                catch (Exception ex) { Logger.Debug(ex, "Banner grab failed"); }
            }

            // ── Advanced-only: UDP top-20, TLS cert, HTTP paths, SMB enum ──
            if (level == ProbeLevel.Advanced)
            {
                RaiseStage($"[{ip}] Scanning UDP top-20…");
                try
                {
                    RaiseStatus("Phase3", $"{ip}: UDP top-20 scan…");
                    result.UdpResults = await new Probes.UdpScannerService()
                        .ScanAsync(ip, ct).ConfigureAwait(false);
                }
                catch (Exception ex) { Logger.Debug(ex, "UDP scan failed"); }

                var tlsPorts = openPorts.Where(IsTlsPort).ToList();
                if (tlsPorts.Count > 0)
                {
                    RaiseStage($"[{ip}] Inspecting TLS certificates ({tlsPorts.Count} port(s))…");
                    result.TlsInfo ??= new Dictionary<int, TlsInfo?>();
                    var tlsSvc = new Probes.TlsInspectorService();
                    foreach (var p in tlsPorts)
                    {
                        try
                        {
                            var info = await tlsSvc.InspectTlsAsync(ip, p, ct).ConfigureAwait(false);
                            result.TlsInfo[p] = info;
                            if (info == null) continue;
                            // Mirror onto the BannerInfo so OS fingerprinting still has the signal.
                            result.Banners ??= new List<BannerInfo>();
                            int idx = result.Banners.FindIndex(b => b.Port == p);
                            if (idx >= 0)
                            {
                                var b = result.Banners[idx];
                                result.Banners[idx] = b with { Tls = info };
                            }
                            else
                            {
                                result.Banners.Add(new BannerInfo(p, null, null, null, info));
                            }
                        }
                        catch (Exception ex) { Logger.Debug(ex, $"TLS inspect failed on {ip}:{p}"); }
                    }
                }

                var httpPorts = openPorts.Where(IsHttpPort).ToList();
                if (httpPorts.Count > 0)
                {
                    RaiseStage($"[{ip}] Discovering HTTP paths ({httpPorts.Count} port(s))…");
                    var httpSvc = new Probes.HttpPathDiscoveryService();
                    result.HttpPaths ??= new Dictionary<int, List<HttpPathFinding>>();
                    foreach (var p in httpPorts)
                    {
                        bool useTls = IsTlsPort(p);
                        try
                        {
                            var findings = await httpSvc.ProbeAsync(ip, p, useTls, ct).ConfigureAwait(false);
                            if (findings.Count > 0) result.HttpPaths[p] = findings;
                        }
                        catch (Exception ex) { Logger.Debug(ex, $"HTTP path probe failed on {ip}:{p}"); }
                    }
                    if (result.HttpPaths.Count == 0) result.HttpPaths = null;
                }

                if (openPorts.Contains(445))
                {
                    RaiseStage($"[{ip}] Enumerating SMB…");
                    try
                    {
                        RaiseStatus("Phase3", $"{ip}: SMB enumerate…");
                        result.SmbInfo = await new Probes.SmbEnumerationService()
                            .EnumerateAsync(ip, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex) { Logger.Debug(ex, "SMB enumerate failed"); }
                }
            }

            RaiseStage($"[{ip}] Fingerprinting OS…");
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

            // Stamp completion time + cache for click-driven detail-panel reads.
            if (result.CompletedAt == null) result.CompletedAt = DateTime.Now;
            lock (_probeResultCacheLock) { _probeResultCache[ip] = result; }

            Logger.Info($"[PROBE] {level} probe complete on {ip}");
            RaiseStatus("Phase3", $"{level} probe of {ip} complete. {openPorts.Count} ports open. OS={result.OsFamily ?? "Unknown"}");
            return result;
        }

        // Bulk probe: run ProbeHostAsync over a list of IPs at fixed concurrency.
        // Per-host failures are swallowed so one bad target doesn't kill the run.
        // Survey uses a stricter concurrency + per-host launch gate to protect
        // production ICS networks (low-bandwidth management VLANs are common).
        private const int BulkProbeConcurrency       = 4;
        private const int BulkSurveyConcurrency      = 2;
        private const int BulkStealthConcurrency     = 2;
        private const int BulkSurveyPerHostStaggerMs = 1000;

        public async Task<(int succeeded, int failed)> BulkProbeAsync(
            List<string> ips,
            ProbeLevel level,
            CancellationToken ct)
        {
            if (ips == null || ips.Count == 0)
            {
                Logger.Warn("[BULK PROBE] Called with empty ips list");
                return (0, 0);
            }

            int concurrency = _stealthMode
                ? BulkStealthConcurrency
                : (level == ProbeLevel.Survey ? BulkSurveyConcurrency : BulkProbeConcurrency);

            // Stealth: shuffle host order so the firewall doesn't see a
            // regular ascending IP sweep. Fast mode keeps the input order.
            if (_stealthMode) ips = ShuffleStealth(ips);

            if (_stealthMode)
            {
                Logger.Info($"[NI-STEALTH] Bulk {level} started in stealth mode: " +
                    $"concurrency={concurrency}, jitter=50-200ms, order=shuffled, retries=1, hosts={ips.Count}");
            }
            else
            {
                Logger.Info($"[NI-SCAN] Bulk {level} started in fast mode: " +
                    $"concurrency={concurrency}, hosts={ips.Count}");
            }

            Logger.Info($"[BULK PROBE] {level} on {ips.Count} hosts (concurrency={concurrency}): " +
                string.Join(", ", ips.Take(5)) +
                (ips.Count > 5 ? $" …+{ips.Count - 5} more" : ""));

            using var gate = new SemaphoreSlim(concurrency, concurrency);
            int succeeded = 0;
            int failed = 0;
            int inProgress = 0;
            int total = ips.Count;

            void RaiseBulk(string? currentIp)
            {
                try
                {
                    BulkProbeProgress?.Invoke(this, new BulkProbeProgressEventArgs
                    {
                        Total = total,
                        Succeeded = Volatile.Read(ref succeeded),
                        Failed = Volatile.Read(ref failed),
                        InProgress = Volatile.Read(ref inProgress),
                        CurrentIp = currentIp,
                        Level = level
                    });
                }
                catch (Exception ex) { Logger.Debug(ex, "BulkProbeProgress listener failed"); }
            }

            // Initial 0/N tick so the UI shows the panel immediately.
            RaiseBulk(null);

            // Per-host stagger gate (Survey only): worst-case 1 new host per
            // BulkSurveyPerHostStaggerMs even if the semaphore would let
            // another in. Concurrency-2 + 1000ms gap = floor on probe-storm
            // burst rate. Implemented as a shared minimum-launch-time
            // SemaphoreSlim of capacity 1 + Task.Delay before release.
            using var staggerGate = level == ProbeLevel.Survey
                ? new SemaphoreSlim(1, 1)
                : null;

            var tasks = ips.Select(async ip =>
            {
                Logger.Debug($"[BULK PROBE] Task queued for {ip}");
                try
                {
                    await gate.WaitAsync(ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    Logger.Warn($"[BULK PROBE] Task for {ip} cancelled at gate before starting");
                    return;
                }

                if (staggerGate != null)
                {
                    try
                    {
                        await staggerGate.WaitAsync(ct).ConfigureAwait(false);
                        // Hold the stagger gate for the configured interval AFTER
                        // entering it — releases the gate so the next host can
                        // start, but only after the gap window has elapsed.
                        _ = Task.Delay(BulkSurveyPerHostStaggerMs, CancellationToken.None)
                                .ContinueWith(_ => { try { staggerGate.Release(); } catch { } });
                    }
                    catch (OperationCanceledException)
                    {
                        gate.Release();
                        return;
                    }
                }

                Logger.Debug($"[BULK PROBE] Task started for {ip}");
                try
                {
                    Interlocked.Increment(ref inProgress);
                    RaiseBulk(ip);

                    if (_stealthMode) await StealthJitterAsync(ct).ConfigureAwait(false);

                    try
                    {
                        await ProbeHostAsync(ip, level, ct).ConfigureAwait(false);
                        Interlocked.Increment(ref succeeded);
                        Logger.Debug($"[BULK PROBE] Task SUCCEEDED for {ip}");
                    }
                    catch (OperationCanceledException)
                    {
                        // User/timeout cancellation — not a failure, just stops counting.
                        Logger.Debug($"[BULK PROBE] Task cancelled for {ip}");
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref failed);
                        Logger.Warn(ex, $"[BULK PROBE] Task FAILED for {ip}");
                    }

                    Interlocked.Decrement(ref inProgress);
                    RaiseBulk(null);
                }
                finally
                {
                    gate.Release();
                }
            }).ToList();

            // Open canvas batch window before any per-host node/edge events
            // fire. Closed in finally after the run settles.
            RaiseScanStarted();
            try
            {
                try { await Task.WhenAll(tasks).ConfigureAwait(false); }
                catch (OperationCanceledException) { /* user/timeout cancel — keep partial state */ }

                Logger.Info($"[BULK PROBE] Complete: {succeeded} succeeded, {failed} failed (of {total} total)");
                RaiseBulk(null);
                return (succeeded, failed);
            }
            finally { RaiseScanCompleted(); }
        }

        // ─── Survey-tier probe ───
        // Survey is the safe-by-default tier for production ICS networks:
        //   Stage 1: ARP/discovery already confirmed the host alive
        //   Stage 2: SNMP GET on sysOIDs incl. sysObjectID, plus DNS/NetBIOS
        //   Stage 3: protocol-specific identification ONLY when the SNMP
        //            sysObjectID matches a known vendor (use HintedProtocols)
        //            OR a TCP connect-and-immediately-close confirms the port
        //            is listening on a known industrial port.
        // Zero unsolicited TCP scans.
        private const int SurveyProbeBudgetMs = 30_000;
        private const int SurveyTcpQuickCheckMs = 750;

        private async Task<HostProbeResult> SurveyHostAsync(string ip, CancellationToken token)
        {
            using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            budgetCts.CancelAfter(SurveyProbeBudgetMs);
            var ct = budgetCts.Token;

            var result = new HostProbeResult
            {
                IpAddress = ip,
                Level = ProbeLevel.Survey,
                StartedAt = DateTime.Now
            };

            RaiseStage($"[{ip}] Reachability test: querying SNMP / DNS / NetBIOS…");
            var enrichSvc = new Probes.HostEnrichmentService();
            Probes.HostEnrichmentService.EnrichmentResult? enrichment = null;
            try
            {
                enrichment = await enrichSvc.EnrichAsync(ip, _community ?? "public", ct).ConfigureAwait(false);
            }
            catch (Exception ex) { Logger.Debug(ex, "[SURVEY] Enrichment failed"); }

            if (enrichment != null)
            {
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
                if (!string.IsNullOrWhiteSpace(enrichment.SnmpSysObjectId))
                    result.SnmpValues["sysObjectID"] = enrichment.SnmpSysObjectId!;
            }

            var vendorEntry = Probes.IndustrialVendorDatabase.LookupBySysObjectID(
                enrichment?.SnmpSysObjectId);

            // Stage 3 — industrial port-open sweep. No protocol-specific
            // payloads; just TCP connect-and-close (or 1-byte UDP probe for
            // BACnet) to detect which industrial protocols the host listens
            // on. ~12 ports × concurrency-6 with 750ms each ≈ 1.5s per host.
            RaiseStage($"[{ip}] Reachability test: industrial port sweep…");
            var openPorts = await SweepIndustrialPortsAsync(ip, ct).ConfigureAwait(false);
            if (openPorts.Count > 0)
                result.IndustrialPortsOpen = openPorts;

            // Convenience back-compat slots (single-port presence flags).
            // These are derived signals; the canonical list is IndustrialPortsOpen.
            foreach (var p in openPorts)
            {
                if (p.Port == 502)
                    result.ModbusInfo = new ModbusInfo { PortOpen = true, ProbedAt = DateTime.UtcNow };
                else if (p.Port == 4840)
                    result.OpcUaInfo = new OpcUaInfo  { PortOpen = true, ProbedAt = DateTime.UtcNow };
            }

            // Synthesize IndustrialIdentity from vendor lookup + port-open heuristic.
            result.IndustrialIdentity = SynthesizeIndustrialIdentity(vendorEntry, openPorts);

            EnrichTopologyNodeFromResult(ip, result);

            if (result.CompletedAt == null) result.CompletedAt = DateTime.Now;
            lock (_probeResultCacheLock) { _probeResultCache[ip] = result; }

            Logger.Info($"[PROBE] Survey complete on {ip}");
            RaiseStatus("Phase3", $"Reachability test of {ip} complete.");
            return result;
        }

        // Quick connect-and-close check — does NOT speak the protocol on the
        // port, just confirms a TCP listener exists. Lower-noise than a SYN
        // scan because it's a complete (RST'd) TCP handshake.
        private static async Task<bool> IsTcpPortOpenAsync(string ip, int port, CancellationToken ct)
        {
            try
            {
                using var tcp = new System.Net.Sockets.TcpClient();
                using var quickCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                quickCts.CancelAfter(SurveyTcpQuickCheckMs);
                await tcp.ConnectAsync(ip, port, quickCts.Token).ConfigureAwait(false);
                return tcp.Connected;
            }
            catch { return false; }
        }

        // Industrial-protocol port → canonical name. The TCP block sweeps all
        // entries via connect-and-close; BACnet (47808 UDP) is handled
        // separately with a 1-byte send-and-listen probe.
        private static readonly (int Port, string Name)[] IndustrialTcpPorts = new[]
        {
            (102,   "S7Comm"),
            (502,   "Modbus TCP"),
            (2222,  "CIP class 1"),
            (2404,  "IEC 60870-5-104"),
            (4840,  "OPC UA"),
            (4001,  "MOXA NPort"),
            (4002,  "MOXA NPort"),
            (4003,  "MOXA NPort"),
            (4004,  "MOXA NPort"),
            (4005,  "MOXA NPort"),
            (4006,  "MOXA NPort"),
            (4007,  "MOXA NPort"),
            (4008,  "MOXA NPort"),
            (9600,  "OMRON FINS"),
            (10110, "NMEA over TCP"),
            (10111, "NMEA over TCP"),
            (10112, "NMEA over TCP"),
            (18245, "GE-SRTP"),
            (20000, "DNP3"),
            (44818, "EtherNet/IP")
        };
        private const int BacnetUdpPort = 47808;
        private const int IndustrialSweepConcurrency = 6;
        private const int IndustrialSweepStealthConcurrency = 2;

        private async Task<List<IndustrialPortInfo>> SweepIndustrialPortsAsync(
            string ip, CancellationToken ct)
        {
            var found = new List<IndustrialPortInfo>();
            var foundLock = new object();

            int concurrency = _stealthMode
                ? IndustrialSweepStealthConcurrency
                : IndustrialSweepConcurrency;

            using var gate = new SemaphoreSlim(concurrency, concurrency);

            // In stealth mode, randomise the port order so a defender's IDS
            // doesn't see a regular ascending/standard sequence.
            var orderedPorts = _stealthMode
                ? ShuffleStealth(IndustrialTcpPorts)
                : IndustrialTcpPorts.AsEnumerable();

            var tasks = orderedPorts.Select(async pp =>
            {
                try { await gate.WaitAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                try
                {
                    if (_stealthMode) await StealthJitterAsync(ct).ConfigureAwait(false);
                    if (await IsTcpPortOpenAsync(ip, pp.Port, ct).ConfigureAwait(false))
                    {
                        lock (foundLock) { found.Add(new IndustrialPortInfo(pp.Port, pp.Name)); }
                    }
                }
                finally { gate.Release(); }
            }).ToList();

            // BACnet UDP — separate from the TCP gate.
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (await IsBacnetUdpResponsiveAsync(ip, ct).ConfigureAwait(false))
                    {
                        lock (foundLock)
                        {
                            found.Add(new IndustrialPortInfo(BacnetUdpPort, "BACnet/IP"));
                        }
                    }
                }
                catch (Exception ex) { Logger.Debug(ex, $"[SURVEY] BACnet probe on {ip} failed"); }
            }, ct));

            try { await Task.WhenAll(tasks).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* fall through with partial */ }
            catch (Exception ex) { Logger.Debug(ex, $"[SURVEY] Industrial sweep on {ip} faulted"); }

            return found.OrderBy(p => p.Port).ToList();
        }

        // Minimal BACnet/IP detection — send a 1-byte UDP probe and listen
        // 750ms for any response. Open BACnet endpoints often respond with
        // a BVLC error indicating the malformed payload, which is the
        // signal we want; quiet endpoints time out (mark as not-open).
        private static async Task<bool> IsBacnetUdpResponsiveAsync(string ip, CancellationToken ct)
        {
            try
            {
                if (!System.Net.IPAddress.TryParse(ip, out var ipAddr)) return false;
                using var udp = new System.Net.Sockets.UdpClient();
                udp.Client.ReceiveTimeout = SurveyTcpQuickCheckMs;
                udp.Client.SendTimeout = SurveyTcpQuickCheckMs;
                var ep = new System.Net.IPEndPoint(ipAddr, BacnetUdpPort);
                var probe = new byte[] { 0x00 };
                try
                {
                    await udp.SendAsync(probe, probe.Length, ep).ConfigureAwait(false);
                }
                catch (System.Net.Sockets.SocketException sx)
                    when (sx.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                {
                    // ICMP port-unreachable → port closed.
                    return false;
                }

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(SurveyTcpQuickCheckMs);
                try
                {
                    var resp = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                    return resp.Buffer != null && resp.Buffer.Length > 0;
                }
                catch (System.Net.Sockets.SocketException sx)
                    when (sx.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionReset)
                {
                    return false;
                }
                catch
                {
                    // Timeout / no response — can't confirm. Conservative: not open.
                    return false;
                }
            }
            catch { return false; }
        }

        private static IndustrialIdentity? SynthesizeIndustrialIdentity(
            Probes.IndustrialVendorDatabase.VendorEntry? vendorEntry,
            List<IndustrialPortInfo> openPorts)
        {
            // Highest-confidence signal first:
            //   1. SNMP sysObjectID matched (vendorEntry != null) → use DB category
            //   2. Industrial port(s) open with no vendor match → port heuristic
            //   3. Neither → return null (host doesn't read as industrial)

            if (vendorEntry != null)
            {
                // Strongest open-port observed becomes the IndustrialIdentity.Protocol.
                // Multiple ports → list the first one; full list lives on
                // result.IndustrialPortsOpen for the detail panel.
                string protocol = openPorts.Count > 0
                    ? openPorts[0].ProtocolName
                    : "SNMP";
                return new IndustrialIdentity(
                    Vendor:          vendorEntry.Vendor,
                    ProductFamily:   null,
                    ProductName:     null,
                    FirmwareVersion: null,
                    SerialNumber:    null,
                    Protocol:        protocol,
                    Category:        vendorEntry.Category,
                    VesselZoneHint:  vendorEntry.VesselZoneHint,
                    ProbedAt:        DateTime.Now);
            }

            if (openPorts.Count > 0)
            {
                // No vendor known — apply the port-heuristic-based category.
                var (vendorHint, categoryHint, protocol) = HeuristicFromPorts(openPorts);
                return new IndustrialIdentity(
                    Vendor:          vendorHint,
                    ProductFamily:   null,
                    ProductName:     null,
                    FirmwareVersion: null,
                    SerialNumber:    null,
                    Protocol:        protocol,
                    Category:        categoryHint,
                    VesselZoneHint:  VesselZone.Unknown,
                    ProbedAt:        DateTime.Now);
            }

            return null;
        }

        // Heuristic fallback when SNMP didn't match a vendor: infer
        // vendor / category from the set of open industrial ports. Best-
        // effort hint that the user can correct via further investigation.
        private static (string? VendorHint, IndustrialCategory Category, string Protocol)
            HeuristicFromPorts(List<IndustrialPortInfo> openPorts)
        {
            if (openPorts.Count > 1)
                return (null, IndustrialCategory.Unknown, "Multiple industrial protocols");

            var only = openPorts[0];
            return only.Port switch
            {
                102   => ("likely Siemens",      IndustrialCategory.PLC,              "S7Comm"),
                502   => (null,                  IndustrialCategory.PLC,              "Modbus TCP"),
                4840  => (null,                  IndustrialCategory.PLC,              "OPC UA"),
                44818 => ("likely Allen-Bradley", IndustrialCategory.PLC,              "EtherNet/IP"),
                20000 => ("likely SCADA",        IndustrialCategory.RTU,              "DNP3"),
                2404  => (null,                  IndustrialCategory.RTU,              "IEC 60870-5-104"),
                2222  => (null,                  IndustrialCategory.PLC,              "CIP class 1"),
                18245 => (null,                  IndustrialCategory.PLC,              "GE-SRTP"),
                9600  => (null,                  IndustrialCategory.PLC,              "OMRON FINS"),
                47808 => (null,                  IndustrialCategory.HMI,              "BACnet/IP"),
                >= 4001 and <= 4008
                      => (null,                  IndustrialCategory.IndustrialSwitch, "MOXA NPort"),
                >= 10110 and <= 10112
                      => (null,                  IndustrialCategory.NavigationDevice, "NMEA over TCP"),
                _     => (null,                  IndustrialCategory.Unknown,          only.ProtocolName)
            };
        }

        // Spec-defined helpers — used by both ProbeHostAsync and the detail panel.
        private static bool IsTlsPort(int p) =>
            p == 443 || p == 8443 || p == 465 || p == 993 ||
            p == 995 || p == 636 || p == 5061;

        private static bool IsHttpPort(int p) =>
            p == 80 || p == 443 || p == 8000 || p == 8008 ||
            p == 8080 || p == 8081 || p == 8443 || p == 8888 ||
            p == 9000;

        private void EnrichTopologyNodeFromResult(string ipAddress, HostProbeResult result)
        {
            if (_graph.GetNode(ipAddress) is not { } node) return;

            if (!string.IsNullOrWhiteSpace(result.Hostname))
                node.Hostname = result.Hostname;
            else if (!string.IsNullOrWhiteSpace(result.NetBiosName))
                node.Hostname = result.NetBiosName;

            // Persist friendly-name signals as separate attrs so ComputeLabel
            // can prefer them in the right order without coalescing destroying
            // intent (e.g. NetBIOS may be more reliable than DNS reverse lookup).
            if (!string.IsNullOrWhiteSpace(result.NetBiosName))
                node.Attributes["netBiosName"] = result.NetBiosName!;
            if (!string.IsNullOrWhiteSpace(result.SmbInfo?.NetBiosComputerName))
                node.Attributes["smbComputerName"] = result.SmbInfo!.NetBiosComputerName!;

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

            // Probed-node visual badge: stamp ISO-8601 timestamp + tier so
            // topology.html can style the border and the detail panel can
            // render "Probed Xm ago (Advanced)" without re-reading the cache.
            node.Attributes["lastProbedAt"]    = DateTime.UtcNow.ToString("o");
            node.Attributes["lastProbeLevel"]  = result.Level.ToString();

            // Industrial-device classification: drives the aggressive-scan
            // warning trigger and (later rounds) cytoscape style overlays.
            // Only the four attribute keys are written; absence means "not
            // industrial / not yet identified."
            if (result.IndustrialIdentity != null)
            {
                var ind = result.IndustrialIdentity;
                if (!string.IsNullOrWhiteSpace(ind.Vendor))
                    node.Attributes["industrialVendor"] = ind.Vendor!;
                node.Attributes["industrialCategory"] = ind.Category.ToString();
                node.Attributes["industrialProtocol"] = ind.Protocol;
                if (ind.VesselZoneHint != VesselZone.Unknown)
                    node.Attributes["vesselZoneHint"] = ind.VesselZoneHint.ToString();
            }

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

                // Live "X/Y hosts" counter on the parent SubnetCloud's label.
                // Recount each time so re-discovered hosts don't double-count.
                var subnetNode = _graph.GetNode(subnetCidr) ?? _graph.GetNode($"subnet:{subnetCidr}");
                if (subnetNode != null
                    && subnetNode.Attributes.TryGetValue("subnet", out var actualCidr))
                {
                    int seen = _graph.Nodes.Count(n =>
                        n.Type != NodeType.SubnetCloud
                        && !string.IsNullOrEmpty(n.IpAddress)
                        && CidrContains(actualCidr, n.IpAddress!));
                    subnetNode.Attributes["seenHostCount"] = seen.ToString();
                    UpsertAndRaiseNode(subnetNode);
                }

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
                        token,
                        stealthMode: _stealthMode).ConfigureAwait(false);
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

        private void SeedLocalSubnet(string sourceIp)
        {
            if (string.IsNullOrEmpty(sourceIp)) return;

            try
            {
                var nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up
                        && n.GetIPProperties().UnicastAddresses
                            .Any(a => a.Address.ToString() == sourceIp));
                if (nic == null) return;

                var addr = nic.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(a => a.Address.ToString() == sourceIp);
                if (addr == null) return;

                int prefixLen = addr.PrefixLength;
                if (prefixLen <= 0 || prefixLen >= 32)
                {
                    var maskBytes = addr.IPv4Mask?.GetAddressBytes();
                    if (maskBytes != null && maskBytes.Length == 4)
                    {
                        uint maskVal = ((uint)maskBytes[0] << 24) | ((uint)maskBytes[1] << 16)
                                     | ((uint)maskBytes[2] << 8)  | maskBytes[3];
                        prefixLen = CountBits(maskVal);
                    }
                }
                if (prefixLen <= 0 || prefixLen >= 32) return;

                var ipBytes = addr.Address.GetAddressBytes();
                var networkBytes = new byte[ipBytes.Length];
                int fullBytes = prefixLen / 8;
                int remainBits = prefixLen % 8;
                for (int i = 0; i < fullBytes; i++)
                    networkBytes[i] = ipBytes[i];
                if (remainBits > 0 && fullBytes < ipBytes.Length)
                {
                    int mask = (0xFF << (8 - remainBits)) & 0xFF;
                    networkBytes[fullBytes] = (byte)(ipBytes[fullBytes] & mask);
                }
                var networkIp = new System.Net.IPAddress(networkBytes);
                var localCidr = $"{networkIp}/{prefixLen}";

                Logger.Info($"[DISCOVERY] Local subnet seeded: {localCidr} (via NIC {nic.Name})");

                var subnetNode = UpsertSubnetCloud(
                    cidr: localCidr,
                    discoverySource: "local-nic",
                    gatewayHint: null);

                // Local subnet is being populated by ARP sweep, not a separate scan.
                // Mark as "done" so it doesn't display the "scanning ⟳" glyph forever.
                subnetNode.Attributes["scanStatus"] = "done";
                subnetNode.Attributes["isLocal"] = "true";
                subnetNode.Attributes["expanded"] = "true";
                UpsertAndRaiseNode(subnetNode);
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "[DISCOVERY] SeedLocalSubnet failed");
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

            // Derive total host capacity from prefix (/24 → 254, /25 → 126, etc.)
            // /31 and /32 don't have usable host counts in the classic sense — skip.
            var prefix = ParsePrefixLength(cidr);
            if (prefix > 0 && prefix < 31 && !node.Attributes.ContainsKey("totalHostCount"))
            {
                int total = (1 << (32 - prefix)) - 2;
                node.Attributes["totalHostCount"] = total.ToString();
            }

            UpsertAndRaiseNode(node);

            // Retroactively re-parent any existing hosts whose IPs land inside
            // the newly-known subnet. Without this, hosts seen before the
            // SubnetCloud existed would never get nested visually.
            ReassignHostsToSubnet(node);
            return node;
        }

        private void ReassignHostsToSubnet(TopologyNode newSubnet)
        {
            if (newSubnet.Type != NodeType.SubnetCloud) return;
            if (!newSubnet.Attributes.TryGetValue("subnet", out var cidr)) return;

            foreach (var host in _graph.Nodes)
            {
                if (host.Type == NodeType.SubnetCloud) continue;
                if (string.IsNullOrEmpty(host.IpAddress)) continue;
                if (!CidrContains(cidr, host.IpAddress)) continue;

                AssignParentSubnet(host);

                try { NodeChanged?.Invoke(this, new TopologyNodeChangedEventArgs { Node = host }); }
                catch (Exception ex) { Logger.Debug(ex, "ReassignHostsToSubnet event raise failed"); }
            }
        }

        /// <summary>
        /// Find the most-specific known SubnetCloud whose CIDR contains
        /// host.IpAddress, stamp parentSubnet attribute, and return that
        /// subnet. Returns null if no private subnet matches. The synthetic
        /// "internet" cloud (0.0.0.0/0) is intentionally excluded — callers
        /// must opt into that fallback explicitly via IsPublicIp.
        /// </summary>
        private TopologyNode? AssignParentSubnet(TopologyNode host)
        {
            if (host.Type == NodeType.SubnetCloud) return null;
            if (string.IsNullOrEmpty(host.IpAddress)) return null;

            TopologyNode? bestMatch = null;
            int bestPrefixLen = -1;

            foreach (var subnet in _graph.Nodes)
            {
                if (subnet.Type != NodeType.SubnetCloud) continue;
                // Skip the Internet cloud — it matches everything (0.0.0.0/0)
                // but should only be used as an explicit fallback for
                // public hops, not as a passive longest-prefix match.
                if (subnet.Attributes.TryGetValue("isInternet", out var ii) && ii == "true") continue;
                if (!subnet.Attributes.TryGetValue("subnet", out var cidr)) continue;
                if (!CidrContains(cidr, host.IpAddress!)) continue;

                var prefixLen = ParsePrefixLength(cidr);
                if (prefixLen > bestPrefixLen)
                {
                    bestMatch = subnet;
                    bestPrefixLen = prefixLen;
                }
            }

            if (bestMatch != null)
            {
                host.Attributes["parentSubnet"] = bestMatch.Id;
                return bestMatch;
            }
            return null;
        }

        public static bool IsPublicIp(string? ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            try
            {
                var addr = System.Net.IPAddress.Parse(ip);
                var bytes = addr.GetAddressBytes();
                if (bytes.Length != 4) return false;

                // RFC1918 private
                if (bytes[0] == 10) return false;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;
                if (bytes[0] == 192 && bytes[1] == 168) return false;
                // Loopback
                if (bytes[0] == 127) return false;
                // Link-local
                if (bytes[0] == 169 && bytes[1] == 254) return false;
                // Multicast / reserved
                if (bytes[0] >= 224) return false;
                // CGNAT (RFC6598)
                if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return false;
                return true;
            }
            catch { return false; }
        }

        /// <summary>
        /// Lazily seed the synthetic Internet compound-parent for public-IP
        /// traceroute hops. Direct UpsertNode (not UpsertAndRaiseNode) on
        /// purpose — we don't want ReassignHostsToSubnet to re-evaluate
        /// parents for every existing host (the 0.0.0.0/0 mask matches
        /// everything, but we only want public hops to use it).
        /// </summary>
        private void EnsureInternetCloud()
        {
            if (_graph.GetNode("internet") != null) return;

            var internetCloud = new TopologyNode
            {
                Id = "internet",
                Type = NodeType.SubnetCloud
            };
            internetCloud.Attributes["subnet"] = "0.0.0.0/0";
            internetCloud.Attributes["discoverySource"] = "traceroute";
            internetCloud.Attributes["isInternet"] = "true";
            internetCloud.Attributes["scanStatus"] = "external";
            _graph.UpsertNode(internetCloud);

            try { NodeChanged?.Invoke(this, new TopologyNodeChangedEventArgs { Node = internetCloud }); }
            catch (Exception ex) { Logger.Debug(ex, "EnsureInternetCloud event raise failed"); }
        }

        private static bool CidrContains(string cidr, string ip)
        {
            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2) return false;
                if (!System.Net.IPAddress.TryParse(parts[0], out var network)) return false;
                if (!int.TryParse(parts[1], out var prefix)) return false;
                if (!System.Net.IPAddress.TryParse(ip, out var hostAddr)) return false;

                var networkBytes = network.GetAddressBytes();
                var hostBytes = hostAddr.GetAddressBytes();
                if (networkBytes.Length != hostBytes.Length) return false;

                int fullBytes = prefix / 8;
                int remainBits = prefix % 8;

                for (int i = 0; i < fullBytes; i++)
                    if (networkBytes[i] != hostBytes[i]) return false;

                if (remainBits > 0 && fullBytes < networkBytes.Length)
                {
                    int mask = (0xFF << (8 - remainBits)) & 0xFF;
                    if ((networkBytes[fullBytes] & mask) != (hostBytes[fullBytes] & mask)) return false;
                }
                return true;
            }
            catch { return false; }
        }

        private static int ParsePrefixLength(string cidr)
        {
            var parts = cidr.Split('/');
            return parts.Length == 2 && int.TryParse(parts[1], out var p) ? p : 0;
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

            // Compound-parent assignment: if any SubnetCloud now contains
            // this host's IP, stamp parentSubnet so the canvas nests it.
            // Skip SubnetCloud itself (would parent to itself / cycles).
            if (stored.Type != NodeType.SubnetCloud)
            {
                AssignParentSubnet(stored);
            }

            try
            {
                Logger.Info($"UpsertAndRaiseNode: id={stored.Id} type={stored.Type} " +
                            $"stale={(stored.Attributes.TryGetValue("stale", out var __s) ? __s : "MISSING")} " +
                            $"lastScanId={(stored.Attributes.TryGetValue("lastScanId", out var __l) ? __l : "MISSING")} " +
                            $"currentScanId={_currentScanId}");
                NodeChanged?.Invoke(this, new TopologyNodeChangedEventArgs { Node = stored });
            }
            catch (Exception ex) { Logger.Debug(ex, "NodeChanged listener failed"); }

            // Offline-first persistence: rolling 1s debounce so a burst of
            // discovery hits the DB once, not once per host.
            SchedulePersistTopology();
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
            SchedulePersistTopology();
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
