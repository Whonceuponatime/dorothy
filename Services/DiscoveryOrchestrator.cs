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

        public DiscoveryOrchestrator(DatabaseService database)
        {
            _database = database ?? throw new ArgumentNullException(nameof(database));
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

            Logger.Info($"[PROBE] Starting {level} probe on {ip}");

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
            var probe = new ReachabilityProbeService(_database);
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
        private const int BulkProbeConcurrency = 4;

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

            Logger.Info($"[BULK PROBE] Starting {level} on {ips.Count} hosts (concurrency={BulkProbeConcurrency}): " +
                string.Join(", ", ips.Take(5)) +
                (ips.Count > 5 ? $" …+{ips.Count - 5} more" : ""));

            using var gate = new SemaphoreSlim(BulkProbeConcurrency, BulkProbeConcurrency);
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

                Logger.Debug($"[BULK PROBE] Task started for {ip}");
                try
                {
                    Interlocked.Increment(ref inProgress);
                    RaiseBulk(ip);

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

            try { await Task.WhenAll(tasks).ConfigureAwait(false); }
            catch (OperationCanceledException) { /* user/timeout cancel — keep partial state */ }

            Logger.Info($"[BULK PROBE] Complete: {succeeded} succeeded, {failed} failed (of {total} total)");
            RaiseBulk(null);
            return (succeeded, failed);
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

        private static bool IsPublicIp(string? ip)
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
