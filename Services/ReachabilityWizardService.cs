using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using Dorothy.Services.Reachability;

namespace Dorothy.Services
{

    public class ReachabilityWizardService
    {

        private readonly IcmpProbeService     _icmpProbe  = new();
        private readonly TcpConnectScanService _tcpScan   = new();
        private readonly TracerouteService    _traceroute = new();
        private const int DEFAULT_ICMP_TIMEOUT_MS = 1000;
        private const int DEFAULT_TCP_TIMEOUT_MS = 1500;
        private const int DEFAULT_ICMP_PROBE_COUNT = 3;
        private const int DEFAULT_MAX_CONCURRENT_PROBES = 32;
        private const int TRACEROUTE_TIMEOUT_MS = 5000;
        private const int TRACEROUTE_MAX_HOPS = 30;
        private const string DEFAULT_EXTERNAL_TEST_IP = "8.8.8.8";

        private static readonly int[] COMPREHENSIVE_BOUNDARY_PORTS = new int[]
        {

            80, 443, 8080, 8443, 8000, 8008, 8009, 8010, 8081, 8888, 9000, 9090,

            22, 23, 2222, 2223,

            25, 110, 143, 993, 995, 587, 465,

            53,

            21, 20, 2121,

            3306, 5432, 1433, 1521, 27017, 6379, 9200, 9300,

            3389, 5900, 5901, 5902,

            139, 445,

            135,

            161, 162,

            389, 636,

            514, 873, 2049, 3300, 5000, 5001, 5060, 5433, 5985, 5986,
            7001, 7002, 8181, 8880, 10000,

            502, 20000, 2404, 4840, 789, 1911, 2222,

            7, 9, 13, 17, 19, 37, 42, 49, 53, 67, 68, 69, 88, 111, 113, 119, 123, 135, 137, 138, 139, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443
        };

        public IPAddress? GetBoundaryGatewayForNic(string sourceNicId)
        {
            try
            {
                var nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.Id == sourceNicId);

                if (nic == null)
                    return null;

                var gateway = nic.GetIPProperties()?.GatewayAddresses
                    .Select(g => g?.Address)
                    .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                return gateway;
            }
            catch
            {
                return null;
            }
        }

        public string? GetBoundaryVendor(IPAddress gatewayIp)
        {

            return null;
        }

        public async Task<List<IcmpReachabilityResult>> RunIcmpChecksAsync(
            AnalysisContext context,
            IProgress<(string message, int percent)>? progress,
            CancellationToken token)
        {
            var results = new List<IcmpReachabilityResult>();

            var targets = new List<(IPAddress Ip, string Role)>();

            if (context.BoundaryGatewayIp != null)
            {
                targets.Add((context.BoundaryGatewayIp, "Boundary device"));
            }

            if (context.Mode == AnalysisMode.RemoteNetworkKnown)
            {

                var gatewayCandidates = ExtractGatewayCandidates(context.TargetCidr);
                foreach (var gateway in gatewayCandidates)
                {
                    targets.Add((gateway, "Gateway candidate"));
                }

                foreach (var asset in context.InsideAssets)
                {
                    targets.Add((asset.AssetIp, "Known asset"));
                }
            }
            else if (context.Mode == AnalysisMode.BoundaryOnly)
            {

                if (context.ExternalTestIp != null)
                {
                    targets.Add((context.ExternalTestIp, "External test target"));
                }
            }

            int totalTargets = targets.Count;
            int completed = 0;

            progress?.Report(($"[ICMP] Testing {totalTargets} targets...", 0));

            foreach (var (ip, role) in targets)
            {
                if (token.IsCancellationRequested)
                    break;

                int percent = totalTargets > 0 ? (completed * 100) / totalTargets : 0;
                progress?.Report(($"[ICMP] Testing {ip} ({role})... ({completed + 1}/{totalTargets})", percent));

                var probeResult = await _icmpProbe.ProbeAsync(
                    ip, DEFAULT_ICMP_PROBE_COUNT, DEFAULT_ICMP_TIMEOUT_MS, token);

                var result = new IcmpReachabilityResult
                {
                    TargetIp  = ip,
                    Role      = role,
                    Sent      = probeResult.Sent,
                    Received  = probeResult.Received,
                    Reachable = probeResult.Reachable,
                    AvgRttMs  = probeResult.AvgRttMs
                };

                try
                {
                    completed++;
                    int finalPercent = totalTargets > 0 ? (completed * 100) / totalTargets : 100;
                    progress?.Report(($"[ICMP] {ip}: {(result.Reachable ? "Reachable" : "Not reachable")} ({result.Received}/{result.Sent})", finalPercent));
                }
                catch (Exception ex)
                {
                    completed++;
                    int finalPercent = totalTargets > 0 ? (completed * 100) / totalTargets : 100;
                    progress?.Report(($"[ICMP] {ip}: Error - {ex.Message}", finalPercent));
                }

                results.Add(result);
            }

            progress?.Report(("ICMP checks completed.", 100));

            return results;
        }

        public async Task<List<TcpReachabilityResult>> RunTcpChecksAsync(
            AnalysisContext context,
            IEnumerable<IcmpReachabilityResult> icmpResults,
            IEnumerable<int> probePorts,
            IProgress<(string message, int percent)>? progress,
            CancellationToken token)
        {
            var results = new List<TcpReachabilityResult>();
            var ports = probePorts.ToList();
            var semaphore = new SemaphoreSlim(DEFAULT_MAX_CONCURRENT_PROBES);

            var targetIps = icmpResults.Select(r => r.TargetIp).Distinct().ToList();

            int totalTests = targetIps.Count * ports.Count;
            int completedTests = 0;
            object lockObject = new object();

            progress?.Report(($"[TCP] Testing {targetIps.Count} IPs on {ports.Count} ports ({totalTests} total tests)...", 0));

            var tasks = new List<Task>();

            foreach (var ip in targetIps)
            {
                foreach (var port in ports)
                {
                    if (token.IsCancellationRequested)
                        break;

                    var task = Task.Run(async () =>
                    {
                        await semaphore.WaitAsync(token);
                        try
                        {
                            var result = await TestTcpPortAsync(ip, port, token);
                            lock (results)
                            {
                                results.Add(result);
                            }

                            lock (lockObject)
                            {
                                completedTests++;
                                int percent = totalTests > 0 ? (completedTests * 100) / totalTests : 0;
                                progress?.Report(($"[TCP] {ip}:{port} - {result.State} ({completedTests}/{totalTests})", percent));
                            }
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, token);

                    tasks.Add(task);
                }
            }

            await Task.WhenAll(tasks);

            progress?.Report(("TCP checks completed.", 100));

            return results;
        }

        private async Task<TcpReachabilityResult> TestTcpPortAsync(
            IPAddress ip,
            int port,
            CancellationToken token)
        {
            var portResult = await _tcpScan.ProbePortAsync(ip, port, DEFAULT_TCP_TIMEOUT_MS, token);

            var wizardState = portResult.State switch
            {
                Reachability.PortState.Open               => Models.TcpState.Open,
                Reachability.PortState.Closed             => Models.TcpState.Closed,
                Reachability.PortState.TimedOut           => Models.TcpState.TimedOut,
                Reachability.PortState.NetworkUnreachable => Models.TcpState.NetworkUnreachable,
                Reachability.PortState.HostUnreachable    => Models.TcpState.HostUnreachable,
                Reachability.PortState.Error              => Models.TcpState.Error,
                _                                          => Models.TcpState.Filtered
            };

            return new TcpReachabilityResult
            {
                TargetIp     = ip,
                Port         = port,
                State        = wizardState,
                RttMs        = portResult.RttMs,
                ErrorMessage = portResult.Error
            };
        }

        public async Task<PathAnalysisResult?> RunPathAnalysisAsync(
            AnalysisContext context,
            IEnumerable<IcmpReachabilityResult> icmpResults,
            IEnumerable<TcpReachabilityResult> tcpResults,
            IProgress<(string message, int percent)>? progress,
            CancellationToken token)
        {
            IPAddress? targetIp = null;

            if (context.Mode == AnalysisMode.RemoteNetworkKnown)
            {

                var reachableIps = icmpResults
                    .Where(r => r.Reachable)
                    .Select(r => r.TargetIp)
                    .Concat(tcpResults
                        .Where(r => r.State != Models.TcpState.Filtered)
                        .Select(r => r.TargetIp))
                    .Distinct()
                    .Where(ip => ip != context.BoundaryGatewayIp)
                    .ToList();

                if (reachableIps.Any())
                {

                    targetIp = reachableIps.FirstOrDefault(ip =>
                        icmpResults.Any(r => r.TargetIp.Equals(ip) && r.Role == "Gateway candidate"))
                        ?? reachableIps.FirstOrDefault(ip =>
                        icmpResults.Any(r => r.TargetIp.Equals(ip) && r.Role == "Known asset"))
                        ?? reachableIps.First();
                }
                else
                {

                    var gatewayCandidates = ExtractGatewayCandidates(context.TargetCidr);
                    if (gatewayCandidates.Any())
                    {
                        targetIp = gatewayCandidates.First();
                    }
                    else if (context.InsideAssets.Any())
                    {
                        targetIp = context.InsideAssets.First().AssetIp;
                    }
                }
            }
            else if (context.Mode == AnalysisMode.BoundaryOnly)
            {

                targetIp = context.ExternalTestIp;
            }

            if (targetIp == null)
            {
                progress?.Report(("[Path] No suitable target found for path analysis", 0));
                return null;
            }

            progress?.Report(($"[Path] Tracing path to {targetIp}...", 0));

            var result = new PathAnalysisResult
            {
                TargetIp = targetIp
            };

            try
            {
                progress?.Report(("[Path] Tracing hops (hostname resolution non-blocking)...", 10));

                var hopResults = await _traceroute.TraceAsync(
                    targetIp, TRACEROUTE_MAX_HOPS, TRACEROUTE_TIMEOUT_MS,
                    resolveHostnames: true, ct: token);

                var hops = hopResults.Select(h => new PathHop
                {
                    HopNumber = h.HopNumber,
                    HopIp     = h.HopIp,
                    RttMs     = h.RttMs,
                    Hostname  = h.Hostname
                }).ToList();

                result.Completed = hops.Count > 0 &&
                    hops[hops.Count - 1].HopIp?.Equals(targetIp) == true;

                if (result.Completed)
                    progress?.Report(($"[Path] Reached target in {hops.Count} hops", 100));

                result.Hops = hops;

                if (result.Completed)
                {
                    result.Notes = $"Path reached target in {hops.Count} hops.";
                }
                else
                {
                    var lastHop = hops.LastOrDefault();
                    if (lastHop?.HopIp != null && context.BoundaryGatewayIp != null && lastHop.HopIp.Equals(context.BoundaryGatewayIp))
                    {
                        result.Notes = $"Path stops at boundary device {context.BoundaryGatewayIp}. Traffic towards target appears blocked or unrouted beyond this firewall.";
                    }
                    else if (lastHop != null)
                    {
                        result.Notes = $"Path did not reach target. Last visible hop: {lastHop.HopIpString} (hop {lastHop.HopNumber}).";
                    }
                    else
                    {
                        result.Notes = $"Path analysis incomplete. No hops recorded.";
                    }
                }
            }
            catch (Exception ex)
            {
                result.Notes = $"Path analysis error: {ex.Message}";
                progress?.Report(($"[Path] Error: {ex.Message}", 100));
            }

            if (!result.Completed && result.Hops.Count > 0)
            {
                progress?.Report(("Path analysis completed.", 100));
            }

            return result;
        }

        public async Task<List<DeeperScanResult>> RunDeeperScanAsync(
            AnalysisContext context,
            IEnumerable<IcmpReachabilityResult> icmpResults,
            IEnumerable<TcpReachabilityResult> tcpResults,
            IEnumerable<int> scanPorts,
            IProgress<(string message, int percent)>? progress,
            CancellationToken token)
        {
            var results = new List<DeeperScanResult>();
            var ports = scanPorts.ToList();
            var semaphore = new SemaphoreSlim(DEFAULT_MAX_CONCURRENT_PROBES);

            var boundaryIps = new HashSet<IPAddress>();
            var reachableIps = new HashSet<IPAddress>();

            int totalBoundaryPorts = 0;
            int totalRegularPorts = 0;
            int totalTests = 0;
            int completedTests = 0;
            object lockObject = new object();

            if (context.Mode == AnalysisMode.RemoteNetworkKnown)
            {

                if (context.BoundaryGatewayIp != null)
                {
                    boundaryIps.Add(context.BoundaryGatewayIp);
                }

                foreach (var icmp in icmpResults.Where(r => r.Reachable))
                {
                    var ip = icmp.TargetIp;
                    var ipBytes = ip.GetAddressBytes();

                    if (icmp.Role == "Boundary device" || icmp.Role == "Gateway candidate")
                    {
                        boundaryIps.Add(ip);
                    }

                    else if (ipBytes[3] == 1 || ipBytes[3] == 254)
                    {
                        boundaryIps.Add(ip);
                        progress?.Report(($"[Deeper Scan] Detected potential boundary device: {ip} (gateway pattern)", 0));
                    }
                    else
                    {
                        reachableIps.Add(ip);
                    }
                }

                foreach (var tcp in tcpResults.Where(r => r.State.IsActiveResponse()))
                {
                    if (!boundaryIps.Contains(tcp.TargetIp))
                    {
                        reachableIps.Add(tcp.TargetIp);
                    }
                }
            }
            else if (context.Mode == AnalysisMode.BoundaryOnly)
            {

                if (context.BoundaryGatewayIp != null)
                {
                    boundaryIps.Add(context.BoundaryGatewayIp);
                }
            }

            totalBoundaryPorts = boundaryIps.Count * COMPREHENSIVE_BOUNDARY_PORTS.Length;
            totalRegularPorts = reachableIps.Count * ports.Count;
            totalTests = totalBoundaryPorts + totalRegularPorts;

            if (boundaryIps.Any())
            {
                progress?.Report(($"[Deeper Scan] Found {boundaryIps.Count} boundary device(s). Scanning with comprehensive port list ({COMPREHENSIVE_BOUNDARY_PORTS.Length} ports) to understand firewall rules...", 0));
            }

            if (reachableIps.Any())
            {
                progress?.Report(($"[Deeper Scan] Scanning {reachableIps.Count} regular host(s) on {ports.Count} ports...", 0));
            }

            if (!boundaryIps.Any() && !reachableIps.Any())
            {
                progress?.Report(("[Deeper Scan] No reachable hosts to scan.", 100));
                return results;
            }

            foreach (var ip in boundaryIps)
            {
                if (token.IsCancellationRequested)
                    break;

                progress?.Report(($"[Deeper Scan] Scanning boundary device {ip} with comprehensive port list ({COMPREHENSIVE_BOUNDARY_PORTS.Length} ports) to understand firewall rules...", totalTests > 0 ? (completedTests * 100) / totalTests : 0));

                var scanResult = new DeeperScanResult
                {
                    TargetIp = ip
                };

                var tasks = new List<Task>();

                foreach (var port in COMPREHENSIVE_BOUNDARY_PORTS)
                {
                    if (token.IsCancellationRequested)
                        break;

                    var task = Task.Run(async () =>
                    {
                        await semaphore.WaitAsync(token);
                        try
                        {
                            var portResult = await TestTcpPortAsync(ip, port, token);
                            lock (scanResult.PortStates)
                            {
                                scanResult.PortStates[port] = portResult.State;
                            }

                            lock (lockObject)
                            {
                                completedTests++;
                                int percent = totalTests > 0 ? (completedTests * 100) / totalTests : 0;
                                progress?.Report(($"[Deeper Scan] {ip}:{port} - {portResult.State} ({completedTests}/{totalTests})", percent));
                            }
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, token);

                    tasks.Add(task);
                }

                await Task.WhenAll(tasks);

                var openCount     = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Open);
                var closedCount   = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Closed);
                var filteredCount = scanResult.PortStates.Count(kvp => kvp.Value.IsNoResponse());

                scanResult.Summary = $"{openCount} open, {closedCount} closed, {filteredCount} filtered/timed out";

                results.Add(scanResult);
                progress?.Report(($"[Deeper Scan] Boundary device {ip}: {scanResult.Summary}", totalTests > 0 ? (completedTests * 100) / totalTests : 0));
            }

            foreach (var ip in reachableIps)
            {
                if (token.IsCancellationRequested)
                    break;

                progress?.Report(($"[Deeper Scan] Scanning {ip}...", totalTests > 0 ? (completedTests * 100) / totalTests : 0));

                var scanResult = new DeeperScanResult
                {
                    TargetIp = ip
                };

                var tasks = new List<Task>();

                foreach (var port in ports)
                {
                    if (token.IsCancellationRequested)
                        break;

                    var task = Task.Run(async () =>
                    {
                        await semaphore.WaitAsync(token);
                        try
                        {
                            var portResult = await TestTcpPortAsync(ip, port, token);
                            lock (scanResult.PortStates)
                            {
                                scanResult.PortStates[port] = portResult.State;
                            }

                            lock (lockObject)
                            {
                                completedTests++;
                                int percent = totalTests > 0 ? (completedTests * 100) / totalTests : 0;
                                progress?.Report(($"[Deeper Scan] {ip}:{port} - {portResult.State} ({completedTests}/{totalTests})", percent));
                            }
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, token);

                    tasks.Add(task);
                }

                await Task.WhenAll(tasks);

                var openCount     = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Open);
                var closedCount   = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Closed);
                var filteredCount = scanResult.PortStates.Count(kvp => kvp.Value.IsNoResponse());

                scanResult.Summary = $"{openCount} open, {closedCount} closed, {filteredCount} filtered/timed out";

                results.Add(scanResult);
                progress?.Report(($"[Deeper Scan] {ip}: {scanResult.Summary}", totalTests > 0 ? (completedTests * 100) / totalTests : 0));
            }

            progress?.Report(("Deeper scan completed.", 100));
            await Task.Delay(100, token);
            while (semaphore.CurrentCount < DEFAULT_MAX_CONCURRENT_PROBES)
            {
                await Task.Delay(100, token);
            }

            return results;
        }

        public List<IPAddress> ExtractGatewayCandidates(string cidr)
        {
            var candidates = new List<IPAddress>();

            try
            {
                if (string.IsNullOrWhiteSpace(cidr))
                    return candidates;

                var parts = cidr.Split('/');
                if (parts.Length != 2)
                    return candidates;

                if (!IPAddress.TryParse(parts[0], out IPAddress? networkIp))
                    return candidates;

                if (!int.TryParse(parts[1], out int prefixLength) || prefixLength < 0 || prefixLength > 32)
                    return candidates;

                var networkBytes = networkIp.GetAddressBytes();
                var maskBits = prefixLength;
                var hostBits = 32 - maskBits;

                if (hostBits <= 0)
                    return candidates;

                var maskBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    if (maskBits >= 8)
                    {
                        maskBytes[i] = 255;
                        maskBits -= 8;
                    }
                    else if (maskBits > 0)
                    {
                        maskBytes[i] = (byte)(255 << (8 - maskBits));
                        maskBits = 0;
                    }
                }

                var networkStart = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkStart[i] = (byte)(networkBytes[i] & maskBytes[i]);
                }

                var firstHost = new byte[4];
                Array.Copy(networkStart, firstHost, 4);
                firstHost[3] += 1;
                if (IPAddress.TryParse(string.Join(".", firstHost), out IPAddress? firstHostIp))
                {
                    candidates.Add(firstHostIp);
                }

                var lastHost = new byte[4];
                Array.Copy(networkStart, lastHost, 4);

                for (int i = 0; i < 4; i++)
                {
                    lastHost[i] = (byte)(networkStart[i] | ~maskBytes[i]);
                }

                if (prefixLength == 24)
                {
                    lastHost[3] = 254;
                }
                else
                {

                    if (lastHost[3] > 0)
                    {
                        lastHost[3]--;
                    }
                    else if (lastHost[2] > 0)
                    {
                        lastHost[2]--;
                        lastHost[3] = 254;
                    }
                }

                if (IPAddress.TryParse(string.Join(".", lastHost), out IPAddress? lastHostIp))
                {
                    candidates.Add(lastHostIp);
                }
            }
            catch
            {

            }

            return candidates;
        }
    }
}

