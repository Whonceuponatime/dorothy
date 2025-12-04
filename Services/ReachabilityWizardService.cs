using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services
{
    /// <summary>
    /// Service for reachability and path analysis wizard
    /// </summary>
    public class ReachabilityWizardService
    {
        private const int DEFAULT_ICMP_TIMEOUT_MS = 1000;
        private const int DEFAULT_TCP_TIMEOUT_MS = 1500;
        private const int DEFAULT_ICMP_PROBE_COUNT = 3;
        private const int DEFAULT_MAX_CONCURRENT_PROBES = 32;
        private const int TRACEROUTE_TIMEOUT_MS = 5000;
        private const int TRACEROUTE_MAX_HOPS = 30;
        private const string DEFAULT_EXTERNAL_TEST_IP = "8.8.8.8";

        /// <summary>
        /// Comprehensive port list for boundary device rule discovery (common ports + well-known services)
        /// </summary>
        private static readonly int[] COMPREHENSIVE_BOUNDARY_PORTS = new int[]
        {
            // Common web/HTTP
            80, 443, 8080, 8443, 8000, 8008, 8009, 8010, 8081, 8888, 9000, 9090,
            // SSH/Telnet
            22, 23, 2222, 2223,
            // Email
            25, 110, 143, 993, 995, 587, 465,
            // DNS
            53,
            // FTP
            21, 20, 2121,
            // Database
            3306, 5432, 1433, 1521, 27017, 6379, 9200, 9300,
            // Remote Desktop/VNC
            3389, 5900, 5901, 5902,
            // SMB/File sharing
            139, 445,
            // RPC
            135,
            // SNMP
            161, 162,
            // LDAP
            389, 636,
            // Other common services
            514, 873, 2049, 3300, 5000, 5001, 5060, 5433, 5985, 5986,
            7001, 7002, 8181, 8880, 10000,
            // Industrial/OT
            502, 20000, 2404, 4840, 789, 1911, 2222,
            // Additional common ports
            7, 9, 13, 17, 19, 37, 42, 49, 53, 67, 68, 69, 88, 111, 113, 119, 123, 135, 137, 138, 139, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443
        };

        /// <summary>
        /// Get boundary gateway IP for a network interface
        /// </summary>
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

        /// <summary>
        /// Get boundary vendor (OUI lookup) - placeholder for future implementation
        /// </summary>
        public string? GetBoundaryVendor(IPAddress gatewayIp)
        {
            // TODO: Implement OUI lookup from MAC address
            // For now, return null
            return null;
        }

        /// <summary>
        /// Run ICMP checks including boundary device and mode-specific targets
        /// </summary>
        public async Task<List<IcmpReachabilityResult>> RunIcmpChecksAsync(
            AnalysisContext context,
            IProgress<(string message, int percent)>? progress,
            CancellationToken token)
        {
            var results = new List<IcmpReachabilityResult>();

            // Build target list
            var targets = new List<(IPAddress Ip, string Role)>();

            // Always add boundary device if available
            if (context.BoundaryGatewayIp != null)
            {
                targets.Add((context.BoundaryGatewayIp, "Boundary device"));
            }

            // Mode-specific targets
            if (context.Mode == AnalysisMode.RemoteNetworkKnown)
            {
                // Extract gateway candidates from CIDR (X.Y.Z.1 and X.Y.Z.254)
                var gatewayCandidates = ExtractGatewayCandidates(context.TargetCidr);
                foreach (var gateway in gatewayCandidates)
                {
                    targets.Add((gateway, "Gateway candidate"));
                }

                // Add known inside assets
                foreach (var asset in context.InsideAssets)
                {
                    targets.Add((asset.AssetIp, "Known asset"));
                }
            }
            else if (context.Mode == AnalysisMode.BoundaryOnly)
            {
                // Add external test IP if set
                if (context.ExternalTestIp != null)
                {
                    targets.Add((context.ExternalTestIp, "External test target"));
                }
            }

            int totalTargets = targets.Count;
            int completed = 0;
            
            progress?.Report(($"[ICMP] Testing {totalTargets} targets...", 0));

            // Test each target
            foreach (var (ip, role) in targets)
            {
                if (token.IsCancellationRequested)
                    break;

                int percent = totalTargets > 0 ? (completed * 100) / totalTargets : 0;
                progress?.Report(($"[ICMP] Testing {ip} ({role})... ({completed + 1}/{totalTargets})", percent));

                var result = new IcmpReachabilityResult
                {
                    TargetIp = ip,
                    Role = role,
                    Sent = DEFAULT_ICMP_PROBE_COUNT
                };

                try
                {
                    using var ping = new Ping();
                    var rtts = new List<long>();

                    for (int i = 0; i < DEFAULT_ICMP_PROBE_COUNT; i++)
                    {
                        if (token.IsCancellationRequested)
                            break;

                        try
                        {
                            var reply = await ping.SendPingAsync(ip, DEFAULT_ICMP_TIMEOUT_MS);
                            if (reply != null && reply.Status == IPStatus.Success)
                            {
                                result.Received++;
                                rtts.Add(reply.RoundtripTime);
                            }
                        }
                        catch
                        {
                            // Ping failed, continue
                        }

                        // Small delay between pings
                        if (i < DEFAULT_ICMP_PROBE_COUNT - 1)
                        {
                            await Task.Delay(200, token);
                        }
                    }

                    result.Reachable = result.Received > 0;
                    if (rtts.Count > 0)
                    {
                        result.AvgRttMs = (long)rtts.Average();
                    }

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

        /// <summary>
        /// Run TCP checks on targets from ICMP stage
        /// </summary>
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

            // Get all IPs from ICMP stage
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

        /// <summary>
        /// Test a single TCP port
        /// </summary>
        private async Task<TcpReachabilityResult> TestTcpPortAsync(
            IPAddress ip,
            int port,
            CancellationToken token)
        {
            var result = new TcpReachabilityResult
            {
                TargetIp = ip,
                Port = port,
                State = Models.TcpState.Filtered
            };

            var startTime = DateTime.UtcNow;

            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ip, port);
                var timeoutTask = Task.Delay(DEFAULT_TCP_TIMEOUT_MS, token);

                var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                var elapsed = (DateTime.UtcNow - startTime).TotalMilliseconds;
                result.RttMs = (long)elapsed;

                if (completedTask == connectTask)
                {
                    if (client.Connected)
                    {
                        result.State = Models.TcpState.Open;
                        client.Close();
                    }
                    else
                    {
                        result.State = Models.TcpState.Closed;
                    }
                }
                else
                {
                    result.State = Models.TcpState.Filtered;
                }
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                result.State = Models.TcpState.Closed;
                var elapsed = (DateTime.UtcNow - startTime).TotalMilliseconds;
                result.RttMs = (long)elapsed;
            }
            catch (Exception ex)
            {
                result.State = Models.TcpState.Filtered;
                result.ErrorMessage = ex.Message;
                var elapsed = (DateTime.UtcNow - startTime).TotalMilliseconds;
                result.RttMs = (long)elapsed;
            }

            return result;
        }

        /// <summary>
        /// Run path analysis (traceroute) - always attempt something
        /// </summary>
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
                // Prefer any IP from IcmpResults/TcpResults with evidence of reachability
                var reachableIps = icmpResults
                    .Where(r => r.Reachable)
                    .Select(r => r.TargetIp)
                    .Concat(tcpResults
                        .Where(r => r.State != Models.TcpState.Filtered)
                        .Select(r => r.TargetIp))
                    .Distinct()
                    .Where(ip => ip != context.BoundaryGatewayIp) // Exclude boundary
                    .ToList();

                if (reachableIps.Any())
                {
                    // Prefer gateway candidate, then known asset
                    targetIp = reachableIps.FirstOrDefault(ip => 
                        icmpResults.Any(r => r.TargetIp.Equals(ip) && r.Role == "Gateway candidate")) 
                        ?? reachableIps.FirstOrDefault(ip => 
                        icmpResults.Any(r => r.TargetIp.Equals(ip) && r.Role == "Known asset"))
                        ?? reachableIps.First();
                }
                else
                {
                    // No reachable targets - choose first gateway candidate or known asset
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
                // Use external test IP
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
                var hops = new List<PathHop>();
                int maxHops = TRACEROUTE_MAX_HOPS;

                for (int ttl = 1; ttl <= maxHops; ttl++)
                {
                    if (token.IsCancellationRequested)
                        break;

                    int percent = (ttl * 100) / maxHops;
                    progress?.Report(($"[Path] Testing hop {ttl}/{maxHops}...", percent));

                    var hop = await SendTraceroutePingAsync(targetIp, ttl, token);
                    hops.Add(hop);

                    if (hop.HopIp != null && hop.HopIp.Equals(targetIp))
                    {
                        result.Completed = true;
                        progress?.Report(($"[Path] Reached target in {ttl} hops", 100));
                        break;
                    }

                    if (hop.HopIp == null && hops.Count >= 3)
                    {
                        // Multiple timeouts, likely blocked or unreachable
                        result.Notes = $"Path stopped at hop {ttl - 1}. Likely firewall/L3 boundary or unreachable.";
                        progress?.Report(($"[Path] Path stopped at hop {ttl - 1}", 100));
                        break;
                    }
                }

                result.Hops = hops;

                // Generate notes based on completion and boundary
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

        /// <summary>
        /// Send a single traceroute ping with specific TTL
        /// </summary>
        private async Task<PathHop> SendTraceroutePingAsync(
            IPAddress targetIp,
            int ttl,
            CancellationToken token)
        {
            var hop = new PathHop
            {
                HopNumber = ttl
            };

            try
            {
                using var ping = new Ping();
                var options = new PingOptions(ttl, true);
                byte[] buffer = new byte[32];

                var reply = await ping.SendPingAsync(targetIp, TRACEROUTE_TIMEOUT_MS, buffer, options);

                if (reply != null && (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success))
                {
                    hop.HopIp = reply.Address;
                    hop.RttMs = reply.RoundtripTime;

                    // Try to get hostname
                    try
                    {
                        var hostEntry = await Dns.GetHostEntryAsync(reply.Address);
                        hop.Hostname = hostEntry.HostName;
                    }
                    catch
                    {
                        // Hostname lookup failed, that's okay
                    }
                }
            }
            catch
            {
                // Timeout or error, hop will have null IP
            }

            return hop;
        }

        /// <summary>
        /// Run deeper port scan on reachable hosts (respects mode)
        /// Automatically uses comprehensive port list for boundary devices to understand firewall rules
        /// </summary>
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

            // Identify boundary devices and regular hosts separately
            var boundaryIps = new HashSet<IPAddress>();
            var reachableIps = new HashSet<IPAddress>();
            
            // Calculate total work for progress tracking
            int totalBoundaryPorts = 0;
            int totalRegularPorts = 0;
            int totalTests = 0;
            int completedTests = 0;
            object lockObject = new object();

            if (context.Mode == AnalysisMode.RemoteNetworkKnown)
            {
                // Identify boundary devices: known gateway, gateway candidates, or common gateway patterns (.1, .254)
                if (context.BoundaryGatewayIp != null)
                {
                    boundaryIps.Add(context.BoundaryGatewayIp);
                }

                // Check ICMP results for boundary devices
                foreach (var icmp in icmpResults.Where(r => r.Reachable))
                {
                    var ip = icmp.TargetIp;
                    var ipBytes = ip.GetAddressBytes();
                    
                    // Check if it's a boundary device
                    if (icmp.Role == "Boundary device" || icmp.Role == "Gateway candidate")
                    {
                        boundaryIps.Add(ip);
                    }
                    // Check common gateway patterns (X.Y.Z.1 or X.Y.Z.254)
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

                // Check TCP results
                foreach (var tcp in tcpResults.Where(r => r.State != Models.TcpState.Filtered))
                {
                    if (!boundaryIps.Contains(tcp.TargetIp))
                    {
                        reachableIps.Add(tcp.TargetIp);
                    }
                }
            }
            else if (context.Mode == AnalysisMode.BoundaryOnly)
            {
                // Only scan boundary device
                if (context.BoundaryGatewayIp != null)
                {
                    boundaryIps.Add(context.BoundaryGatewayIp);
                }
            }

            // Calculate total work for progress tracking
            totalBoundaryPorts = boundaryIps.Count * COMPREHENSIVE_BOUNDARY_PORTS.Length;
            totalRegularPorts = reachableIps.Count * ports.Count;
            totalTests = totalBoundaryPorts + totalRegularPorts;

            // Scan boundary devices with comprehensive port list
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

            // Scan boundary devices with comprehensive port list first
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

                // Generate summary
                var openCount = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Open);
                var closedCount = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Closed);
                var filteredCount = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Filtered);

                scanResult.Summary = $"{openCount} open, {closedCount} closed, {filteredCount} filtered";

                results.Add(scanResult);
                progress?.Report(($"[Deeper Scan] Boundary device {ip}: {scanResult.Summary}", totalTests > 0 ? (completedTests * 100) / totalTests : 0));
            }

            // Scan regular hosts with user-specified ports
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

                // Generate summary
                var openCount = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Open);
                var closedCount = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Closed);
                var filteredCount = scanResult.PortStates.Count(kvp => kvp.Value == Models.TcpState.Filtered);

                scanResult.Summary = $"{openCount} open, {closedCount} closed, {filteredCount} filtered";

                results.Add(scanResult);
                progress?.Report(($"[Deeper Scan] {ip}: {scanResult.Summary}", totalTests > 0 ? (completedTests * 100) / totalTests : 0));
            }

            // Wait for all scans to complete
            progress?.Report(("Deeper scan completed.", 100));
            await Task.Delay(100, token); // Give tasks time to start
            while (semaphore.CurrentCount < DEFAULT_MAX_CONCURRENT_PROBES)
            {
                await Task.Delay(100, token);
            }

            return results;
        }

        /// <summary>
        /// Extract gateway candidates (X.Y.Z.1 and X.Y.Z.254) from CIDR notation
        /// </summary>
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

                // Calculate network address
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

                // Calculate .1 (first host)
                var firstHost = new byte[4];
                Array.Copy(networkStart, firstHost, 4);
                firstHost[3] += 1;
                if (IPAddress.TryParse(string.Join(".", firstHost), out IPAddress? firstHostIp))
                {
                    candidates.Add(firstHostIp);
                }

                // Calculate .254 (common gateway, or last host - 1 for /24)
                var lastHost = new byte[4];
                Array.Copy(networkStart, lastHost, 4);

                // Calculate broadcast address
                for (int i = 0; i < 4; i++)
                {
                    lastHost[i] = (byte)(networkStart[i] | ~maskBytes[i]);
                }

                // .254 is common for /24, but for other subnets, use last host - 1
                if (prefixLength == 24)
                {
                    lastHost[3] = 254;
                }
                else
                {
                    // Last host - 1
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
                // Return empty list on error
            }

            return candidates;
        }
    }
}

