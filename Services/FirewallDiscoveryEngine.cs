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
    /// Engine for firewall reachability testing and rule discovery
    /// UI-agnostic, testable core with no WPF dependencies
    /// </summary>
    public class FirewallDiscoveryEngine
    {
        // Explicit classification thresholds
        private const int DEFAULT_ICMP_TIMEOUT_MS = 1000;
        private const int DEFAULT_TCP_CONNECT_TIMEOUT_MS = 1500;
        private const int DEFAULT_ICMP_PROBE_COUNT = 3;
        private const int DEFAULT_MAX_CONCURRENT_PROBES = 32;

        /// <summary>
        /// Discover hosts behind firewall by scanning IP ranges
        /// </summary>
        public async Task<List<FirewallHostDefinition>> DiscoverHostsInRangeAsync(
            FirewallDiscoveryOptions options,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var discoveredHosts = new List<FirewallHostDefinition>();
            List<string> ipRange = new List<string>();

            // Parse IP range or CIDR
            if (!string.IsNullOrEmpty(options.CidrRange))
            {
                ipRange = ParseCidrRange(options.CidrRange);
                progress?.Report($"[Discovery] Scanning CIDR range: {options.CidrRange} ({ipRange.Count} IPs)");
            }
            else if (!string.IsNullOrEmpty(options.IpRangeStart) && !string.IsNullOrEmpty(options.IpRangeEnd))
            {
                ipRange = ParseIpRange(options.IpRangeStart, options.IpRangeEnd);
                progress?.Report($"[Discovery] Scanning IP range: {options.IpRangeStart} - {options.IpRangeEnd} ({ipRange.Count} IPs)");
            }
            else
            {
                progress?.Report("[Discovery] No IP range specified for discovery");
                return discoveredHosts;
            }

            if (ipRange.Count == 0)
            {
                progress?.Report("[Discovery] Invalid IP range");
                return discoveredHosts;
            }

            // Scan IPs with concurrency control
            var semaphore = new SemaphoreSlim(options.MaxConcurrentHostScans, options.MaxConcurrentHostScans);
            var tasks = new List<Task<FirewallHostDefinition?>>();

            int scanned = 0;
            int total = ipRange.Count;

            foreach (var ipStr in ipRange)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var task = ScanIpForReachabilityAsync(
                    ipStr,
                    options,
                    semaphore,
                    progress,
                    cancellationToken);

                tasks.Add(task);

                // Process in batches to avoid too many tasks
                if (tasks.Count >= options.MaxConcurrentHostScans)
                {
                    var batchResults = await Task.WhenAll(tasks);
                    foreach (var host in batchResults.Where(h => h != null))
                    {
                        discoveredHosts.Add(host!);
                    }
                    tasks.Clear();
                    scanned += options.MaxConcurrentHostScans;
                    progress?.Report($"[Discovery] Scanned {scanned}/{total} IPs, found {discoveredHosts.Count} reachable hosts");
                }
            }

            // Process remaining tasks
            if (tasks.Count > 0)
            {
                var batchResults = await Task.WhenAll(tasks);
                foreach (var host in batchResults.Where(h => h != null))
                {
                    discoveredHosts.Add(host!);
                }
            }

            progress?.Report($"[Discovery] Range scan complete. Found {discoveredHosts.Count} reachable hosts out of {ipRange.Count} scanned");
            return discoveredHosts;
        }

        /// <summary>
        /// Scan a single IP for reachability
        /// </summary>
        private async Task<FirewallHostDefinition?> ScanIpForReachabilityAsync(
            string ipAddress,
            FirewallDiscoveryOptions options,
            SemaphoreSlim semaphore,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            await semaphore.WaitAsync(cancellationToken);

            try
            {
                // Quick ICMP test
                bool icmpReachable = await TestIcmpAsync(
                    ipAddress,
                    options.IcmpTimeoutMs,
                    1, // Single ping for discovery
                    cancellationToken);

                if (icmpReachable)
                {
                    if (IPAddress.TryParse(ipAddress, out IPAddress? ip))
                    {
                        progress?.Report($"[Discovery] Found reachable host: {ipAddress}");
                        return new FirewallHostDefinition { HostIp = ip, Label = null };
                    }
                    return null;
                }

                // If ICMP fails, try TCP reachability
                var tcpPorts = await TestTcpReachabilityAsync(
                    ipAddress,
                    options.DefaultReachabilityPorts,
                    options.ConnectTimeoutMs,
                    cancellationToken);

                if (tcpPorts.Count > 0)
                {
                    if (IPAddress.TryParse(ipAddress, out IPAddress? ip))
                    {
                        progress?.Report($"[Discovery] Found reachable host (TCP-only): {ipAddress}");
                        return new FirewallHostDefinition { HostIp = ip, Label = null };
                    }
                }

                return null;
            }
            catch
            {
                return null;
            }
            finally
            {
                semaphore.Release();
            }
        }

        /// <summary>
        /// Parse CIDR notation to IP range
        /// </summary>
        private List<string> ParseCidrRange(string cidr)
        {
            var ips = new List<string>();

            try
            {
                var parts = cidr.Split('/');
                if (parts.Length != 2)
                    return ips;

                if (!IPAddress.TryParse(parts[0], out IPAddress? networkIp))
                    return ips;

                if (!int.TryParse(parts[1], out int prefixLength) || prefixLength < 0 || prefixLength > 32)
                    return ips;

                var networkBytes = networkIp.GetAddressBytes();
                var maskBytes = new byte[4];
                int hostBits = 32 - prefixLength;

                // Calculate subnet mask
                for (int i = 0; i < 4; i++)
                {
                    int bitsInByte = Math.Min(8, prefixLength - (i * 8));
                    if (bitsInByte > 0)
                    {
                        maskBytes[i] = (byte)(0xFF << (8 - bitsInByte));
                    }
                    prefixLength -= bitsInByte;
                }

                // Calculate network address
                var networkStart = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkStart[i] = (byte)(networkBytes[i] & maskBytes[i]);
                }

                // Calculate number of hosts
                long hostCount = (long)Math.Pow(2, hostBits) - 2; // Exclude network and broadcast

                // Generate IP range (skip network and broadcast)
                for (long i = 1; i <= hostCount; i++)
                {
                    var hostIp = new byte[4];
                    Array.Copy(networkStart, hostIp, 4);

                    long remaining = i;
                    for (int j = 3; j >= 0 && remaining > 0; j--)
                    {
                        hostIp[j] += (byte)(remaining % 256);
                        remaining /= 256;
                    }

                    ips.Add(string.Join(".", hostIp));
                }
            }
            catch
            {
                // Return empty list on error
            }

            return ips;
        }

        /// <summary>
        /// Parse IP range (start - end)
        /// </summary>
        private List<string> ParseIpRange(string startIp, string endIp)
        {
            var ips = new List<string>();

            try
            {
                if (!IPAddress.TryParse(startIp, out IPAddress? startIpObj) || 
                    !IPAddress.TryParse(endIp, out IPAddress? endIpObj))
                    return ips;

                var startBytes = startIpObj.GetAddressBytes();
                var endBytes = endIpObj.GetAddressBytes();

                // Validate start <= end
                if (CompareIpBytes(startBytes, endBytes) > 0)
                    return ips;

                // Generate IP range
                var currentBytes = new byte[4];
                Array.Copy(startBytes, currentBytes, 4);

                while (CompareIpBytes(currentBytes, endBytes) <= 0)
                {
                    ips.Add(string.Join(".", currentBytes));

                    // Increment IP
                    bool carry = true;
                    for (int i = 3; i >= 0 && carry; i--)
                    {
                        if (currentBytes[i] == 255)
                        {
                            currentBytes[i] = 0;
                        }
                        else
                        {
                            currentBytes[i]++;
                            carry = false;
                        }
                    }

                    // Check if we've exceeded end IP
                    if (CompareIpBytes(currentBytes, endBytes) > 0) break;
                }
            }
            catch
            {
                // Return empty list on error
            }

            return ips;
        }

        /// <summary>
        /// Compare two IP addresses as byte arrays
        /// </summary>
        private int CompareIpBytes(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < 4; i++)
            {
                if (ip1[i] < ip2[i]) return -1;
                if (ip1[i] > ip2[i]) return 1;
            }
            return 0;
        }

        /// <summary>
        /// Test reachability to all hosts defined in options
        /// </summary>
        public async Task<List<FirewallDiscoveryHostReachabilityResult>> TestReachabilityAsync(
            FirewallDiscoveryOptions options,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var results = new List<FirewallDiscoveryHostReachabilityResult>();

            foreach (var network in options.Networks)
            {
                foreach (var host in network.Hosts)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    var result = await TestHostReachabilityAsync(
                        network,
                        host,
                        options,
                        progress,
                        cancellationToken);

                    results.Add(result);
                }
            }

            return results;
        }

        /// <summary>
        /// Test reachability for a single host
        /// </summary>
        private async Task<FirewallDiscoveryHostReachabilityResult> TestHostReachabilityAsync(
            FirewallNetworkDefinition network,
            FirewallHostDefinition host,
            FirewallDiscoveryOptions options,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var result = new FirewallDiscoveryHostReachabilityResult
            {
                Network = network,
                Host = host,
                State = ReachabilityState.UnknownError
            };

            try
            {
                // Try ICMP ping
                result.IcmpTried = true;
                bool icmpSuccess = await TestIcmpAsync(
                    host.HostIp.ToString(),
                    options.IcmpTimeoutMs,
                    options.IcmpProbeCount,
                    cancellationToken);

                result.IcmpSucceeded = icmpSuccess;

                if (icmpSuccess)
                {
                    result.State = ReachabilityState.ReachableIcmp;
                    progress?.Report($"[Reachability] {host.HostIp} → ReachableIcmp");
                    return result;
                }

                // If ICMP failed, try TCP reachability
                var tcpPorts = await TestTcpReachabilityAsync(
                    host.HostIp.ToString(),
                    options.DefaultReachabilityPorts,
                    options.ConnectTimeoutMs,
                    cancellationToken);

                result.TcpTestedPorts = options.DefaultReachabilityPorts.ToList();
                result.TcpRespondedPorts = tcpPorts;

                if (tcpPorts.Count > 0)
                {
                    result.State = ReachabilityState.ReachableTcpOnly;
                    progress?.Report($"[Reachability] {host.HostIp} → ReachableTcpOnly (ports: {string.Join(",", tcpPorts)})");
                }
                else
                {
                    result.State = ReachabilityState.Unreachable;
                    progress?.Report($"[Reachability] {host.HostIp} → Unreachable");
                }
            }
            catch (Exception ex)
            {
                result.State = ReachabilityState.UnknownError;
                result.ErrorMessage = ex.Message;
                progress?.Report($"[Reachability] {host.HostIp} → UnknownError: {ex.Message}");
            }

            return result;
        }

        /// <summary>
        /// Test ICMP ping to a host
        /// </summary>
        private async Task<bool> TestIcmpAsync(
            string ipAddress,
            int timeoutMs,
            int probeCount,
            CancellationToken cancellationToken)
        {
            try
            {
                using var ping = new Ping();
                int successCount = 0;

                for (int i = 0; i < probeCount; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    try
                    {
                        var reply = await ping.SendPingAsync(ipAddress, timeoutMs);
                        if (reply != null && reply.Status == IPStatus.Success)
                        {
                            successCount++;
                        }
                    }
                    catch
                    {
                        // Ping failed, continue to next attempt
                    }

                    // Small delay between pings
                    if (i < probeCount - 1)
                    {
                        await Task.Delay(200, cancellationToken);
                    }
                }

                return successCount > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test TCP reachability by attempting connections to specified ports
        /// </summary>
        private async Task<List<int>> TestTcpReachabilityAsync(
            string ipAddress,
            List<int> ports,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            var reachablePorts = new List<int>();

            foreach (var port in ports)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    var timeoutTask = Task.Delay(timeoutMs, cancellationToken);

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                    if (completedTask == connectTask)
                    {
                        if (client.Connected)
                        {
                            reachablePorts.Add(port);
                            client.Close();
                        }
                        else
                        {
                            // Connection attempt completed - check for connection refused
                            // This indicates host is reachable
                            reachablePorts.Add(port);
                        }
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    // Connection refused means host is reachable, port is just closed
                    reachablePorts.Add(port);
                }
                catch
                {
                    // Timeout or other error - port is likely filtered or host unreachable
                }
            }

            return reachablePorts;
        }

        /// <summary>
        /// Probe ports for reachable hosts
        /// </summary>
        public async Task<List<PortProbeResult>> ProbePortsAsync(
            FirewallDiscoveryOptions options,
            IEnumerable<FirewallDiscoveryHostReachabilityResult> reachability,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var results = new List<PortProbeResult>();
            var reachableHosts = reachability.Where(r =>
                r.State == ReachabilityState.ReachableIcmp ||
                r.State == ReachabilityState.ReachableTcpOnly).ToList();

            if (reachableHosts.Count == 0)
            {
                progress?.Report("[Probe] No reachable hosts to probe");
                return results;
            }

            var semaphore = new SemaphoreSlim(options.MaxConcurrentProbes, options.MaxConcurrentProbes);
            var tasks = new List<Task<List<PortProbeResult>>>();

            foreach (var hostResult in reachableHosts)
            {
                var task = ProbeHostPortsAsync(
                    hostResult.Network,
                    hostResult.Host,
                    options.PortsToScan,
                    options.ConnectTimeoutMs,
                    semaphore,
                    progress,
                    cancellationToken);

                tasks.Add(task);
            }

            var allResults = await Task.WhenAll(tasks);
            results.AddRange(allResults.SelectMany(r => r));

            return results;
        }

        /// <summary>
        /// Probe all ports for a single host
        /// </summary>
        private async Task<List<PortProbeResult>> ProbeHostPortsAsync(
            FirewallNetworkDefinition? network,
            FirewallHostDefinition host,
            List<int> ports,
            int timeoutMs,
            SemaphoreSlim semaphore,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var results = new List<PortProbeResult>();
            var tasks = new List<Task<PortProbeResult?>>();

            foreach (var port in ports)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var task = ProbeSinglePortAsync(
                    network,
                    host,
                    port,
                    timeoutMs,
                    semaphore,
                    progress,
                    cancellationToken);

                tasks.Add(task);
            }

            var portResults = await Task.WhenAll(tasks);
            results.AddRange(portResults.Where(r => r != null).Select(r => r!));

            return results;
        }

        /// <summary>
        /// Probe a single port with concurrency control
        /// </summary>
        private async Task<PortProbeResult?> ProbeSinglePortAsync(
            FirewallNetworkDefinition? network,
            FirewallHostDefinition host,
            int port,
            int timeoutMs,
            SemaphoreSlim semaphore,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            await semaphore.WaitAsync(cancellationToken);

            try
            {
                var result = new PortProbeResult
                {
                    Network = network,
                    Host = host,
                    Port = port
                };

                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(host.HostIp.ToString(), port);
                    var timeoutTask = Task.Delay(timeoutMs, cancellationToken);

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                    stopwatch.Stop();
                    result.RoundTripTimeMs = stopwatch.ElapsedMilliseconds;

                    if (cancellationToken.IsCancellationRequested)
                        return null;

                    if (completedTask == timeoutTask)
                    {
                        // Timeout - likely filtered
                        result.Action = FirewallRuleAction.FilteredTimeout;
                        result.Evidence = "Timeout / no response";
                        progress?.Report($"[Probe] {network?.Name ?? "Unknown"} {host.HostIp}:{port} → FilteredTimeout");
                    }
                    else if (client.Connected)
                    {
                        // Connection succeeded
                        result.Action = FirewallRuleAction.AllowedOpen;
                        result.Evidence = "Connect OK (SYN-ACK)";
                        progress?.Report($"[Probe] {network?.Name ?? "Unknown"} {host.HostIp}:{port} → AllowedOpen (Connect OK)");
                    }
                    else
                    {
                        // Connection attempt completed but not connected
                        result.Action = FirewallRuleAction.FilteredTimeout;
                        result.Evidence = "Timeout / no response";
                        progress?.Report($"[Probe] {network?.Name ?? "Unknown"} {host.HostIp}:{port} → FilteredTimeout");
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    stopwatch.Stop();
                    result.RoundTripTimeMs = stopwatch.ElapsedMilliseconds;
                    result.Action = FirewallRuleAction.ClosedNoFirewall;
                    result.Evidence = "Connection refused (RST)";
                    progress?.Report($"[Probe] {network?.Name ?? "Unknown"} {host.HostIp}:{port} → ClosedNoFirewall (Connection refused)");
                }
                catch (OperationCanceledException)
                {
                    return null;
                }
                catch (Exception ex)
                {
                    stopwatch.Stop();
                    result.RoundTripTimeMs = stopwatch.ElapsedMilliseconds;
                    result.Action = FirewallRuleAction.UnknownError;
                    result.Evidence = "Error";
                    result.ErrorMessage = ex.Message;
                    progress?.Report($"[Probe] {network?.Name ?? "Unknown"} {host.HostIp}:{port} → UnknownError: {ex.Message}");
                }

                return result;
            }
            finally
            {
                semaphore.Release();
            }
        }

        /// <summary>
        /// Build inferred rules from port probe results
        /// </summary>
        public List<InferredFirewallRule> BuildInferredRules(List<PortProbeResult> portProbes)
        {
            var rules = new List<InferredFirewallRule>();

            // Filter out UnknownError results
            var validProbes = portProbes.Where(p => p.Action != FirewallRuleAction.UnknownError).ToList();

            // Group by Network, Host, Protocol, and Action
            var groups = validProbes
                .GroupBy(p => new
                {
                    Network = p.Network,
                    Host = p.Host,
                    Protocol = "TCP", // Always TCP for MVP
                    Action = p.Action
                })
                .ToList();

            foreach (var group in groups)
            {
                var ports = group.Select(p => p.Port).Distinct().OrderBy(p => p).ToList();

                if (ports.Count == 0)
                    continue;

                var portExpression = CompressPortRanges(ports);

                var rule = new InferredFirewallRule
                {
                    Network = group.Key.Network,
                    Host = group.Key.Host,
                    Protocol = group.Key.Protocol,
                    Action = group.Key.Action,
                    PortExpression = portExpression,
                    SampleCount = ports.Count
                };

                rules.Add(rule);
            }

            // Sort by Network name, Host IP, Protocol, Action
            return rules
                .OrderBy(r => r.Network?.Name ?? "")
                .ThenBy(r => r.Host.HostIp.ToString())
                .ThenBy(r => r.Protocol)
                .ThenBy(r => r.Action)
                .ToList();
        }

        /// <summary>
        /// Compress consecutive ports into ranges (e.g., [22,23,24,80,443] → "22-24,80,443")
        /// </summary>
        private string CompressPortRanges(List<int> ports)
        {
            if (ports.Count == 0)
                return string.Empty;

            if (ports.Count == 1)
                return ports[0].ToString();

            var ranges = new List<string>();
            int start = ports[0];
            int end = ports[0];

            for (int i = 1; i < ports.Count; i++)
            {
                if (ports[i] == end + 1)
                {
                    // Consecutive port, extend range
                    end = ports[i];
                }
                else
                {
                    // Gap found, add current range
                    if (start == end)
                        ranges.Add(start.ToString());
                    else
                        ranges.Add($"{start}-{end}");

                    start = ports[i];
                    end = ports[i];
                }
            }

            // Add final range
            if (start == end)
                ranges.Add(start.ToString());
            else
                ranges.Add($"{start}-{end}");

            return string.Join(",", ranges);
        }

        /// <summary>
        /// Orchestrate the complete discovery process
        /// </summary>
        public async Task<FirewallDiscoveryResult> DiscoverAsync(
            FirewallDiscoveryOptions options,
            IProgress<string>? progress,
            CancellationToken cancellationToken)
        {
            var result = new FirewallDiscoveryResult();

            // Stage 0: Discover hosts behind firewall via IP range scanning (if enabled)
            if (options.EnableRangeScanning)
            {
                progress?.Report("[Discovery] Starting host discovery via IP range scanning...");
                
                var discoveredHosts = await DiscoverHostsInRangeAsync(
                    options,
                    progress,
                    cancellationToken);

                if (cancellationToken.IsCancellationRequested)
                {
                    progress?.Report("[Discovery] Canceled during host discovery");
                    return result;
                }

                // Add discovered hosts to a network definition
                if (discoveredHosts.Count > 0)
                {
                    var discoveryNetwork = new FirewallNetworkDefinition
                    {
                        Name = "Discovered Hosts",
                        Cidr = options.CidrRange ?? $"{options.IpRangeStart}-{options.IpRangeEnd}",
                        Hosts = discoveredHosts
                    };

                    options.Networks.Add(discoveryNetwork);
                    progress?.Report($"[Discovery] Discovered {discoveredHosts.Count} reachable hosts behind firewall");
                }
                else
                {
                    progress?.Report("[Discovery] No reachable hosts discovered in the specified range");
                }
            }

            progress?.Report("[Discovery] Starting reachability tests...");

            // Stage 1: Reachability tests (on both discovered and manually entered hosts)
            result.ReachabilityResults = await TestReachabilityAsync(
                options,
                progress,
                cancellationToken);

            if (cancellationToken.IsCancellationRequested)
            {
                progress?.Report("[Discovery] Canceled during reachability tests");
                return result;
            }

            progress?.Report($"[Discovery] Reachability tests complete. {result.ReachabilityResults.Count} hosts tested.");

            // Stage 2: Port probing for reachable hosts
            progress?.Report("[Discovery] Starting port probes...");
            result.RawPortProbes = await ProbePortsAsync(
                options,
                result.ReachabilityResults,
                progress,
                cancellationToken);

            if (cancellationToken.IsCancellationRequested)
            {
                progress?.Report("[Discovery] Canceled during port probes");
                return result;
            }

            progress?.Report($"[Discovery] Port probes complete. {result.RawPortProbes.Count} probes performed.");

            // Stage 3: Rule inference
            progress?.Report("[Discovery] Building inferred rules...");
            result.InferredRules = BuildInferredRules(result.RawPortProbes);

            progress?.Report($"[Discovery] Complete. {result.InferredRules.Count} inferred rules generated.");

            return result;
        }

        /// <summary>
        /// Parse port list from string (e.g., "22,80,443" or "1-1024" or "22,80-85,443")
        /// </summary>
        public static List<int> ParsePortList(string portString)
        {
            var ports = new List<int>();

            if (string.IsNullOrWhiteSpace(portString))
                return ports;

            var parts = portString.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();

                // Check for range (e.g., "1-1024")
                if (trimmed.Contains('-'))
                {
                    var rangeParts = trimmed.Split('-');
                    if (rangeParts.Length == 2 &&
                        int.TryParse(rangeParts[0].Trim(), out int start) &&
                        int.TryParse(rangeParts[1].Trim(), out int end))
                    {
                        for (int i = start; i <= end; i++)
                        {
                            if (i > 0 && i <= 65535)
                                ports.Add(i);
                        }
                    }
                }
                else if (int.TryParse(trimmed, out int port))
                {
                    if (port > 0 && port <= 65535)
                        ports.Add(port);
                }
            }

            return ports.Distinct().OrderBy(p => p).ToList();
        }
    }
}

