using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Dorothy.Services.Reachability
{

    public sealed class TargetExpansionService
    {

        public static readonly string CommonPortsPreset =
            "22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080,8443";
        public static readonly string WebPortsPreset         = "80,443,8080,8443,8888,3000";
        public static readonly string RemoteAccessPreset     = "22,23,3389,5900,4899";
        public static readonly string DatabasePortsPreset    = "1433,1521,3306,5432,27017,6379,9200";

        private const long InfoThreshold    =   256;
        private const long ConfirmThreshold =  2_000;
        private const long LargeThreshold   = 50_000;

        public long EstimateHostCount(string input)
        {
            long total = 0;
            foreach (var token in SplitTokens(input))
            {
                if (token.Contains('/'))        total += EstimateCidrCount(token);
                else if (token.Contains('-'))   total += EstimateRangeCount(token);
                else                            total += 1;
            }
            return total;
        }

        public async Task<TargetExpansionResult> ExpandHostsAsync(
            string input, CancellationToken ct = default)
        {
            var seen       = new HashSet<uint>();
            var resolved   = new List<IPAddress>();
            var unresolved = new List<UnresolvedTarget>();

            foreach (var token in SplitTokens(input))
            {
                ct.ThrowIfCancellationRequested();

                if (token.Contains('/'))
                {
                    foreach (var ip in ExpandCidr(token))
                        if (seen.Add(IpToUint(ip))) resolved.Add(ip);
                }
                else if (token.Contains('-'))
                {
                    foreach (var ip in ExpandRange(token))
                        if (seen.Add(IpToUint(ip))) resolved.Add(ip);
                }
                else if (IPAddress.TryParse(token, out var single) &&
                         single.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (seen.Add(IpToUint(single))) resolved.Add(single);
                }
                else
                {

                    using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    dnsCts.CancelAfter(2000);
                    bool resolvedAny = false;
                    string failReason = "Hostname could not be resolved (DNS failure or offline)";

                    try
                    {
                        var addrs = await Dns.GetHostAddressesAsync(token, dnsCts.Token)
                            .ConfigureAwait(false);
                        foreach (var a in addrs.Where(
                            a => a.AddressFamily == AddressFamily.InterNetwork))
                        {
                            if (seen.Add(IpToUint(a))) resolved.Add(a);
                            resolvedAny = true;
                        }
                        if (!resolvedAny)
                            failReason = "Hostname resolved but returned no IPv4 addresses";
                    }
                    catch (OperationCanceledException)
                    {
                        failReason = "DNS lookup timed out (2 s) — check DNS availability";
                    }
                    catch (Exception ex)
                    {
                        failReason = $"DNS error: {ex.Message}";
                    }

                    if (!resolvedAny)
                        unresolved.Add(new UnresolvedTarget
                        {
                            Input  = token,
                            Reason = failReason
                        });
                }
            }

            return new TargetExpansionResult
            {
                ResolvedHosts = resolved,
                Unresolved    = unresolved
            };
        }

        public static IReadOnlyList<int> ParsePorts(string input)
        {
            var ports = new HashSet<int>();
            foreach (var token in input.Split(new[] { ',', ';', ' ' },
                StringSplitOptions.RemoveEmptyEntries))
            {
                var t = token.Trim();
                if (t.Contains('-'))
                {
                    var parts = t.Split('-');
                    if (parts.Length == 2 &&
                        int.TryParse(parts[0], out int from) &&
                        int.TryParse(parts[1], out int to))
                    {
                        for (int p = Math.Max(1, from); p <= Math.Min(65535, to); p++)
                            ports.Add(p);
                    }
                }
                else if (int.TryParse(t, out int port) && port >= 1 && port <= 65535)
                {
                    ports.Add(port);
                }
            }
            return ports.OrderBy(p => p).ToList();
        }

        public WorkloadEstimate EstimateWorkload(
            long hostCount, int portCount, ScanOptions options)
        {
            long totalProbes = hostCount * portCount;
            double avgProbeMs   = options.PerProbeTimeoutMs / 3.0;
            double batches      = totalProbes == 0 ? 0
                : Math.Ceiling((double)totalProbes / options.MaxConcurrency);
            var estimated = TimeSpan.FromMilliseconds(batches * avgProbeMs);

            string warning = string.Empty;
            if (totalProbes > LargeThreshold)
                warning = $"Very large scan: {hostCount:N0} hosts × {portCount} ports = " +
                          $"{totalProbes:N0} probes (~{estimated.TotalMinutes:F0} min estimated). " +
                          "Consider narrowing your target range or port list.";
            else if (totalProbes > ConfirmThreshold)
                warning = $"Large scan: {hostCount:N0} hosts × {portCount} ports = " +
                          $"{totalProbes:N0} probes (~{(estimated.TotalSeconds < 60 ? $"{estimated.TotalSeconds:F0}s" : $"{estimated.TotalMinutes:F1} min")}).";
            else if (totalProbes > InfoThreshold)
                warning = $"{hostCount:N0} hosts × {portCount} ports = " +
                          $"{totalProbes:N0} probes (~{estimated.TotalSeconds:F0}s).";

            return new WorkloadEstimate
            {
                HostCount            = hostCount,
                PortCount            = portCount,
                TotalProbes          = totalProbes,
                EstimatedDuration    = estimated,
                Warning              = warning,
                RequiresConfirmation = totalProbes > ConfirmThreshold,
                IsVeryLarge          = totalProbes > LargeThreshold
            };
        }

        public static RouteType DetermineRoute(IPAddress sourceIp, IPAddress target)
        {
            if (sourceIp == null ||
                sourceIp.Equals(IPAddress.None) ||
                sourceIp.Equals(IPAddress.Any))
                return RouteType.Unknown;

            try
            {
                var unicast = NetworkInterface
                    .GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                    .FirstOrDefault(u =>
                        u.Address.Equals(sourceIp) &&
                        u.Address.AddressFamily == AddressFamily.InterNetwork);

                if (unicast?.IPv4Mask == null || unicast.IPv4Mask.Equals(IPAddress.None))
                    return RouteType.Unknown;

                return IsOnSameSubnet(sourceIp, target, unicast.IPv4Mask)
                    ? RouteType.OnLink
                    : RouteType.ViaGateway;
            }
            catch { return RouteType.Unknown; }
        }

        private static bool IsOnSameSubnet(IPAddress a, IPAddress b, IPAddress mask)
        {
            var ba = a.GetAddressBytes();
            var bb = b.GetAddressBytes();
            var bm = mask.GetAddressBytes();
            for (int i = 0; i < 4; i++)
                if ((ba[i] & bm[i]) != (bb[i] & bm[i])) return false;
            return true;
        }

        public static IReadOnlyList<(IPAddress Address, string DisplayLabel)>
            GetLocalIpAddresses()
        {
            var result = new List<(IPAddress, string)>();
            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                {
                    foreach (var ua in nic.GetIPProperties().UnicastAddresses
                        .Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork))
                    {
                        result.Add((ua.Address, $"{nic.Name}  ({ua.Address})"));
                    }
                }
            }
            catch {  }
            return result;
        }

        private static IEnumerable<string> SplitTokens(string input) =>
            input.Split(new[] { '\n', '\r', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
                 .Select(s => s.Trim())
                 .Where(s => s.Length > 0 && !s.StartsWith('#'));

        private static IEnumerable<IPAddress> ExpandCidr(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2) yield break;
            if (!IPAddress.TryParse(parts[0], out var baseIp)) yield break;
            if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32) yield break;

            uint mask    = prefix == 0 ? 0 : ~((1u << (32 - prefix)) - 1);
            uint network = IpToUint(baseIp) & mask;
            uint bcast   = network | ~mask;

            for (uint addr = network + 1; addr < bcast; addr++)
                yield return UintToIp(addr);
        }

        private static IEnumerable<IPAddress> ExpandRange(string range)
        {
            var parts = range.Split('-');
            if (parts.Length != 2) yield break;
            if (!IPAddress.TryParse(parts[0].Trim(), out var start)) yield break;

            if (IPAddress.TryParse(parts[1].Trim(), out var end))
            {
                uint s = IpToUint(start), e = IpToUint(end);
                for (uint a = s; a <= e; a++) yield return UintToIp(a);
                yield break;
            }
            if (int.TryParse(parts[1].Trim(), out int lastOctet) &&
                lastOctet >= 0 && lastOctet <= 255)
            {
                var sb = start.GetAddressBytes();
                var eb = new byte[] { sb[0], sb[1], sb[2], (byte)lastOctet };
                if (!IPAddress.TryParse(string.Join(".", eb.Select(b => b.ToString())), out var endIp))
                    yield break;
                uint s = IpToUint(start), e = IpToUint(endIp);
                for (uint a = s; a <= e; a++) yield return UintToIp(a);
            }
        }

        private static long EstimateCidrCount(string cidr)
        {
            var parts = cidr.Split('/');
            if (parts.Length != 2 || !int.TryParse(parts[1], out int prefix) ||
                prefix < 0 || prefix > 32) return 1;
            int hostBits = 32 - prefix;
            if (hostBits <= 1) return 1;
            return (1L << hostBits) - 2;
        }

        private static long EstimateRangeCount(string range)
        {
            var parts = range.Split('-');
            if (parts.Length != 2) return 1;
            if (IPAddress.TryParse(parts[0].Trim(), out var start) &&
                IPAddress.TryParse(parts[1].Trim(), out var end))
                return (long)IpToUint(end) - IpToUint(start) + 1;
            if (IPAddress.TryParse(parts[0].Trim(), out var s2) &&
                int.TryParse(parts[1].Trim(), out int lastOctet))
                return lastOctet - s2.GetAddressBytes()[3] + 1;
            return 1;
        }

        private static uint IpToUint(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static IPAddress UintToIp(uint u) =>
            new(new[] { (byte)(u >> 24), (byte)(u >> 16), (byte)(u >> 8), (byte)u });
    }
}
