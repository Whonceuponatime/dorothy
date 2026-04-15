using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services
{

    public class FirewallAnalysisService
    {
        private readonly ReachabilityService _reachabilityService;
        private readonly FirewallRuleDiscoveryService _ruleDiscoveryService;
        private readonly List<int> _defaultPortList;

        public FirewallAnalysisService()
        {
            _reachabilityService = new ReachabilityService();
            _ruleDiscoveryService = new FirewallRuleDiscoveryService();

            _defaultPortList = new List<int>();
            for (int i = 1; i <= 1024; i++)
            {
                _defaultPortList.Add(i);
            }

            _defaultPortList.AddRange(new[] { 3389, 8080, 8443, 5900, 1433, 3306, 5432 });
        }

        public async Task<List<HostFirewallAnalysis>> AnalyzeFirewallAsync(
            FirewallConfig firewallConfig,
            List<TargetHost> targetHosts,
            List<int>? customPortList = null,
            CancellationToken cancellationToken = default,
            IProgress<FirewallAnalysisProgress>? progress = null)
        {
            var results = new List<HostFirewallAnalysis>();
            var portList = customPortList ?? _defaultPortList;

            ReportProgress(progress, 0, targetHosts.Count, "Testing firewall interface...", "");

            bool firewallReachable = await _reachabilityService.TestFirewallInterfaceReachabilityAsync(
                firewallConfig.FirewallIp,
                cancellationToken);

            if (!firewallReachable)
            {
                ReportProgress(progress, 0, targetHosts.Count,
                    "Firewall interface unreachable. Skipping host tests.", "");

                foreach (var host in targetHosts)
                {
                    results.Add(new HostFirewallAnalysis
                    {
                        IpAddress = host.IpAddress,
                        Label = host.Label,
                        Reachability = ReachabilityState.Unreachable
                    });
                }
                return results;
            }

            for (int i = 0; i < targetHosts.Count; i++)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var host = targetHosts[i];
                ReportProgress(progress, i + 1, targetHosts.Count,
                    $"Testing reachability: {host.IpAddress}", host.IpAddress);

                var reachabilityResult = await _reachabilityService.TestReachabilityAsync(
                    host.IpAddress,
                    cancellationToken);

                var analysis = new HostFirewallAnalysis
                {
                    IpAddress = host.IpAddress,
                    Label = host.Label,
                    Reachability = reachabilityResult.State,
                    ReachabilityResult = reachabilityResult
                };

                if (reachabilityResult.State == ReachabilityState.ReachableIcmp ||
                    reachabilityResult.State == ReachabilityState.ReachableTcpOnly)
                {
                    ReportProgress(progress, i + 1, targetHosts.Count,
                        $"Discovering firewall rules: {host.IpAddress}", host.IpAddress);

                    analysis = await _ruleDiscoveryService.DiscoverRulesAsync(
                        host.IpAddress,
                        host.Label,
                        reachabilityResult.State,
                        portList,
                        cancellationToken);

                    analysis.ReachabilityResult = reachabilityResult;
                }

                results.Add(analysis);
            }

            ReportProgress(progress, targetHosts.Count, targetHosts.Count,
                "Analysis complete", "");

            return results;
        }

        public List<int> GetDefaultPortList()
        {
            return new List<int>(_defaultPortList);
        }

        public List<int> ParsePortList(string portString)
        {
            var ports = new List<int>();

            if (string.IsNullOrWhiteSpace(portString))
                return ports;

            var parts = portString.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();

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

        private void ReportProgress(
            IProgress<FirewallAnalysisProgress>? progress,
            int current,
            int total,
            string step,
            string currentIp)
        {
            progress?.Report(new FirewallAnalysisProgress
            {
                CurrentHost = current,
                TotalHosts = total,
                CurrentHostIp = currentIp,
                CurrentStep = step
            });
        }
    }
}

