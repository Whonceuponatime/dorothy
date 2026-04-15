using System;
using System.Collections.Generic;
using System.Linq;

namespace Dorothy.Models
{

    public class FirewallConfig
    {
        public string FirewallIp { get; set; } = string.Empty;
        public List<string> InterfaceIps { get; set; } = new List<string>();
    }

    public class TargetHost
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string? VlanId { get; set; }
        public string? Role { get; set; }
    }

    public enum ReachabilityState
    {
        Unknown,
        ReachableIcmp,
        ReachableTcpOnly,
        Unreachable,
        UnknownError
    }

    public class HostReachabilityResult
    {
        public string IpAddress { get; set; } = string.Empty;
        public ReachabilityState State { get; set; }
        public bool PingSuccess { get; set; }
        public int PingCount { get; set; }
        public int PingSuccessCount { get; set; }
        public List<int> ReachableTcpPorts { get; set; } = new List<int>();
        public string? ErrorMessage { get; set; }
    }

    public enum FirewallRuleAction
    {
        AllowedOpen,
        ClosedNoFirewall,
        FilteredTimeout,
        UnknownError
    }

    public enum FirewallAction
    {
        AllowedOpen = FirewallRuleAction.AllowedOpen,
        ClosedNoFirewall = FirewallRuleAction.ClosedNoFirewall,
        FilteredTimeout = FirewallRuleAction.FilteredTimeout,
        UnknownError = FirewallRuleAction.UnknownError
    }

    public class FirewallRuleResult
    {
        public int Port { get; set; }
        public FirewallRuleAction Action { get; set; }
        public string? ServiceName { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public string? ErrorMessage { get; set; }
    }

    public class HostFirewallAnalysis
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public ReachabilityState Reachability { get; set; }
        public HostReachabilityResult? ReachabilityResult { get; set; }
        public List<FirewallRuleResult> RuleResults { get; set; } = new List<FirewallRuleResult>();

        public List<FirewallRuleResult> AllowedOpenPorts =>
            RuleResults.Where(r => r.Action == FirewallRuleAction.AllowedOpen).ToList();

        public List<FirewallRuleResult> ClosedPorts =>
            RuleResults.Where(r => r.Action == FirewallRuleAction.ClosedNoFirewall).ToList();

        public List<FirewallRuleResult> FilteredPorts =>
            RuleResults.Where(r => r.Action == FirewallRuleAction.FilteredTimeout).ToList();

        public string OpenPortsSummary =>
            AllowedOpenPorts.Count > 0
                ? string.Join(", ", AllowedOpenPorts.Select(p => p.Port.ToString()))
                : "None";
    }

    public class FirewallAnalysisProgress
    {
        public int CurrentHost { get; set; }
        public int TotalHosts { get; set; }
        public string CurrentHostIp { get; set; } = string.Empty;
        public string CurrentStep { get; set; } = string.Empty;
    }
}

