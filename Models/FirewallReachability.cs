using System;
using System.Collections.Generic;
using System.Linq;

namespace Dorothy.Models
{
    /// <summary>
    /// Configuration for a firewall
    /// </summary>
    public class FirewallConfig
    {
        public string FirewallIp { get; set; } = string.Empty;
        public List<string> InterfaceIps { get; set; } = new List<string>();
    }

    /// <summary>
    /// Represents a target host to test
    /// </summary>
    public class TargetHost
    {
        public string IpAddress { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string? VlanId { get; set; }
        public string? Role { get; set; }
    }

    /// <summary>
    /// Reachability state of a host
    /// </summary>
    public enum ReachabilityState
    {
        Unknown,
        ReachableIcmp,
        ReachableTcpOnly,
        Unreachable,
        UnknownError
    }

    /// <summary>
    /// Result of reachability testing for a host
    /// </summary>
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

    /// <summary>
    /// Action type for a firewall rule
    /// </summary>
    public enum FirewallRuleAction
    {
        AllowedOpen,        // Connection success → port open and allowed
        ClosedNoFirewall,   // Connection refused → host reachable, port closed, no firewall drop
        FilteredTimeout,    // No response within timeout → probably silently filtered
        UnknownError        // Local or unexpected error
    }

    /// <summary>
    /// Alias for FirewallRuleAction to match MVP spec naming
    /// </summary>
    public enum FirewallAction
    {
        AllowedOpen = FirewallRuleAction.AllowedOpen,
        ClosedNoFirewall = FirewallRuleAction.ClosedNoFirewall,
        FilteredTimeout = FirewallRuleAction.FilteredTimeout,
        UnknownError = FirewallRuleAction.UnknownError
    }

    /// <summary>
    /// Result of a firewall rule test for a specific port
    /// </summary>
    public class FirewallRuleResult
    {
        public int Port { get; set; }
        public FirewallRuleAction Action { get; set; }
        public string? ServiceName { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Complete firewall analysis for a single host
    /// </summary>
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

    /// <summary>
    /// Progress information for firewall analysis
    /// </summary>
    public class FirewallAnalysisProgress
    {
        public int CurrentHost { get; set; }
        public int TotalHosts { get; set; }
        public string CurrentHostIp { get; set; } = string.Empty;
        public string CurrentStep { get; set; } = string.Empty;
    }
}





