using System;
using System.Collections.Generic;
using System.Net;

namespace Dorothy.Models
{
    /// <summary>
    /// Represents a network/VLAN behind the firewall
    /// </summary>
    public class FirewallNetworkDefinition
    {
        public string Name { get; set; } = string.Empty;
        public int? VlanId { get; set; }
        public string Cidr { get; set; } = string.Empty;
        public IPAddress? FirewallInterfaceIp { get; set; }
        public List<FirewallHostDefinition> Hosts { get; set; } = new List<FirewallHostDefinition>();
    }

    /// <summary>
    /// Represents a single host we want to test
    /// </summary>
    public class FirewallHostDefinition
    {
        public IPAddress HostIp { get; set; } = null!;
        public string? Label { get; set; }

        /// <summary>
        /// Host IP as string for display
        /// </summary>
        public string HostIpString => HostIp?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Represents reachability outcome for one host (Firewall Discovery MVP)
    /// </summary>
    public class FirewallDiscoveryHostReachabilityResult
    {
        public FirewallNetworkDefinition? Network { get; set; }
        public FirewallHostDefinition Host { get; set; } = null!;
        public ReachabilityState State { get; set; }
        public bool IcmpTried { get; set; }
        public bool IcmpSucceeded { get; set; }
        public List<int> TcpTestedPorts { get; set; } = new List<int>();
        public List<int> TcpRespondedPorts { get; set; } = new List<int>();
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Stable key for DataGrid binding (Network name + Host IP)
        /// </summary>
        public string Key => $"{Network?.Name ?? "Unknown"}:{Host.HostIp}";

        /// <summary>
        /// Summary of open ports for display
        /// </summary>
        public string OpenPortsSummary => TcpRespondedPorts.Count > 0 
            ? string.Join(", ", TcpRespondedPorts) 
            : "None";
    }

    /// <summary>
    /// Represents the result of a single (host, port) probe
    /// </summary>
    public class PortProbeResult
    {
        public FirewallNetworkDefinition? Network { get; set; }
        public FirewallHostDefinition Host { get; set; } = null!;
        public int Port { get; set; }
        public FirewallRuleAction Action { get; set; }
        public long RoundTripTimeMs { get; set; }
        public string Evidence { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Compact rule inferred from multiple PortProbeResult entries
    /// </summary>
    public class InferredFirewallRule
    {
        public FirewallNetworkDefinition? Network { get; set; }
        public FirewallHostDefinition Host { get; set; } = null!;
        public string Protocol { get; set; } = "TCP";
        public FirewallRuleAction Action { get; set; }
        public string PortExpression { get; set; } = string.Empty;
        public int SampleCount { get; set; }
    }

    /// <summary>
    /// Configuration for the discovery engine
    /// </summary>
    public class FirewallDiscoveryOptions
    {
        public IPAddress? KnownFirewallIp { get; set; }
        public IPAddress? SampleSubnetIp { get; set; }
        public List<FirewallNetworkDefinition> Networks { get; set; } = new List<FirewallNetworkDefinition>();
        
        // IP Range Scanning (for discovering hosts behind firewall)
        public string? IpRangeStart { get; set; }  // e.g., "192.168.1.1"
        public string? IpRangeEnd { get; set; }    // e.g., "192.168.1.254"
        public string? CidrRange { get; set; }      // e.g., "192.168.1.0/24"
        public bool EnableRangeScanning { get; set; } = false;
        
        public List<int> PortsToScan { get; set; } = new List<int>();
        public List<int> DefaultReachabilityPorts { get; set; } = new List<int>();
        public int MaxConcurrentProbes { get; set; } = 32;
        public int MaxConcurrentHostScans { get; set; } = 64;  // For range scanning
        public int ConnectTimeoutMs { get; set; } = 1500;
        public int IcmpTimeoutMs { get; set; } = 1000;
        public int IcmpProbeCount { get; set; } = 3;
    }

    /// <summary>
    /// Final result container
    /// </summary>
    public class FirewallDiscoveryResult
    {
        public List<FirewallDiscoveryHostReachabilityResult> ReachabilityResults { get; set; } = new List<FirewallDiscoveryHostReachabilityResult>();
        public List<PortProbeResult> RawPortProbes { get; set; } = new List<PortProbeResult>();
        public List<InferredFirewallRule> InferredRules { get; set; } = new List<InferredFirewallRule>();
    }
}

