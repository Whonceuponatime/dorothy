using System;
using System.Collections.Generic;
using System.Net;

namespace Dorothy.Models
{

    public class FirewallNetworkDefinition
    {
        public string Name { get; set; } = string.Empty;
        public int? VlanId { get; set; }
        public string Cidr { get; set; } = string.Empty;
        public IPAddress? FirewallInterfaceIp { get; set; }
        public List<FirewallHostDefinition> Hosts { get; set; } = new List<FirewallHostDefinition>();
    }

    public class FirewallHostDefinition
    {
        public IPAddress HostIp { get; set; } = null!;
        public string? Label { get; set; }

        public string HostIpString => HostIp?.ToString() ?? string.Empty;
    }

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

        public string Key => $"{Network?.Name ?? "Unknown"}:{Host.HostIp}";

        public string OpenPortsSummary => TcpRespondedPorts.Count > 0
            ? string.Join(", ", TcpRespondedPorts)
            : "None";
    }

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

    public class InferredFirewallRule
    {
        public FirewallNetworkDefinition? Network { get; set; }
        public FirewallHostDefinition Host { get; set; } = null!;
        public string Protocol { get; set; } = "TCP";
        public FirewallRuleAction Action { get; set; }
        public string PortExpression { get; set; } = string.Empty;
        public int SampleCount { get; set; }
    }

    public class FirewallDiscoveryOptions
    {
        public IPAddress? KnownFirewallIp { get; set; }
        public IPAddress? SampleSubnetIp { get; set; }
        public List<FirewallNetworkDefinition> Networks { get; set; } = new List<FirewallNetworkDefinition>();

        public string? IpRangeStart { get; set; }
        public string? IpRangeEnd { get; set; }
        public string? CidrRange { get; set; }
        public bool EnableRangeScanning { get; set; } = false;

        public List<int> PortsToScan { get; set; } = new List<int>();
        public List<int> DefaultReachabilityPorts { get; set; } = new List<int>();
        public int MaxConcurrentProbes { get; set; } = 32;
        public int MaxConcurrentHostScans { get; set; } = 64;
        public int ConnectTimeoutMs { get; set; } = 1500;
        public int IcmpTimeoutMs { get; set; } = 1000;
        public int IcmpProbeCount { get; set; } = 3;
    }

    public class FirewallDiscoveryResult
    {
        public List<FirewallDiscoveryHostReachabilityResult> ReachabilityResults { get; set; } = new List<FirewallDiscoveryHostReachabilityResult>();
        public List<PortProbeResult> RawPortProbes { get; set; } = new List<PortProbeResult>();
        public List<InferredFirewallRule> InferredRules { get; set; } = new List<InferredFirewallRule>();
    }
}

