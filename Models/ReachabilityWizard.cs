using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Dorothy.Models
{
    /// <summary>
    /// Analysis mode for the wizard
    /// </summary>
    public enum AnalysisMode
    {
        RemoteNetworkKnown,  // Mode A: User knows target CIDR + optional IPs
        BoundaryOnly         // Mode B: Analyze boundary device only
    }

    /// <summary>
    /// Stores wizard state and context for reachability analysis
    /// </summary>
    public class AnalysisContext
    {
        public AnalysisMode Mode { get; set; } = AnalysisMode.RemoteNetworkKnown;
        public string VantagePointName { get; set; } = "LAN-Host";
        public string SourceNicId { get; set; } = string.Empty;
        public IPAddress SourceIp { get; set; } = null!;
        public string TargetNetworkName { get; set; } = string.Empty;
        public string TargetCidr { get; set; } = string.Empty;
        public List<InsideAssetDefinition> InsideAssets { get; set; } = new List<InsideAssetDefinition>();
        
        // Boundary device information
        public IPAddress? BoundaryGatewayIp { get; set; }
        public string? BoundaryVendor { get; set; }
        
        // For boundary-only mode
        public IPAddress? ExternalTestIp { get; set; }
    }

    /// <summary>
    /// Represents a known inside asset (IP + optional label)
    /// </summary>
    public class InsideAssetDefinition
    {
        public IPAddress AssetIp { get; set; } = null!;
        public string? Label { get; set; }

        /// <summary>
        /// Asset IP as string for display
        /// </summary>
        public string AssetIpString => AssetIp?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Result of ICMP reachability check for a target
    /// </summary>
    public class IcmpReachabilityResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public string Role { get; set; } = string.Empty; // "Gateway candidate" or "Known asset"
        public bool Reachable { get; set; }
        public int Sent { get; set; }
        public int Received { get; set; }
        public long? AvgRttMs { get; set; }

        /// <summary>
        /// Target IP as string for display
        /// </summary>
        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// TCP port state classification
    /// </summary>
    public enum TcpState
    {
        Open,      // Connection succeeded
        Closed,    // Connection refused
        Filtered   // Timeout / no response
    }

    /// <summary>
    /// Result of TCP reachability check for a specific port
    /// </summary>
    public class TcpReachabilityResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public int Port { get; set; }
        public TcpState State { get; set; }
        public long RttMs { get; set; }
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Target IP as string for display
        /// </summary>
        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Represents a single hop in a traceroute path
    /// </summary>
    public class PathHop
    {
        public int HopNumber { get; set; }
        public IPAddress? HopIp { get; set; }
        public long? RttMs { get; set; }
        public string? Hostname { get; set; }

        /// <summary>
        /// Hop IP as string for display
        /// </summary>
        public string HopIpString => HopIp?.ToString() ?? "*";
    }

    /// <summary>
    /// Complete path analysis result from traceroute
    /// </summary>
    public class PathAnalysisResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public List<PathHop> Hops { get; set; } = new List<PathHop>();
        public bool Completed { get; set; }
        public string? Notes { get; set; }

        /// <summary>
        /// Target IP as string for display
        /// </summary>
        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Result of deeper port scan on a reachable host
    /// </summary>
    public class DeeperScanResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public Dictionary<int, TcpState> PortStates { get; set; } = new Dictionary<int, TcpState>();
        public string? Summary { get; set; }

        /// <summary>
        /// Target IP as string for display
        /// </summary>
        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;

        /// <summary>
        /// Get open ports as comma-separated string
        /// </summary>
        public string OpenPortsString
        {
            get
            {
                var openPorts = PortStates.Where(kvp => kvp.Value == Models.TcpState.Open)
                    .Select(kvp => kvp.Key)
                    .OrderBy(p => p)
                    .ToList();
                return openPorts.Count > 0 ? string.Join(", ", openPorts) : "None";
            }
        }

        /// <summary>
        /// Get counts of closed and filtered ports
        /// </summary>
        public int ClosedCount => PortStates.Count(kvp => kvp.Value == Models.TcpState.Closed);
        public int FilteredCount => PortStates.Count(kvp => kvp.Value == Models.TcpState.Filtered);
    }

    /// <summary>
    /// Complete wizard result containing all analysis data
    /// </summary>
    public class ReachabilityWizardResult
    {
        public AnalysisContext Context { get; set; } = null!;
        public List<IcmpReachabilityResult> IcmpResults { get; set; } = new List<IcmpReachabilityResult>();
        public List<TcpReachabilityResult> TcpResults { get; set; } = new List<TcpReachabilityResult>();
        public PathAnalysisResult? PathResult { get; set; }
        public List<DeeperScanResult> DeeperScanResults { get; set; } = new List<DeeperScanResult>();
        
        // Boundary device summary (derived from results for convenience)
        public IPAddress? BoundaryGatewayIp { get; set; }
        public string? BoundaryVendor { get; set; }
        public bool BoundaryIcmpReachable { get; set; }
        public bool BoundaryAnyTcpReachable { get; set; }
    }
}

