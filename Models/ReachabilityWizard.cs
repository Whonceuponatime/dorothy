using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Dorothy.Models
{

    public enum AnalysisMode
    {
        RemoteNetworkKnown,
        BoundaryOnly
    }

    public class AnalysisContext
    {
        public AnalysisMode Mode { get; set; } = AnalysisMode.RemoteNetworkKnown;
        public string VantagePointName { get; set; } = "LAN-Host";
        public string SourceNicId { get; set; } = string.Empty;
        public IPAddress SourceIp { get; set; } = null!;
        public string TargetNetworkName { get; set; } = string.Empty;
        public string TargetCidr { get; set; } = string.Empty;
        public List<InsideAssetDefinition> InsideAssets { get; set; } = new List<InsideAssetDefinition>();

        public IPAddress? BoundaryGatewayIp { get; set; }
        public string? BoundaryVendor { get; set; }

        public IPAddress? ExternalTestIp { get; set; }
    }

    public class InsideAssetDefinition
    {
        public IPAddress AssetIp { get; set; } = null!;
        public string? Label { get; set; }

        public string AssetIpString => AssetIp?.ToString() ?? string.Empty;
    }

    public class IcmpReachabilityResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public string Role { get; set; } = string.Empty;
        public bool Reachable { get; set; }
        public int Sent { get; set; }
        public int Received { get; set; }
        public long? AvgRttMs { get; set; }

        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;
    }

    public enum TcpState
    {
        Open,
        Closed,
        Filtered,
        TimedOut,
        NetworkUnreachable,
        HostUnreachable,
        Error
    }

    public static class TcpStateExtensions
    {
        public static bool IsActiveResponse(this TcpState s) =>
            s == TcpState.Open || s == TcpState.Closed;

        public static bool IsNoResponse(this TcpState s) =>
            s == TcpState.Filtered || s == TcpState.TimedOut ||
            s == TcpState.NetworkUnreachable || s == TcpState.HostUnreachable ||
            s == TcpState.Error;
    }

    public class TcpReachabilityResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public int Port { get; set; }
        public TcpState State { get; set; }
        public long RttMs { get; set; }
        public string? ErrorMessage { get; set; }

        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;
    }

    public class PathHop
    {
        public int HopNumber { get; set; }
        public IPAddress? HopIp { get; set; }
        public long? RttMs { get; set; }
        public string? Hostname { get; set; }

        public string HopIpString => HopIp?.ToString() ?? "*";
    }

    public class PathAnalysisResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public List<PathHop> Hops { get; set; } = new List<PathHop>();
        public bool Completed { get; set; }
        public string? Notes { get; set; }

        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;
    }

    public class DeeperScanResult
    {
        public IPAddress TargetIp { get; set; } = null!;
        public Dictionary<int, TcpState> PortStates { get; set; } = new Dictionary<int, TcpState>();
        public string? Summary { get; set; }

        public string TargetIpString => TargetIp?.ToString() ?? string.Empty;

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

        public int ClosedCount => PortStates.Count(kvp => kvp.Value == Models.TcpState.Closed);

        public int FilteredCount => PortStates.Count(kvp => kvp.Value.IsNoResponse());
    }

    public class ReachabilityWizardResult
    {
        public AnalysisContext Context { get; set; } = null!;
        public List<IcmpReachabilityResult> IcmpResults { get; set; } = new List<IcmpReachabilityResult>();
        public List<TcpReachabilityResult> TcpResults { get; set; } = new List<TcpReachabilityResult>();
        public PathAnalysisResult? PathResult { get; set; }
        public List<DeeperScanResult> DeeperScanResults { get; set; } = new List<DeeperScanResult>();

        public IPAddress? BoundaryGatewayIp { get; set; }
        public string? BoundaryVendor { get; set; }
        public bool BoundaryIcmpReachable { get; set; }
        public bool BoundaryAnyTcpReachable { get; set; }
    }
}

