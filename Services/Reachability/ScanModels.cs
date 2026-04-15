using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace Dorothy.Services.Reachability
{

    public enum PortState
    {
        Open,
        Closed,
        TimedOut,
        NetworkUnreachable,
        HostUnreachable,
        Error
    }

    public enum HostScanStatus
    {
        Pending,
        Scanning,
        Done,
        Unreachable,
        UnresolvedName,
        Error
    }

    public enum RouteType
    {
        OnLink,
        ViaGateway,
        NoRoute,
        Unknown
    }

    public sealed class UnresolvedTarget
    {
        public string Input  { get; init; } = string.Empty;
        public string Reason { get; init; } = string.Empty;
    }

    public sealed class TargetExpansionResult
    {
        public IReadOnlyList<IPAddress>       ResolvedHosts { get; init; } = Array.Empty<IPAddress>();
        public IReadOnlyList<UnresolvedTarget> Unresolved   { get; init; } = Array.Empty<UnresolvedTarget>();
    }

    public sealed class ReportContext
    {

        public string     NicDisplayName   { get; init; } = string.Empty;
        public IPAddress? SourceIp         { get; init; }
        public string?    BoundaryGateway  { get; init; }
        public RouteType  Route            { get; init; } = RouteType.Unknown;

        public string     TargetResolution { get; init; } = "IP";
    }

    public enum IcmpReplyStatus
    {
        NotTested,
        Reply,
        NoReply,
        Error
    }

    public sealed class IcmpProbeResult
    {
        public IPAddress       Target      { get; init; } = IPAddress.None;

        public bool            Reachable   { get; init; }

        public IcmpReplyStatus ReplyStatus { get; init; } = IcmpReplyStatus.NotTested;
        public int             Sent        { get; init; }
        public int             Received    { get; init; }
        public long            AvgRttMs    { get; init; }
    }

    public sealed class TcpPortResult
    {
        public int       Port  { get; init; }
        public PortState State { get; init; }
        public long      RttMs { get; init; }
        public string?   Error { get; init; }
    }

    public sealed class PathHopResult
    {
        public int         HopNumber  { get; init; }
        public IPAddress?  HopIp      { get; init; }
        public long        RttMs      { get; init; }
        public string?     Hostname   { get; set; }
        public string HopIpDisplay => HopIp?.ToString() ?? "*";
    }

    public sealed class HostScanResult
    {
        public IPAddress       Target    { get; init; } = IPAddress.None;
        public string?         Hostname  { get; set; }
        public HostScanStatus  Status    { get; set; } = HostScanStatus.Pending;
        public IcmpProbeResult? IcmpResult { get; set; }
        public List<TcpPortResult> TcpResults { get; init; } = new();
        public string? ErrorMessage { get; set; }

        public IEnumerable<TcpPortResult> OpenPorts     => TcpResults.Where(p => p.State == PortState.Open);
        public IEnumerable<TcpPortResult> ClosedPorts   => TcpResults.Where(p => p.State == PortState.Closed);
        public IEnumerable<TcpPortResult> TimedOutPorts => TcpResults.Where(p =>
            p.State == PortState.TimedOut ||
            p.State == PortState.NetworkUnreachable ||
            p.State == PortState.HostUnreachable);
        public IEnumerable<TcpPortResult> ErrorPorts    => TcpResults.Where(p => p.State == PortState.Error);

        public bool HasAnyDefinitiveResponse =>
            (IcmpResult?.Reachable ?? false) ||
            TcpResults.Any(p => p.State == PortState.Open || p.State == PortState.Closed);
    }

    public sealed class ScanOptions
    {
        public bool       UseIcmpDiscovery  { get; init; } = true;
        public int        MaxConcurrency    { get; init; } = 10;
        public int        PerProbeTimeoutMs { get; init; } = 3000;
        public int        IcmpTimeoutMs     { get; init; } = 2000;
        public int        IcmpPingCount     { get; init; } = 2;

        public IPAddress? SourceIp         { get; init; }
    }

    public sealed record ScanProgress(int CompletedHosts, int TotalHosts, string CurrentActivity);

    public sealed class WorkloadEstimate
    {
        public long      HostCount            { get; init; }
        public int       PortCount            { get; init; }
        public long      TotalProbes          { get; init; }
        public TimeSpan  EstimatedDuration    { get; init; }

        public string    Warning              { get; init; } = string.Empty;

        public bool      RequiresConfirmation { get; init; }

        public bool      IsVeryLarge          { get; init; }

        public string Summary =>
            $"{HostCount:N0} host(s) × {PortCount} port(s) = {TotalProbes:N0} probe(s)" +
            (EstimatedDuration.TotalSeconds >= 1
                ? $"  (~{FormatDuration(EstimatedDuration)} estimated)"
                : string.Empty);

        private static string FormatDuration(TimeSpan ts) =>
            ts.TotalMinutes >= 1
                ? $"{ts.TotalMinutes:F1} min"
                : $"{ts.TotalSeconds:F0} s";
    }

    public static class PortStateExtensions
    {

        public static string ToDisplayGroup(this PortState s) => s switch
        {
            PortState.Open                                      => "Open",
            PortState.Closed                                    => "Closed",
            PortState.TimedOut or PortState.NetworkUnreachable
                or PortState.HostUnreachable                   => "Timed Out / Filtered",
            _                                                   => "Error"
        };
    }
}
