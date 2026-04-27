using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
namespace Dorothy.Models
{
    public class HostProbeResult : INotifyPropertyChanged
    {
        private string _ipAddress = string.Empty;
        private string? _hostname;
        private ProbeStatus _status = ProbeStatus.Pending;
        private RouteStatus _routeStatus = RouteStatus.Unknown;
        private string? _routeGateway;
        private IcmpStatus _icmpStatus = IcmpStatus.NoReply;
        private long? _icmpRttMs;
        private string? _summary;
        private DateTime _startedAt;
        private DateTime? _completedAt;

        public string IpAddress
        {
            get => _ipAddress;
            set { _ipAddress = value; NotifyChanged(nameof(IpAddress)); }
        }

        public string? Hostname
        {
            get => _hostname;
            set { _hostname = value; NotifyChanged(nameof(Hostname)); }
        }

        public ProbeStatus Status
        {
            get => _status;
            set { _status = value; NotifyChanged(nameof(Status)); }
        }

        public RouteStatus RouteStatus
        {
            get => _routeStatus;
            set { _routeStatus = value; NotifyChanged(nameof(RouteStatus)); }
        }

        public string? RouteGateway
        {
            get => _routeGateway;
            set { _routeGateway = value; NotifyChanged(nameof(RouteGateway)); }
        }

        public IcmpStatus IcmpStatus
        {
            get => _icmpStatus;
            set { _icmpStatus = value; NotifyChanged(nameof(IcmpStatus)); }
        }

        public long? IcmpRttMs
        {
            get => _icmpRttMs;
            set { _icmpRttMs = value; NotifyChanged(nameof(IcmpRttMs)); }
        }

        public List<TracerouteHop> TracerouteHops { get; set; } = new List<TracerouteHop>();
        public List<TracerouteHop> TcpTracerouteHops { get; set; } = new List<TracerouteHop>();

        public Dictionary<int, PortStatus> TcpPorts { get; set; } = new Dictionary<int, PortStatus>();
        public Dictionary<string, string> SnmpValues { get; set; } = new Dictionary<string, string>();

        public string? NetBiosName { get; set; }
        public string? NetBiosWorkgroup { get; set; }
        public string? OsFamily { get; set; }
        public string? OsVersion { get; set; }
        public double OsConfidence { get; set; }
        public List<BannerInfo>? Banners { get; set; }

        // 2.5.1 expansion: tiered probe pipeline (Simple / Advanced)
        public ProbeLevel Level { get; set; } = ProbeLevel.Simple;
        public List<UdpScanResult>? UdpResults { get; set; }
        public SmbInfo? SmbInfo { get; set; }
        // Per-port HTTP path findings, keyed by HTTP/HTTPS port number.
        public Dictionary<int, List<HttpPathFinding>>? HttpPaths { get; set; }
        // Per-port TLS certificate / handshake info, populated only by Advanced.
        public Dictionary<int, TlsInfo?>? TlsInfo { get; set; }

        public string? Summary
        {
            get => _summary;
            set { _summary = value; NotifyChanged(nameof(Summary)); }
        }

        public DateTime StartedAt
        {
            get => _startedAt;
            set { _startedAt = value; NotifyChanged(nameof(StartedAt)); }
        }

        public DateTime? CompletedAt
        {
            get => _completedAt;
            set { _completedAt = value; NotifyChanged(nameof(CompletedAt)); }
        }

        public static string PortStatusExplanation(PortStatus status) => status switch
        {
            PortStatus.Open => "Port is open and accepting connections.",
            PortStatus.Closed => "Host responded but the port is closed (no service listening).",
            PortStatus.Filtered => "No response - likely blocked by a firewall or ACL.",
            PortStatus.Error => "Probe error - see diagnostics for details.",
            _ => "Unknown port status."
        };

        public string RouteExplanation => RouteStatus switch
        {
            RouteStatus.Local => "Target is on a directly-connected subnet (no gateway hop).",
            RouteStatus.ViaGateway => $"Target is off-subnet; traffic forwarded via {RouteGateway ?? "the default gateway"}.",
            RouteStatus.NoRoute => "No route found: target matches no local subnet and no default gateway is configured.",
            _ => "Route state unknown."
        };

        public string IcmpExplanation => IcmpStatus switch
        {
            IcmpStatus.Reply => IcmpRttMs.HasValue
                ? $"ICMP echo reply received in {IcmpRttMs} ms."
                : "ICMP echo reply received.",
            IcmpStatus.NoReply => "No ICMP echo reply within timeout. Host may be offline, firewalled, or ICMP-blocked.",
            IcmpStatus.Error => "ICMP probe errored out - see logs for details.",
            _ => "ICMP status unknown."
        };

        public bool SnmpResponded => SnmpValues != null && SnmpValues.Count > 0;

        public event PropertyChangedEventHandler? PropertyChanged;

        protected void NotifyChanged([CallerMemberName] string? prop = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(prop));
        }
    }
}
