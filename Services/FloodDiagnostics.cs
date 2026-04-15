namespace Dorothy.Services
{

    public enum RateUnit
    {
        Bps,
        Kbps,
        Mbps,
        Gbps
    }

    public enum DiagnosticReason
    {

        None,

        CpuBound,

        SchedulerGranularity,

        DeviceSendLatency,

        PacketBuildOverhead,

        UiOverhead,

        GatewayOrMacUnresolved,

        InvalidPacketRejected,

        AdapterOrDriverLimit,

        ConfiguredTargetBelowMinPracticalRate,

        Unknown
    }

    public enum DiagnosticConfidence
    {
        NotApplicable,
        Low,
        Medium,
        High
    }

    public enum FloodRunStatus
    {
        Idle,
        Calibrating,
        Running,
        UnderTarget,
        Stopped,
        Error
    }

    public sealed class FloodProtocolCapabilities
    {
        public bool SupportsRateSnapshots    { get; init; }
        public bool SupportsDiagnostics      { get; init; }
        public bool SupportsCalibrationState { get; init; }
        public string UnavailableMessage     { get; init; } = string.Empty;

        public static FloodProtocolCapabilities TcpWithCalibration { get; } = new()
        {
            SupportsRateSnapshots    = true,
            SupportsDiagnostics      = true,
            SupportsCalibrationState = true
        };

        public static FloodProtocolCapabilities FullScheduler { get; } = new()
        {
            SupportsRateSnapshots    = true,
            SupportsDiagnostics      = true,
            SupportsCalibrationState = false
        };

        public static FloodProtocolCapabilities None { get; } = new()
        {
            SupportsRateSnapshots    = false,
            SupportsDiagnostics      = false,
            SupportsCalibrationState = false,
            UnavailableMessage       =
                "Rate diagnostics not available for this protocol. " +
                "Only TCP SYN, UDP, ICMP, and Ethernet floods use the shared " +
                "FloodScheduler snapshot model. NMEA 0183, Modbus/TCP, and ARP " +
                "spoofing use legacy send paths and are deferred for porting."
        };
    }

    public sealed class FloodSnapshot
    {

        public long TargetWireBytesPerSec { get; init; }

        public long ActualWireBytesPerSecShort  { get; init; }
        public long ActualWireBytesPerSecMedium { get; init; }

        public long PacketsAttempted { get; init; }
        public long PacketsSent      { get; init; }
        public long PacketsFailed    { get; init; }
        public long PacketsDropped   { get; init; }

        public long WireBytesSent { get; init; }

        public long SchedulerSleepCycles { get; init; }
        public long SchedulerSpinCycles  { get; init; }

        public double ElapsedSeconds { get; init; }
        public string Protocol { get; init; } = string.Empty;

        public DiagnosticReason LastReason { get; init; }
        public DiagnosticConfidence Confidence { get; init; }
        public bool IsCalibrating { get; init; }

        public string ReasonString { get; init; } = "Idle";

        public double ActualMbps { get; init; }

        public double VsTargetPercent { get; init; }

        public double ActualMbpsShort  => ActualWireBytesPerSecShort  * 8.0 / 1_000_000.0;
        public double ActualMbpsMedium => ActualWireBytesPerSecMedium * 8.0 / 1_000_000.0;
        public double TargetMbps       => TargetWireBytesPerSec       * 8.0 / 1_000_000.0;
        public double DeltaMbps        => ActualMbpsShort - TargetMbps;
    }

    public static class RateConverter
    {

        public static long ToWireBytesPerSec(double value, RateUnit unit) => unit switch
        {
            RateUnit.Bps  => (long)(value / 8.0),
            RateUnit.Kbps => (long)(value * 125.0),
            RateUnit.Mbps => (long)(value * 125_000.0),
            RateUnit.Gbps => (long)(value * 125_000_000.0),
            _             => (long)(value * 125_000.0)
        };

        public static string Format(long wireBytesPerSec)
        {
            double bits = wireBytesPerSec * 8.0;
            if (bits >= 1_000_000_000) return $"{bits / 1_000_000_000:F2} Gbps";
            if (bits >= 1_000_000)     return $"{bits / 1_000_000:F2} Mbps";
            if (bits >= 1_000)         return $"{bits / 1_000:F2} Kbps";
            return $"{bits:F0} bps";
        }

        public static string FormatConfidenceShort(DiagnosticConfidence confidence) => confidence switch
        {
            DiagnosticConfidence.High          => "High",
            DiagnosticConfidence.Medium        => "Medium",
            DiagnosticConfidence.Low           => "Low",
            DiagnosticConfidence.NotApplicable => "—",
            _                                  => "—"
        };

        public static string FormatConfidence(DiagnosticConfidence confidence) => confidence switch
        {
            DiagnosticConfidence.High   => "High — direct counter evidence",
            DiagnosticConfidence.Medium => "Medium — one indirect indicator",
            DiagnosticConfidence.Low    => "Low — weak signal; reason may be misclassified",
            _                           => string.Empty
        };

        public static string Explain(DiagnosticReason reason) => reason switch
        {
            DiagnosticReason.None
                => string.Empty,
            DiagnosticReason.CpuBound
                => "CPU saturated — generation cannot keep up",
            DiagnosticReason.SchedulerGranularity
                => "OS timer resolution limits low-rate precision",
            DiagnosticReason.DeviceSendLatency
                => "NIC driver / Npcap send latency",
            DiagnosticReason.PacketBuildOverhead
                => "Packet pool rebuild overhead",
            DiagnosticReason.UiOverhead
                => "UI event overhead",
            DiagnosticReason.GatewayOrMacUnresolved
                => "Gateway or target MAC not resolved",
            DiagnosticReason.InvalidPacketRejected
                => "Packets rejected by validator",
            DiagnosticReason.AdapterOrDriverLimit
                => "NIC / driver throughput ceiling",
            DiagnosticReason.ConfiguredTargetBelowMinPracticalRate
                => "Target below min practical rate",
            _
                => "Unknown — check NLog"
        };

        public static string ExplainFull(DiagnosticReason reason) => reason switch
        {
            DiagnosticReason.None
                => "Throughput is on target.",
            DiagnosticReason.CpuBound
                => "CPU is saturated — packet generation cannot keep up with the target rate. " +
                   "Consider reducing the rate or payload size.",
            DiagnosticReason.SchedulerGranularity
                => "Windows default timer resolution (~15 ms) limits how precisely the token " +
                   "bucket can pace very low rates.",
            DiagnosticReason.DeviceSendLatency
                => "NIC driver or Npcap send-path latency is constraining throughput. " +
                   "Check driver version or try a different NIC.",
            DiagnosticReason.PacketBuildOverhead
                => "Packet pool rebuild (checksum computation, randomisation) is consuming " +
                   "significant CPU time.",
            DiagnosticReason.UiOverhead
                => "UI event-dispatch overhead may be affecting the send loop.",
            DiagnosticReason.GatewayOrMacUnresolved
                => "Gateway or target MAC address could not be resolved — frames are not " +
                   "being transmitted. Check gateway IP and NIC selection.",
            DiagnosticReason.InvalidPacketRejected
                => "Frames were rejected by PacketValidator before transmit. " +
                   "Check NLog for checksum or format details.",
            DiagnosticReason.AdapterOrDriverLimit
                => "NIC adapter or Npcap driver throughput ceiling reached. " +
                   "This is the hardware maximum for this interface.",
            DiagnosticReason.ConfiguredTargetBelowMinPracticalRate
                => "The configured target rate is below the minimum practical rate for this " +
                   "protocol and OS combination.",
            _
                => "Rate is below target for an unclassified reason. Check NLog output."
        };
    }
}
