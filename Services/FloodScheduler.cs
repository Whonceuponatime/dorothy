using System;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using NLog;

namespace Dorothy.Services
{

    public sealed class FloodScheduler
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private double _tokens;
        private readonly double _ratePerTick;
        private readonly double _burstCapBytes;
        private long _lastTick;
        private readonly long _freq;
        private readonly Stopwatch _sw;

        private long _scheduledPackets;
        private long _sentPackets;
        private long _failedSends;
        private long _droppedPackets;
        private long _totalWireBytesSent;
        private long _sleepCycles;
        private long _spinCycles;

        private long _telemetryLastTick;
        private long _telemetryWindowStartBytes;
        private long _telemetryWindowStartPackets;
        private long _telemetryWindowStartDrained;
        private long _telemetryWindowDrained;
        private long _telemetryCarriedBytes;

        private long _drainCalls;
        private long _drainGrantedBytes;
        private long _drainDeniedCount;
        private long _drainLastSchedLogAtCalls;
        private long _drainLastSchedLogAtTick;
        private long _drainLastSchedLogAtGrantedBytes;

        public long ScheduledPackets  => Interlocked.Read(ref _scheduledPackets);
        public long SentPackets       => Interlocked.Read(ref _sentPackets);
        public long FailedSends       => Interlocked.Read(ref _failedSends);
        public long DroppedPackets    => Interlocked.Read(ref _droppedPackets);
        public long TotalWireBytesSent => Interlocked.Read(ref _totalWireBytesSent);
        public long SleepCycles       => Interlocked.Read(ref _sleepCycles);
        public long SpinCycles        => Interlocked.Read(ref _spinCycles);

        public double CurrentTokens => _tokens;
        public double BurstCapBytes => _burstCapBytes;

        public DiagnosticReason LastReason { get; set; } = DiagnosticReason.None;

        public double Mbps1s  { get; set; }
        public double Mbps5s  { get; set; }
        public double Mbps10s { get; set; }

        public FloodScheduler(long targetWireBytesPerSec, double burstWindowMs = 10.0)
        {
            _freq          = Stopwatch.Frequency;
            _ratePerTick   = (double)targetWireBytesPerSec / _freq;
            _burstCapBytes = targetWireBytesPerSec * (burstWindowMs / 1000.0);
            _tokens        = 0;
            _sw            = Stopwatch.StartNew();
            _lastTick      = _sw.ElapsedTicks;
            _telemetryLastTick = _lastTick;
        }

        public static long ConvertToBytes(double value, RateUnit unit)
            => RateConverter.ToWireBytesPerSec(value, unit);

        public int Drain(int wirePacketSize, int maxPerCall = 32)
        {
            long now = _sw.ElapsedTicks;
            _tokens += (now - _lastTick) * _ratePerTick;
            _lastTick = now;

            if (_tokens > _burstCapBytes) _tokens = _burstCapBytes;

            long calls = Interlocked.Increment(ref _drainCalls);

            if (_tokens < wirePacketSize)
            {
                Interlocked.Increment(ref _drainDeniedCount);
                MaybeLogSched(calls, now);
                return 0;
            }

            int count = (int)(_tokens / wirePacketSize);
            if (count > maxPerCall) count = maxPerCall;
            _tokens -= count * wirePacketSize;
            Interlocked.Add(ref _drainGrantedBytes, (long)count * wirePacketSize);
            Interlocked.Add(ref _scheduledPackets, count);
            Interlocked.Add(ref _telemetryWindowDrained, count);
            MaybeLogSched(calls, now);
            return count;
        }

        private void MaybeLogSched(long calls, long nowTick)
        {
            if (calls - _drainLastSchedLogAtCalls < 1000) return;

            long winCalls = calls - _drainLastSchedLogAtCalls;
            long grantedNow = Interlocked.Read(ref _drainGrantedBytes);
            long winGranted = grantedNow - _drainLastSchedLogAtGrantedBytes;
            long winTicks = _drainLastSchedLogAtTick == 0 ? 0 : nowTick - _drainLastSchedLogAtTick;
            double winSec = _freq > 0 ? winTicks / (double)_freq : 0.0;
            long winDenied = Interlocked.Read(ref _drainDeniedCount);
            long avgWaitUs = winCalls > 0 && winSec > 0 ? (long)(winSec * 1_000_000.0 / winCalls) : 0;

            Logger.Info(
                $"[SCHED] waits={calls} win_calls={winCalls} win_sec={winSec:F3} " +
                $"granted_bytes={winGranted} total_granted={grantedNow} " +
                $"avg_wait_us={avgWaitUs} tokens_requested={calls} tokens_denied={winDenied}");

            _drainLastSchedLogAtCalls = calls;
            _drainLastSchedLogAtTick = nowTick;
            _drainLastSchedLogAtGrantedBytes = grantedNow;
        }

        public static long ClampTargetToNicSpeed(string? sourceIp, long targetWireBytesPerSec)
        {
            if (targetWireBytesPerSec <= 0 || string.IsNullOrWhiteSpace(sourceIp))
                return targetWireBytesPerSec;

            try
            {
                NetworkInterface? match = null;
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    var props = nic.GetIPProperties();
                    if (props.UnicastAddresses.Any(a => a.Address.ToString() == sourceIp))
                    {
                        match = nic;
                        break;
                    }
                }
                if (match == null || match.Speed <= 0) return targetWireBytesPerSec;

                long nicBps = match.Speed / 8;
                long capBps = (long)(nicBps * 0.95);
                if (targetWireBytesPerSec > capBps)
                {
                    double targetMbps = targetWireBytesPerSec * 8.0 / 1_000_000.0;
                    double nicMbps = match.Speed / 1_000_000.0;
                    double capMbps = capBps * 8.0 / 1_000_000.0;
                    Logger.Warn(
                        $"Target {targetMbps:F2} Mbps exceeds 95% of NIC link speed {nicMbps:F2} Mbps. " +
                        $"Clamping to {capMbps:F2} Mbps.");
                    return capBps;
                }
            }
            catch (Exception ex) { Logger.Debug(ex, "NIC speed probe failed"); }
            return targetWireBytesPerSec;
        }

        public void Refund(int wireBytes)
        {
            if (wireBytes <= 0) return;
            _tokens += wireBytes;
            if (_tokens > _burstCapBytes) _tokens = _burstCapBytes;
            Interlocked.Add(ref _telemetryCarriedBytes, wireBytes);
        }

        public void LogTelemetry(int workerId, int workerCount, long targetBps, string reason)
            => LogTelemetry(workerId, workerCount, targetBps, reason, queueDepthBytes: -1);

        public void LogTelemetry(int workerId, int workerCount, long targetBps, string reason, long queueDepthBytes)
        {
            long now = _sw.ElapsedTicks;
            double windowSec = (now - _telemetryLastTick) / (double)_freq;
            if (windowSec < 1.0) return;

            long bytesNow   = Interlocked.Read(ref _totalWireBytesSent);
            long packetsNow = Interlocked.Read(ref _sentPackets);
            long drainedNow = Interlocked.Read(ref _telemetryWindowDrained);
            long carryNow   = Interlocked.Read(ref _telemetryCarriedBytes);

            long wBytes   = bytesNow   - _telemetryWindowStartBytes;
            long wPackets = packetsNow - _telemetryWindowStartPackets;
            long wDrained = drainedNow - _telemetryWindowStartDrained;
            long actualBps = (long)(wBytes / windowSec);

            string qd = queueDepthBytes >= 0 ? $" queue_depth={queueDepthBytes}" : string.Empty;
            Logger.Info(
                $"FloodScheduler[{workerId}/{workerCount}] target={targetBps}B/s actual={actualBps}B/s " +
                $"tokens_drained={wDrained} packets_sent={wPackets} deficit_carried={carryNow}{qd} reason={reason}");

            _telemetryLastTick            = now;
            _telemetryWindowStartBytes    = bytesNow;
            _telemetryWindowStartPackets  = packetsNow;
            _telemetryWindowStartDrained  = drainedNow;
        }

        public void RecordSent(int wireBytes)
        {
            Interlocked.Increment(ref _sentPackets);
            Interlocked.Add(ref _totalWireBytesSent, wireBytes);
        }

        public void RecordFailed()   => Interlocked.Increment(ref _failedSends);
        public void RecordDropped()  => Interlocked.Increment(ref _droppedPackets);
        public void RecordSleep()    => Interlocked.Increment(ref _sleepCycles);
        public void RecordSpin()     => Interlocked.Increment(ref _spinCycles);

        public double ElapsedSeconds => _sw.ElapsedTicks / (double)_freq;

        public string DiagLine =>
            $"sched={ScheduledPackets:N0} sent={SentPackets:N0} fail={FailedSends} " +
            $"drop={DroppedPackets} wireKB={TotalWireBytesSent / 1024:N0} " +
            $"sleep={SleepCycles} spin={SpinCycles} " +
            $"Mbps(1s/5s/10s)={Mbps1s:F2}/{Mbps5s:F2}/{Mbps10s:F2}";

        public DiagnosticConfidence InferConfidence(DiagnosticReason reason, long targetWireBytesPerSec)
        {
            return reason switch
            {
                DiagnosticReason.None
                    => DiagnosticConfidence.NotApplicable,

                DiagnosticReason.GatewayOrMacUnresolved
                    => SentPackets == 0 && ElapsedSeconds > 2.0
                        ? DiagnosticConfidence.High
                        : DiagnosticConfidence.Low,

                DiagnosticReason.InvalidPacketRejected
                    => ScheduledPackets > 0 && (double)DroppedPackets / ScheduledPackets > 0.05
                        ? DiagnosticConfidence.High
                        : DiagnosticConfidence.Medium,

                DiagnosticReason.DeviceSendLatency
                    => (SentPackets + FailedSends) > 0 &&
                       (double)FailedSends / (SentPackets + FailedSends) > 0.05
                        ? DiagnosticConfidence.High
                        : DiagnosticConfidence.Low,

                DiagnosticReason.ConfiguredTargetBelowMinPracticalRate
                    => targetWireBytesPerSec < 10_000
                        ? DiagnosticConfidence.High
                        : DiagnosticConfidence.Medium,

                DiagnosticReason.SchedulerGranularity
                    => targetWireBytesPerSec < 100_000 && SleepCycles > 0
                        ? DiagnosticConfidence.High
                        : DiagnosticConfidence.Medium,

                DiagnosticReason.CpuBound
                    => DiagnosticConfidence.Medium,

                _ => DiagnosticConfidence.Low
            };
        }

        public DiagnosticReason InferReason(long targetWireBytesPerSec)
        {
            if (SentPackets == 0 && ElapsedSeconds > 2.0)
                return DiagnosticReason.GatewayOrMacUnresolved;

            if (DroppedPackets > 0 && ScheduledPackets > 0 &&
                (double)DroppedPackets / ScheduledPackets > 0.05)
                return DiagnosticReason.InvalidPacketRejected;

            if (FailedSends > 0 && (SentPackets + FailedSends) > 0 &&
                (double)FailedSends / (SentPackets + FailedSends) > 0.05)
                return DiagnosticReason.DeviceSendLatency;

            double actualWireBytesPerSec = Mbps1s * 1_000_000.0 / 8.0;
            double ratio = targetWireBytesPerSec > 0
                ? actualWireBytesPerSec / targetWireBytesPerSec
                : 1.0;

            if (ratio >= 0.95) return DiagnosticReason.None;

            if (targetWireBytesPerSec < 10_000)
                return DiagnosticReason.ConfiguredTargetBelowMinPracticalRate;
            if (targetWireBytesPerSec < 100_000 && SleepCycles > 0)
                return DiagnosticReason.SchedulerGranularity;

            if (SpinCycles > 0 && SleepCycles == 0 && ratio < 0.90)
                return DiagnosticReason.CpuBound;

            if (FailedSends > 0)
                return DiagnosticReason.DeviceSendLatency;

            return DiagnosticReason.Unknown;
        }

        public string InferReasonString(long targetWireBytesPerSec)
        {
            if (SentPackets == 0 && ElapsedSeconds < 1.0) return "Idle";
            if (targetWireBytesPerSec <= 0)               return "Idle";

            double actualWireBytesPerSec = Mbps1s * 1_000_000.0 / 8.0;
            double ratio = actualWireBytesPerSec / targetWireBytesPerSec;

            long totalSends = SentPackets + FailedSends;
            if (FailedSends > 0 && totalSends > 0 && (double)FailedSends / totalSends > 0.05)
                return "NIC saturated";

            if (ratio >= 0.95) return "On target";

            if (SpinCycles > 0 && SleepCycles == 0 && ratio < 0.90)
                return "CPU bound";

            return "Drain starved";
        }

        public static string InferReasonString(
            long   targetWireBytesPerSec,
            double actualMbps1s,
            long   sentPackets,
            long   failedSends,
            long   spinCycles,
            long   sleepCycles,
            double elapsedSeconds)
        {
            if (sentPackets == 0 && elapsedSeconds < 1.0) return "Idle";
            if (targetWireBytesPerSec <= 0)               return "Idle";

            double actualWireBytesPerSec = actualMbps1s * 1_000_000.0 / 8.0;
            double ratio = actualWireBytesPerSec / targetWireBytesPerSec;

            long totalSends = sentPackets + failedSends;
            if (failedSends > 0 && totalSends > 0 && (double)failedSends / totalSends > 0.05)
                return "NIC saturated";

            if (ratio >= 0.95) return "On target";

            if (spinCycles > 0 && sleepCycles == 0 && ratio < 0.90)
                return "CPU bound";

            return "Drain starved";
        }

        public FloodSnapshot TakeSnapshot(
            long   targetWireBytesPerSec,
            string protocol      = "",
            bool   isCalibrating = false)
        {
            long shortWireBytesPerSec  = (long)(Mbps1s * 1_000_000.0 / 8.0);
            long mediumWireBytesPerSec = (long)(Mbps5s * 1_000_000.0 / 8.0);

            var confidence = InferConfidence(LastReason, targetWireBytesPerSec);

            double elapsed   = ElapsedSeconds;
            long   bytesSent = TotalWireBytesSent;
            double actualMbps = elapsed > 0
                ? bytesSent * 8.0 / (elapsed * 1_000_000.0)
                : 0.0;
            double targetMbps = targetWireBytesPerSec * 8.0 / 1_000_000.0;
            double vsPct = targetMbps > 0 ? (actualMbps / targetMbps) * 100.0 : 0.0;

            return new FloodSnapshot
            {
                TargetWireBytesPerSec       = targetWireBytesPerSec,
                ActualWireBytesPerSecShort  = shortWireBytesPerSec,
                ActualWireBytesPerSecMedium = mediumWireBytesPerSec,
                PacketsAttempted            = ScheduledPackets,
                PacketsSent                 = SentPackets,
                PacketsFailed               = FailedSends,
                PacketsDropped              = DroppedPackets,
                WireBytesSent               = bytesSent,
                SchedulerSleepCycles        = SleepCycles,
                SchedulerSpinCycles         = SpinCycles,
                ElapsedSeconds              = elapsed,
                LastReason                  = LastReason,
                Confidence                  = confidence,
                Protocol                    = protocol,
                IsCalibrating               = isCalibrating,
                ReasonString                = InferReasonString(targetWireBytesPerSec),
                ActualMbps                  = actualMbps,
                VsTargetPercent             = vsPct
            };
        }
    }
}
