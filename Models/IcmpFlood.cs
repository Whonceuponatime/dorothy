using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NLog;
using PacketDotNet;
using PacketDotNet.Utils;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Services;

namespace Dorothy.Models
{

    public class IcmpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public event EventHandler<PacketEventArgs>? PacketSent;
        public event EventHandler<Dorothy.Services.FloodSnapshot>? StatsPublished;

        public bool DryRunMode { get; set; } = false;

        public IcmpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(
            byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        protected virtual void OnStatsPublished(Dorothy.Services.FloodSnapshot snapshot)
            => StatsPublished?.Invoke(this, snapshot);

        private static ushort IcmpChecksum(byte[] data)
        {
            long sum = 0;
            int  i   = 0;
            while (i < data.Length - 1) { sum += (data[i] << 8) | data[i + 1]; i += 2; }
            if (i < data.Length) sum += data[i] << 8;
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        public async Task StartAsync()
        {
            Logger.Info(DryRunMode ? "[ICMP] DRY-RUN — validate pool only, no transmit."
                                   : "[ICMP] Starting flood.");
            try
            {
                if (!DryRunMode)
                {
                    _device = CaptureDeviceList.Instance
                        .OfType<LibPcapLiveDevice>()
                        .FirstOrDefault(d => d.Addresses.Any(addr =>
                            addr.Addr.ipAddress != null &&
                            addr.Addr.ipAddress.ToString() == _params.SourceIp.ToString()));

                    if (_device == null)
                        throw new Exception("No capture device found for source IP " + _params.SourceIp);

                    _device.Open(DeviceModes.Promiscuous, 1000);
                }

                var sourceMac = PhysicalAddress.Parse(
                    BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(
                    BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                var random = new Random();
                const int payloadSize   = 1400;
                const int icmpHeaderLen = 8;
                const int icmpTotalLen  = icmpHeaderLen + payloadSize;
                const int poolSize      = 512;

                int pid = Environment.ProcessId;
                var pool = new byte[poolSize][];

                for (int i = 0; i < poolSize; i++)
                {
                    var icmpRaw = new byte[icmpTotalLen];
                    icmpRaw[0] = 8;
                    icmpRaw[1] = 0;
                    icmpRaw[4] = (byte)(pid >> 8);
                    icmpRaw[5] = (byte)pid;
                    icmpRaw[6] = (byte)(i >> 8);
                    icmpRaw[7] = (byte)i;
                    random.NextBytes(icmpRaw.AsSpan(icmpHeaderLen));
                    ushort cs = IcmpChecksum(icmpRaw);
                    icmpRaw[2] = (byte)(cs >> 8);
                    icmpRaw[3] = (byte)cs;

                    var icmpPkt = new IcmpV4Packet(new ByteArraySegment(icmpRaw));
                    var ipPkt   = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                    {
                        Protocol   = PacketDotNet.ProtocolType.Icmp,
                        TimeToLive = _params.Ttl,
                        Id         = (ushort)random.Next(0, 65536)
                    };
                    var ethPkt = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);

                    ipPkt.PayloadPacket  = icmpPkt;
                    ethPkt.PayloadPacket = ipPkt;
                    ipPkt.UpdateCalculatedValues();
                    pool[i] = ethPkt.Bytes;
                }

                int  wireSize  = pool[0].Length + 4;
                long targetBps = _params.BytesPerSecond;
                if (!DryRunMode)
                    targetBps = FloodScheduler.ClampTargetToNicSpeed(_params.SourceIp?.ToString(), targetBps);
                double tgtMbps = targetBps * 8.0 / 1_000_000;

                Logger.Info($"[ICMP] frame={pool[0].Length}B  wire={wireSize}B  " +
                            $"target={tgtMbps:F2} Mbps  pool={poolSize}");

                if (DryRunMode)
                {
                    var (valid, invalid) = PacketValidator.ValidatePoolFull(pool, "ICMP");
                    Logger.Info($"[ICMP] DRY-RUN complete — {valid}/{poolSize} valid, " +
                                $"{invalid} invalid. No packets transmitted.");
                    return;
                }

                await RunParallelSendLoopAsync(pool, wireSize, targetBps, tgtMbps);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "[ICMP] Flood failed.");
                throw;
            }
            finally
            {
                _device?.Close();
            }
        }

        private const int SendQueueCapacityBytes = 16 * 1024 * 1024;
        private const int FlushThresholdBytes = 1_000_000;
        private const int FlushThresholdPackets = 1000;

        private async Task RunParallelSendLoopAsync(
            byte[][] pool, int wireSize, long targetBps, double tgtMbps)
        {
            int drainMax = tgtMbps > 500 ? 2000 : tgtMbps > 100 ? 1000 : tgtMbps > 10 ? 400 : 100;

            long sharedBytes   = 0;
            long sharedPackets = 0;
            long sharedFailed  = 0;
            long sharedSpin    = 0;
            long sharedSleep   = 0;

            var scheduler = new FloodScheduler(targetBps);
            var schedulers = new[] { scheduler };

            Logger.Info($"[ICMP] Single-threaded SendQueue loop: target={tgtMbps:F2} Mbps, " +
                        $"queue_capacity={SendQueueCapacityBytes} bytes, drain_max={drainMax}");

            var sendTask = Task.Run(() =>
            {
                int idx = 0;
                long localSent = 0;
                var workerSw = Stopwatch.StartNew();
                Logger.Info($"Flood worker started: id=0 of 1 targetBps={targetBps} pool_size={pool.Length}");

                var sender = new DoubleBufferedSender(
                    _device!, SendQueueCapacityBytes, FlushThresholdBytes, FlushThresholdPackets, "ICMP");

                long winPkts = 0, winBytes = 0, winEnqueueUs = 0, winWaitUs = 0, winWaitCount = 0;
                var winSw = Stopwatch.StartNew();

                void EmitWorkerWindowIfDue()
                {
                    if (winSw.ElapsedMilliseconds < 1000) return;
                    double avgEnq  = winPkts > 0 ? (double)winEnqueueUs / winPkts : 0.0;
                    double avgWait = winWaitCount > 0 ? (double)winWaitUs / winWaitCount : 0.0;
                    double lastSendUs = sender.LastFlushTransmittedBytes > 0 && sender.LastFlushMicros > 0 && wireSize > 0
                        ? sender.LastFlushMicros / (double)Math.Max(1, sender.LastFlushTransmittedBytes / wireSize)
                        : 0.0;
                    Logger.Info($"[ICMP-W0] pkts={winPkts} bytes={winBytes} " +
                                $"send_us_avg={lastSendUs:F1} enqueue_us_avg={avgEnq:F1} " +
                                $"bucket_wait_us_avg={avgWait:F1} waits={winWaitCount}");
                    winPkts = 0; winBytes = 0; winEnqueueUs = 0; winWaitUs = 0; winWaitCount = 0;
                    winSw.Restart();
                }

                try
                {
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        EmitWorkerWindowIfDue();
                        int count = scheduler.Drain(wireSize, drainMax);

                        if (count == 0)
                        {
                            long waitStart = Stopwatch.GetTimestamp();
                            if (tgtMbps < 5.0)
                            {
                                Thread.Sleep(1);
                                scheduler.RecordSleep();
                                Interlocked.Increment(ref sharedSleep);
                            }
                            else
                            {
                                Thread.SpinWait(200);
                                scheduler.RecordSpin();
                                Interlocked.Increment(ref sharedSpin);
                            }
                            long waitTicks = Stopwatch.GetTimestamp() - waitStart;
                            winWaitUs += waitTicks * 1_000_000L / Stopwatch.Frequency;
                            winWaitCount++;
                            scheduler.LogTelemetry(0, 1, targetBps,
                                tgtMbps < 5.0 ? "Sleep" : "SpinWait", 0);
                            continue;
                        }

                        long enqStart = Stopwatch.GetTimestamp();
                        for (int i = 0; i < count; i++)
                        {
                            sender.AddPacket(pool[idx].ToArray());
                            idx++;
                            if (idx >= pool.Length) idx = 0;
                        }
                        long enqTicks = Stopwatch.GetTimestamp() - enqStart;
                        winEnqueueUs += enqTicks * 1_000_000L / Stopwatch.Frequency;

                        for (int i = 0; i < count; i++) scheduler.RecordSent(wireSize);
                        Interlocked.Add(ref sharedBytes, (long)wireSize * count);
                        long running = Interlocked.Add(ref sharedPackets, count);
                        localSent += count;
                        winPkts += count;
                        winBytes += (long)wireSize * count;

                        if (count > 0 && ((running >> 10) != ((running - count) >> 10)))
                            OnPacketSent(pool[idx], _params.SourceIp, _params.DestinationIp, 0);
                    }
                }
                finally
                {
                    try { sender.Dispose(); }
                    catch (Exception ex) { Logger.Debug(ex, "[ICMP] sender dispose failed"); }
                }

                workerSw.Stop();
                Logger.Info($"Flood worker finished: id=0 sent={localSent} elapsed={workerSw.ElapsedMilliseconds}ms");
            }, _cancellationToken);

            await PublishStatsLoopAsync(
                "ICMP", targetBps, tgtMbps, schedulers,
                () => Interlocked.Read(ref sharedBytes),
                () => Interlocked.Read(ref sharedPackets),
                () => Interlocked.Read(ref sharedFailed),
                () => Interlocked.Read(ref sharedSpin),
                () => Interlocked.Read(ref sharedSleep));

            try { await sendTask; } catch (OperationCanceledException) { }

            Logger.Info($"[ICMP] Stopped. bytes={Interlocked.Read(ref sharedBytes):N0} " +
                        $"packets={Interlocked.Read(ref sharedPackets):N0} " +
                        $"failed={Interlocked.Read(ref sharedFailed):N0}");
        }

        private async Task PublishStatsLoopAsync(
            string protocol,
            long targetBps,
            double tgtMbps,
            FloodScheduler[] schedulers,
            Func<long> getBytes,
            Func<long> getPackets,
            Func<long> getFailed,
            Func<long> getSpin,
            Func<long> getSleep)
        {
            const double α1s  = 0.393;
            const double α5s  = 0.095;
            const double α10s = 0.049;
            double ema1s = 0, ema5s = 0, ema10s = 0;

            long freq = Stopwatch.Frequency;
            long windowStartTick  = Stopwatch.GetTimestamp();
            long windowStartBytes = 0;
            long runStartTick     = windowStartTick;

            try
            {
                while (!_cancellationToken.IsCancellationRequested)
                {
                    await Task.Delay(500, _cancellationToken);

                    long nowTick   = Stopwatch.GetTimestamp();
                    long bytesNow  = getBytes();
                    long pktNow    = getPackets();
                    long failNow   = getFailed();
                    long spinNow   = getSpin();
                    long sleepNow  = getSleep();

                    double windowSec = (nowTick - windowStartTick) / (double)freq;
                    if (windowSec <= 0) windowSec = 0.5;

                    long   wBytes   = bytesNow - windowStartBytes;
                    double wMbps    = wBytes * 8.0 / (windowSec * 1_000_000.0);

                    ema1s  = ema1s  == 0 ? wMbps : α1s  * wMbps + (1 - α1s)  * ema1s;
                    ema5s  = ema5s  == 0 ? wMbps : α5s  * wMbps + (1 - α5s)  * ema5s;
                    ema10s = ema10s == 0 ? wMbps : α10s * wMbps + (1 - α10s) * ema10s;

                    double elapsed = (nowTick - runStartTick) / (double)freq;
                    double actualMbps = elapsed > 0
                        ? bytesNow * 8.0 / (elapsed * 1_000_000.0)
                        : 0.0;
                    double vsPct = tgtMbps > 0 ? (actualMbps / tgtMbps) * 100.0 : 0.0;

                    string reason = FloodScheduler.InferReasonString(
                        targetBps, ema1s, pktNow, failNow, spinNow, sleepNow, elapsed);

                    var snap = new FloodSnapshot
                    {
                        TargetWireBytesPerSec       = targetBps,
                        ActualWireBytesPerSecShort  = (long)(ema1s * 125_000),
                        ActualWireBytesPerSecMedium = (long)(ema5s * 125_000),
                        PacketsAttempted            = pktNow,
                        PacketsSent                 = pktNow,
                        PacketsFailed               = failNow,
                        PacketsDropped              = 0,
                        WireBytesSent               = bytesNow,
                        SchedulerSleepCycles        = sleepNow,
                        SchedulerSpinCycles         = spinNow,
                        ElapsedSeconds              = elapsed,
                        Protocol                    = protocol,
                        LastReason                  = DiagnosticReason.None,
                        Confidence                  = DiagnosticConfidence.Medium,
                        IsCalibrating               = false,
                        ReasonString                = reason,
                        ActualMbps                  = actualMbps,
                        VsTargetPercent             = vsPct
                    };

                    foreach (var sch in schedulers)
                    {
                        sch.Mbps1s  = ema1s;
                        sch.Mbps5s  = ema5s;
                        sch.Mbps10s = ema10s;
                    }

                    OnStatsPublished(snap);
                    Logger.Info($"[{protocol}] target={tgtMbps:F2}  window={wMbps:F2}  " +
                                $"ema1s={ema1s:F2}  actual={actualMbps:F2}  " +
                                $"pkts={pktNow:N0}  fail={failNow}  reason={reason}");

                    windowStartTick  = nowTick;
                    windowStartBytes = bytesNow;
                }
            }
            catch (OperationCanceledException) {  }
        }

        public void Dispose() => _device?.Close();

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
}
