using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Linq;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Services;

namespace Dorothy.Models
{

    public class UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public event EventHandler<PacketEventArgs>? PacketSent;
        public event EventHandler<Dorothy.Services.FloodSnapshot>? StatsPublished;

        public bool DryRunMode { get; set; } = false;

        public UdpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp,
            IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        protected virtual void OnStatsPublished(Dorothy.Services.FloodSnapshot snapshot)
            => StatsPublished?.Invoke(this, snapshot);

        public async Task StartAsync()
        {
            Logger.Info(DryRunMode ? "[UDP] DRY-RUN — validate pool only, no transmit."
                                   : "[UDP] Starting flood.");
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
                const int payloadSize = 1400;
                const int poolSize    = 512;

                var eth = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ip  = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol   = PacketDotNet.ProtocolType.Udp,
                    TimeToLive = _params.Ttl
                };
                var udp = new UdpPacket(
                    (ushort)_params.SourcePort,
                    (ushort)_params.DestinationPort)
                {
                    PayloadData = new byte[payloadSize]
                };
                ip.PayloadPacket  = udp;
                eth.PayloadPacket = ip;

                var pool = new byte[poolSize][];
                for (int i = 0; i < poolSize; i++)
                {
                    random.NextBytes(udp.PayloadData);
                    udp.SourcePort = (ushort)random.Next(1024, 65535);
                    ip.Id          = (ushort)random.Next(0, 65536);
                    udp.UpdateCalculatedValues();
                    ip.UpdateCalculatedValues();
                    pool[i] = eth.Bytes;
                }

                int  wireSize  = pool[0].Length + 4;
                long targetBps = _params.BytesPerSecond;
                double tgtMbps = targetBps * 8.0 / 1_000_000;

                Logger.Info($"[UDP] frame={pool[0].Length}B  wire={wireSize}B  " +
                            $"target={tgtMbps:F2} Mbps  pool={poolSize}");

                if (DryRunMode)
                {
                    var (valid, invalid) = PacketValidator.ValidatePoolFull(pool, "UDP");
                    Logger.Info($"[UDP] DRY-RUN complete — {valid}/{poolSize} valid, " +
                                $"{invalid} invalid. No packets transmitted.");
                    return;
                }

                await RunParallelSendLoopAsync(pool, wireSize, targetBps, tgtMbps);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "[UDP] Flood failed.");
                throw;
            }
            finally
            {
                _device?.Close();
            }
        }

        private async Task RunParallelSendLoopAsync(
            byte[][] pool, int wireSize, long targetBps, double tgtMbps)
        {
            int workerCount = Math.Min(Environment.ProcessorCount, 4);
            if (workerCount < 1) workerCount = 1;

            long perWorkerBps = Math.Max(1, targetBps / workerCount);
            int sliceLen = pool.Length / workerCount;
            if (sliceLen < 1) { workerCount = 1; sliceLen = pool.Length; }

            int drainMax = tgtMbps > 500 ? 200 : tgtMbps > 100 ? 100 : tgtMbps > 10 ? 40 : 10;

            long sharedBytes   = 0;
            long sharedPackets = 0;
            long sharedFailed  = 0;
            long sharedSpin    = 0;
            long sharedSleep   = 0;

            var schedulers = new FloodScheduler[workerCount];
            var workerTasks = new Task[workerCount];

            Logger.Info($"[UDP] Launching {workerCount} worker(s) at {perWorkerBps * 8.0 / 1_000_000:F2} Mbps each.");

            for (int w = 0; w < workerCount; w++)
            {
                int workerId  = w;
                int startIdx  = workerId * sliceLen;
                int endIdx    = (workerId == workerCount - 1) ? pool.Length : startIdx + sliceLen;

                schedulers[workerId] = new FloodScheduler(perWorkerBps);
                var localScheduler   = schedulers[workerId];

                workerTasks[w] = Task.Run(() =>
                {
                    int idx = startIdx;
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        int count = localScheduler.Drain(wireSize, drainMax);

                        if (count == 0)
                        {

                            if (tgtMbps < 5.0)
                            {
                                Thread.Sleep(1);
                                localScheduler.RecordSleep();
                                Interlocked.Increment(ref sharedSleep);
                            }
                            else
                            {
                                Thread.SpinWait(200);
                                localScheduler.RecordSpin();
                                Interlocked.Increment(ref sharedSpin);
                            }
                            continue;
                        }

                        for (int i = 0; i < count; i++)
                        {
                            try
                            {
                                _device!.SendPacket(pool[idx]);
                                localScheduler.RecordSent(wireSize);
                                Interlocked.Add(ref sharedBytes, wireSize);
                                Interlocked.Increment(ref sharedPackets);

                                if ((Interlocked.Read(ref sharedPackets) & 1023) == 0)
                                    OnPacketSent(pool[idx],
                                        _params.SourceIp, _params.DestinationIp,
                                        _params.DestinationPort);
                            }
                            catch (Exception ex)
                            {
                                localScheduler.RecordFailed();
                                Interlocked.Increment(ref sharedFailed);
                                if ((Interlocked.Read(ref sharedFailed) & 63) == 0)
                                    Logger.Warn($"[UDP] SendPacket failed: {ex.Message}");
                            }

                            idx++;
                            if (idx >= endIdx) idx = startIdx;
                        }
                    }
                }, _cancellationToken);
            }

            await PublishStatsLoopAsync(
                "UDP", targetBps, tgtMbps, schedulers,
                () => Interlocked.Read(ref sharedBytes),
                () => Interlocked.Read(ref sharedPackets),
                () => Interlocked.Read(ref sharedFailed),
                () => Interlocked.Read(ref sharedSpin),
                () => Interlocked.Read(ref sharedSleep));

            try { await Task.WhenAll(workerTasks); } catch (OperationCanceledException) { }

            Logger.Info($"[UDP] Stopped. bytes={Interlocked.Read(ref sharedBytes):N0} " +
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
    }
}
