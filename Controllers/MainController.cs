using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;
using Dorothy.Models;
using System.Windows;
using System.Text.RegularExpressions;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace Dorothy.Controllers
{
    public class MainController
    {
        private readonly NetworkStorm _networkStorm;
        private readonly Button _startButton;
        private readonly Button _stopButton;
        private readonly Label _statusLabel;
        private readonly TextBox _logTextBox;
        private readonly Window _mainWindow;
        private readonly ILogger _logger;
        private ArpSpoof? _arpSpoofer;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(Int32 destIp, Int32 srcIp, byte[] macAddr, ref uint macAddrLen);

        public MainController(NetworkStorm networkStorm, Button startButton, Button stopButton, Label statusLabel, TextBox logTextBox, Window mainWindow)
        {
            _networkStorm = networkStorm;
            _startButton = startButton;
            _stopButton = stopButton;
            _statusLabel = statusLabel;
            _logTextBox = logTextBox;
            _mainWindow = mainWindow;
            _logger = LogManager.GetCurrentClassLogger();
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            try
            {
                _startButton.IsEnabled = false;
                _stopButton.IsEnabled = true;
                _statusLabel.Content = "Status: Attacking";

                await _networkStorm.StartAttackAsync(attackType, targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Attack failed.");
                Log($"Attack failed: {ex.Message}");
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Idle";
            }
        }

        public async Task StopAttackAsync()
        {
            try
            {
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Stopping...";

                await _networkStorm.StopAttackAsync();
                _startButton.IsEnabled = true;
                _statusLabel.Content = "Status: Ready";
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to stop attack.");
                Log($"Failed to stop attack: {ex.Message}");
                _stopButton.IsEnabled = false;
                _startButton.IsEnabled = true;
                _statusLabel.Content = "Status: Idle";
            }
        }

        public void Log(string message)
        {
            _logTextBox.Dispatcher.Invoke(() =>
            {
                _logTextBox.AppendText(message + Environment.NewLine);
                _logTextBox.ScrollToEnd();
            });
        }

        public async Task<string> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                var destIp = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);
                var srcIp = 0;
                var macAddr = new byte[6];
                var macAddrLen = (uint)macAddr.Length;

                var result = SendARP(destIp, srcIp, macAddr, ref macAddrLen);
                if (result != 0)
                {
                    throw new Exception($"Failed to get MAC address. Error code: {result}");
                }

                return BitConverter.ToString(macAddr, 0, (int)macAddrLen).Replace("-", ":");
            }
            catch (Exception ex)
            {
                Log($"Error retrieving MAC address: {ex.Message}");
                _logger.Error(ex, "Error retrieving MAC address.");
                return "Error";
            }
        }

        public async Task<PingResult> PingHostAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress);
                return new PingResult
                {
                    Success = reply.Status == IPStatus.Success,
                    RoundtripTime = reply.RoundtripTime
                };
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Failed to ping {ipAddress}");
                return new PingResult { Success = false };
            }
        }

        public async Task ApplyAdvancedSettingsAsync(string additionalAttackType, bool enableLogging, string customParameters)
        {
            try
            {
                // Implement advanced settings logic here
                Log($"Advanced Settings Applied: Additional Attack Type - {additionalAttackType}, Custom Parameters - {customParameters}");
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to apply advanced settings.");
                throw;
            }
        }

        public async Task StartArpSpoofingAsync(string sourceIp, string sourceMac, string targetIp, string targetMac, string spoofedMac)
        {
            try
            {
                _logger.Info($"Starting ARP spoofing attack: {sourceIp} -> {targetIp}");
                
                byte[] sourceMacBytes = ParseMacAddress(sourceMac);
                byte[] targetMacBytes = ParseMacAddress(targetMac);
                byte[] spoofedMacBytes = ParseMacAddress(spoofedMac);

                var cancellationTokenSource = new CancellationTokenSource();
                _arpSpoofer = new ArpSpoof(sourceIp, sourceMacBytes, targetIp, targetMacBytes, spoofedMacBytes, cancellationTokenSource.Token);
                await Task.Run(() => _arpSpoofer.StartAsync());
                
                _statusLabel.Content = "Status: ARP Spoofing Active";
                LogMessage("ARP spoofing attack started successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to start ARP spoofing");
                throw;
            }
        }

        public async Task StopArpSpoofingAsync()
        {
            try
            {
                _statusLabel.Content = "Status: Stopping...";
                
                _arpSpoofer?.Dispose();
                _arpSpoofer = null;
                
                _statusLabel.Content = "Status: Ready";
                LogMessage("ARP spoofing attack stopped");
                
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to stop ARP spoofing");
                throw;
            }
        }

        private void LogMessage(string message)
        {
            _logTextBox.Dispatcher.Invoke(() =>
            {
                _logTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
                _logTextBox.ScrollToEnd();
            });
        }

        private byte[] ParseMacAddress(string macAddress)
        {
            // Remove any colons or hyphens and ensure uppercase
            string cleanMac = macAddress.Replace(":", "").Replace("-", "").ToUpper();
            
            if (cleanMac.Length != 12)
            {
                throw new FormatException("Invalid MAC address length");
            }

            byte[] bytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                string byteStr = cleanMac.Substring(i * 2, 2);
                bytes[i] = Convert.ToByte(byteStr, 16);
            }
            
            return bytes;
        }

        public async Task StartBroadcastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            try
            {
                _logger.Info($"Starting Broadcast attack: Target={targetIp}:{targetPort}, Rate={megabitsPerSecond}Mbps");
                await _networkStorm.StartBroadcastAttackAsync(targetIp, targetPort, megabitsPerSecond);
                _statusLabel.Content = "Status: Broadcast Attack Active";
                Log("Broadcast attack started successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to start broadcast attack");
                throw;
            }
        }

        public async Task StartMulticastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            try
            {
                _logger.Info($"Starting Multicast attack: Target={targetIp}:{targetPort}, Rate={megabitsPerSecond}Mbps");
                await _networkStorm.StartMulticastAttackAsync(targetIp, targetPort, megabitsPerSecond);
                _statusLabel.Content = "Status: Multicast Attack Active";
                Log("Multicast attack started successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to start multicast attack");
                throw;
            }
        }

        public async Task StopBroadcastAttackAsync()
        {
            try
            {
                await _networkStorm.StopAttackAsync();
                _statusLabel.Content = "Status: Ready";
                Log("Broadcast attack stopped");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to stop broadcast attack");
                throw;
            }
        }

        public async Task StopMulticastAttackAsync()
        {
            try
            {
                await _networkStorm.StopAttackAsync();
                _statusLabel.Content = "Status: Ready";
                Log("Multicast attack stopped");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to stop multicast attack");
                throw;
            }
        }
    }

    public class PingResult
    {
        public bool Success { get; set; }
        public long RoundtripTime { get; set; }
    }
} 