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
using System.Windows.Media;
using System.Collections.Generic;
using System.Net.Sockets;  // For AddressFamily
using System.Net.NetworkInformation;
using System.Diagnostics;

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
        private readonly AttackLogger _attackLogger;
        private ArpSpoof? _arpSpoofer;
        private CancellationTokenSource? _arpSpoofingCts;

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
            _attackLogger = new AttackLogger(logTextBox);
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
                _attackLogger.LogError($"Attack failed: {ex.Message}");
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Error";
            }
        }

        public async Task StopAttackAsync()
        {
            try
            {
                await _networkStorm.StopAttackAsync();
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Ready";
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error stopping attack");
                _attackLogger.LogError($"Error stopping attack: {ex.Message}");
                throw;
            }
        }

        public void Log(string message)
        {
            _attackLogger.LogInfo(message);
        }

        public async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                var arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                // If no ARP entry found, try to ping the IP to populate ARP cache
                await SendPingAsync(ipAddress);
                arpEntry = await GetArpEntryAsync(ipAddress);
                
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                throw new Exception($"Could not resolve MAC address for {ipAddress}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, $"Failed to get MAC address for {ipAddress}");
                throw;
            }
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

        private async Task<string> GetArpEntryAsync(string ipAddress)
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = $"-a {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                var match = Regex.Match(output, @"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", RegexOptions.IgnoreCase);
                return match.Success ? match.Value : null;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get ARP entry");
                return null;
            }
        }

        private async Task SendPingAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                await ping.SendPingAsync(ipAddress, 1000);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to send ping");
            }
        }

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2)
        {
            byte[] subnet = new byte[] { 255, 255, 255, 0 }; // Default subnet mask
            byte[] bytes1 = ip1.GetAddressBytes();
            byte[] bytes2 = ip2.GetAddressBytes();
            
            for (int i = 0; i < 4; i++)
            {
                if ((bytes1[i] & subnet[i]) != (bytes2[i] & subnet[i]))
                    return false;
            }
            return true;
        }

        private IPAddress? GetDefaultGateway()
        {
            var gateway = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            return gateway ?? throw new Exception("No default gateway found");
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
                _logger.Info("=== Starting ARP Spoofing Attack ===");
                _logger.Info($"Validating inputs:");
                _logger.Info($"Source IP: {sourceIp}, Source MAC: {sourceMac}");
                _logger.Info($"Target IP: {targetIp}, Target MAC: {targetMac}");
                _logger.Info($"SpoofedMAC: {spoofedMac}");

                // Validate all inputs
                if (string.IsNullOrWhiteSpace(sourceIp) || string.IsNullOrWhiteSpace(sourceMac) ||
                    string.IsNullOrWhiteSpace(targetIp) || string.IsNullOrWhiteSpace(targetMac) ||
                    string.IsNullOrWhiteSpace(spoofedMac))
                {
                    var missingFields = new List<string>();
                    if (string.IsNullOrWhiteSpace(sourceIp)) missingFields.Add("Source IP");
                    if (string.IsNullOrWhiteSpace(sourceMac)) missingFields.Add("Source MAC");
                    if (string.IsNullOrWhiteSpace(targetIp)) missingFields.Add("Target IP");
                    if (string.IsNullOrWhiteSpace(targetMac)) missingFields.Add("Target MAC");
                    if (string.IsNullOrWhiteSpace(spoofedMac)) missingFields.Add("Spoofed MAC");

                    var errorMessage = $"Missing required fields: {string.Join(", ", missingFields)}";
                    _logger.Error(errorMessage);
                    LogMessage(errorMessage);
                    throw new ArgumentException(errorMessage);
                }

                byte[] sourceMacBytes = ParseMacAddress(sourceMac);
                byte[] targetMacBytes = ParseMacAddress(targetMac);
                byte[] spoofedMacBytes = ParseMacAddress(spoofedMac);

                _arpSpoofer = new ArpSpoof(sourceIp, sourceMacBytes, targetIp, targetMacBytes, spoofedMacBytes, CancellationToken.None);
                
                _statusLabel.Content = "Status: Starting ARP Spoofing...";
                LogMessage("Initializing ARP spoofing attack...");
                
                await _arpSpoofer.StartAsync();
                
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: ARP Spoofing Complete";
                LogMessage("ARP spoofing attack completed successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to start ARP spoofing");
                _statusLabel.Content = "Status: Error";
                LogMessage($"Failed to start ARP spoofing: {ex.Message}");
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                throw;
            }
        }

        public async Task StopArpSpoofingAsync()
        {
            try
            {
                _statusLabel.Content = "Status: Stopping...";
                LogMessage("Stopping ARP spoofing attack...");

                if (_arpSpoofer != null)
                {
                    await Task.Run(() => {
                        _arpSpoofer.Dispose();
                        _arpSpoofer = null;
                    });
                }

                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Ready";
                LogMessage("ARP spoofing attack stopped");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to stop ARP spoofing");
                _statusLabel.Content = "Status: Error";
                LogMessage($"Failed to stop ARP spoofing: {ex.Message}");
                throw;
            }
        }

        private void LogMessage(string message)
        {
            _logTextBox.Dispatcher.Invoke(() =>
            {
                _logTextBox.AppendText($"{message}{Environment.NewLine}");
                _logTextBox.ScrollToEnd();
            });
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

        public async Task<byte[]> GetLocalMacAddressAsync()
        {
            try
            {
                var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.OperationalStatus == OperationalStatus.Up && 
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                if (networkInterface == null)
                {
                    throw new Exception("No active network interface found");
                }

                return networkInterface.GetPhysicalAddress().GetAddressBytes();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get local MAC address");
                throw;
            }
        }

        public async Task<string> GetLocalIpAddressAsync()
        {
            try
            {
                var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.OperationalStatus == OperationalStatus.Up && 
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback);

                if (networkInterface == null)
                {
                    throw new Exception("No active network interface found");
                }

                var ipProperties = networkInterface.GetIPProperties();
                var ipAddress = ipProperties.UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

                return ipAddress?.Address.ToString() ?? throw new Exception("No IPv4 address found");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get local IP address");
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