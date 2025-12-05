using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Avalonia.Controls;
using NLog;
using Dorothy.Models;
using Avalonia;
using System.Text.RegularExpressions;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Avalonia.Media;
using Avalonia.Controls.Shapes;
using System.Collections.Generic;
using System.Net.Sockets;  // For AddressFamily
using System.Diagnostics;
using Avalonia.Threading;

namespace Dorothy.Controllers
{
    public class MainController
    {
        private readonly NetworkStorm _networkStorm;
        private readonly Button _startButton;
        private readonly Button _stopButton;
        private readonly Border _statusBadge;
        private readonly TextBlock _statusBadgeText;
        private readonly Ellipse _statusDot;
        private readonly TextBox _logTextBox;
        private readonly Window _mainWindow;
        private readonly ILogger _logger;
        private readonly AttackLogger _attackLogger;
        private ArpSpoof? _arpSpoofer;
        private CancellationTokenSource? _arpSpoofingCts;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(Int32 destIp, Int32 srcIp, byte[] macAddr, ref uint macAddrLen);

        public MainController(NetworkStorm networkStorm, Button startButton, Button stopButton, Border statusBadge, TextBlock statusBadgeText, Ellipse statusDot, TextBox logTextBox, Window mainWindow)
        {
            _networkStorm = networkStorm ?? throw new ArgumentNullException(nameof(networkStorm));
            _startButton = startButton ?? throw new ArgumentNullException(nameof(startButton));
            _stopButton = stopButton ?? throw new ArgumentNullException(nameof(stopButton));
            _statusBadge = statusBadge ?? throw new ArgumentNullException(nameof(statusBadge));
            _statusBadgeText = statusBadgeText ?? throw new ArgumentNullException(nameof(statusBadgeText));
            _statusDot = statusDot ?? throw new ArgumentNullException(nameof(statusDot));
            _logTextBox = logTextBox ?? throw new ArgumentNullException(nameof(logTextBox));
            _mainWindow = mainWindow ?? throw new ArgumentNullException(nameof(mainWindow));
            _logger = LogManager.GetCurrentClassLogger();
            _attackLogger = networkStorm.Logger;
        }

        private void UpdateStatusBadge(string status, string statusType)
        {
            _ = Dispatcher.UIThread.InvokeAsync(() =>
            {
                _statusBadgeText.Text = status;
                
                // Update badge style and color based on status type
                switch (statusType.ToLower())
                {
                    case "ready":
                    case "idle":
                        _statusBadge.Background = new SolidColorBrush(Color.Parse("#D1FAE5"));
                        _statusBadgeText.Foreground = new SolidColorBrush(Color.Parse("#059669"));
                        _statusDot.Fill = new SolidColorBrush(Color.Parse("#059669"));
                        break;
                    case "attacking":
                    case "running":
                    case "active":
                        _statusBadge.Background = new SolidColorBrush(Color.Parse("#FEE2E2"));
                        _statusBadgeText.Foreground = new SolidColorBrush(Color.Parse("#E45757"));
                        _statusDot.Fill = new SolidColorBrush(Color.Parse("#E45757"));
                        break;
                    case "error":
                        _statusBadge.Background = new SolidColorBrush(Color.Parse("#FEE2E2"));
                        _statusBadgeText.Foreground = new SolidColorBrush(Color.Parse("#E45757"));
                        _statusDot.Fill = new SolidColorBrush(Color.Parse("#E45757"));
                        break;
                    default:
                        _statusBadge.Background = new SolidColorBrush(Color.Parse("#D1FAE5"));
                        _statusBadgeText.Foreground = new SolidColorBrush(Color.Parse("#059669"));
                        _statusDot.Fill = new SolidColorBrush(Color.Parse("#059669"));
                        break;
                }
            });
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            try
            {
                _startButton.IsEnabled = false;
                _stopButton.IsEnabled = true;
                UpdateStatusBadge("Attacking", "attacking");

                await _networkStorm.StartAttackAsync(attackType, targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Attack failed.");
                _attackLogger.LogError($"Attack failed: {ex.Message}");
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                UpdateStatusBadge("Error", "error");
            }
        }

        public async Task StopAttackAsync(long packetsSent = 0)
        {
            try
            {
                await _networkStorm.StopAttackAsync(packetsSent);
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                UpdateStatusBadge("Ready", "ready");
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
                if (string.IsNullOrWhiteSpace(ipAddress))
                {
                    return Array.Empty<byte>();
                }

                var arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                // If no ARP entry found, try to ping the IP to populate ARP cache
                // Only ping if it's likely to help (same subnet or gateway)
                var pingResult = await SendPingAsync(ipAddress);
                if (pingResult)
                {
                arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                    }
                }

                // Return empty array instead of throwing - let caller handle gracefully
                _logger.Info($"Could not resolve MAC address for {ipAddress} - ARP entry not found");
                return Array.Empty<byte>();
            }
            catch (Exception ex)
            {
                _logger.Warn(ex, $"Failed to get MAC address for {ipAddress} - returning empty array");
                return Array.Empty<byte>();
            }
        }

        private byte[] ParseMacAddress(string macAddress)
        {
            // Remove any colons or hyphens and convert to bytes
            string cleanMac = macAddress.Replace(":", "").Replace("-", "");
            if (cleanMac.Length != 12)
            {
                throw new ArgumentException("Invalid MAC address format");
            }

            byte[] macBytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                macBytes[i] = Convert.ToByte(cleanMac.Substring(i * 2, 2), 16);
            }
            return macBytes;
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

        private async Task<bool> SendPingAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, 1000);
                return reply.Status == IPStatus.Success;
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, $"Ping to {ipAddress} failed");
                return false;
            }
        }

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2, byte[] subnetMask)
        {
            byte[] subnet = subnetMask ?? new byte[] { 255, 255, 255, 0 }; // Default subnet mask
            byte[] bytes1 = ip1.GetAddressBytes();
            byte[] bytes2 = ip2.GetAddressBytes();
            
            for (int i = 0; i < 4; i++)
            {
                if ((bytes1[i] & subnet[i]) != (bytes2[i] & subnet[i]))
                    return false;
            }
            return true;
        }

        public byte[] GetSubnetMaskFromInterface(NetworkInterface nic)
        {
            try
            {
                var ipProps = nic.GetIPProperties();
                var unicastInfo = ipProps.UnicastAddresses
                    .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                if (unicastInfo?.IPv4Mask != null)
                {
                    return unicastInfo.IPv4Mask.GetAddressBytes();
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get subnet mask from interface");
            }
            return new byte[] { 255, 255, 255, 0 }; // Default fallback
        }

        public IPAddress? GetDefaultGateway()
        {
            var gateway = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

            return gateway;
        }

        public IPAddress? GetGatewayForInterface(NetworkInterface nic)
        {
            try
            {
                if (nic == null) return null;
                
                var gateway = nic.GetIPProperties()?.GatewayAddresses
                    .Select(g => g?.Address)
                    .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                return gateway;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to get gateway for interface");
                return null;
            }
        }

        public IPAddress? CalculateDefaultGateway(string sourceIp)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sourceIp) || !IPAddress.TryParse(sourceIp, out var sourceIpAddress))
                {
                    return null;
                }

                var bytes = sourceIpAddress.GetAddressBytes();
                bytes[3] = 1; // Set last octet to 1 (x.x.x.x.1)
                return new IPAddress(bytes);
            }
            catch
            {
                return null;
            }
        }

        public IPAddress? GetDefaultGatewayWithFallback(string sourceIp)
        {
            // Try to get system default gateway first
            var systemGateway = GetDefaultGateway();
            if (systemGateway != null)
            {
                return systemGateway;
            }

            // Fallback to calculated default (x.x.x.x.1)
            return CalculateDefaultGateway(sourceIp);
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
                _startButton.IsEnabled = false;
                _stopButton.IsEnabled = true;
                UpdateStatusBadge("ARP Spoofing", "attacking");

                // Convert MAC addresses from string format (XX:XX:XX:XX:XX:XX) to byte arrays
                byte[] sourceMacBytes = ParseMacAddress(sourceMac);
                byte[] targetMacBytes = ParseMacAddress(targetMac);
                byte[] spoofedMacBytes = ParseMacAddress(spoofedMac);

                _arpSpoofingCts = new CancellationTokenSource();
                _arpSpoofer = new ArpSpoof(sourceIp, sourceMacBytes, targetIp, targetMacBytes, spoofedMacBytes, _arpSpoofingCts.Token);
                await _arpSpoofer.StartAsync();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "ARP Spoofing failed.");
                _attackLogger.LogError($"ARP Spoofing failed: {ex.Message}");
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                UpdateStatusBadge("Error", "error");
                throw;
            }
        }

        public async Task StopArpSpoofingAsync(long packetsSent = 0)
        {
            try
            {
                if (_arpSpoofer != null)
                {
                    _arpSpoofingCts?.Cancel();
                    _arpSpoofer.Dispose();
                    _arpSpoofer = null;
                }
                _attackLogger.StopAttack(packetsSent);
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                UpdateStatusBadge("Ready", "ready");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error stopping ARP Spoofing");
                _attackLogger.LogError($"Error stopping ARP Spoofing: {ex.Message}");
                throw;
            }
        }

        private void LogMessage(string message)
        {
            _ = Dispatcher.UIThread.InvokeAsync(() =>
            {
                _logTextBox.Text += $"{message}{Environment.NewLine}";
                // Scroll to end - Avalonia TextBox doesn't have ScrollToEnd, need to use ScrollViewer
                if (_logTextBox.Parent is ScrollViewer scrollViewer)
                {
                    scrollViewer.Offset = new Vector(scrollViewer.Offset.X, scrollViewer.Extent.Height);
                }
            });
        }

        public async Task StartBroadcastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            try
            {
                _logger.Info($"Starting Broadcast attack: Target={targetIp}:{targetPort}, Rate={megabitsPerSecond}Mbps");
                await _networkStorm.StartBroadcastAttackAsync(targetIp, targetPort, megabitsPerSecond);
                UpdateStatusBadge("Broadcast Active", "attacking");
                Log("Broadcast attack started successfully");
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to start broadcast attack");
                throw;
            }
        }

        public async Task StopBroadcastAttackAsync(long packetsSent = 0)
        {
            try
            {
                await _networkStorm.StopAttackAsync(packetsSent);
                UpdateStatusBadge("Ready", "ready");
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