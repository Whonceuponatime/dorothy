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
    }

    public class PingResult
    {
        public bool Success { get; set; }
        public long RoundtripTime { get; set; }
    }
} 