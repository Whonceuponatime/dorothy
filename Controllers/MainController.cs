using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;
using Dorothy.Models;
using System.Windows;

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

        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public MainController(NetworkStorm networkStorm, Button startButton, Button stopButton, Label statusLabel, TextBox logTextBox, Window mainWindow)
        {
            _networkStorm = networkStorm;
            _startButton = startButton;
            _stopButton = stopButton;
            _statusLabel = statusLabel;
            _logTextBox = logTextBox;
            _mainWindow = mainWindow;
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
                Logger.Error(ex, "Attack failed.");
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
                _statusLabel.Content = "Status: Idle";
                Log("Attack has been stopped.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error stopping attack.");
                Log($"Error stopping attack: {ex.Message}");
                _stopButton.IsEnabled = true;
                _statusLabel.Content = "Status: Idle";
            }
        }

        public async Task UpdateNetworkInterface(string interfaceName)
        {
            try
            {
                var networkInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

                if (networkInterface == null)
                {
                    Log($"No network interface found with name {interfaceName}.");
                    return;
                }

                var unicastAddr = networkInterface.GetIPProperties().UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                if (unicastAddr == null)
                {
                    Log($"No IPv4 address found for interface '{interfaceName}'.");
                    return;
                }

                string newIp = unicastAddr.Address.ToString();
                byte[] newMac = networkInterface.GetPhysicalAddress().GetAddressBytes();

                if (_networkStorm.SourceIp != newIp || !_networkStorm.SourceMac.SequenceEqual(newMac))
                {
                    _networkStorm.SetSourceIp(newIp);
                    _networkStorm.SetSourceMac(newMac);
                    Log($"Updated network interface to '{interfaceName}' with IP {newIp} and MAC {BytesToMacString(newMac)}.");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error updating network interface.");
                Log($"Error updating network interface: {ex.Message}");
            }
        }

        public void Log(string message)
        {
            _networkStorm.Log(message);
        }

        private string BytesToMacString(byte[] macBytes)
        {
            return string.Join(":", macBytes.Select(b => b.ToString("X2")));
        }
    }
} 