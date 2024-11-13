using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Models;
using NLog;

namespace Dorothy.Controllers
{
    public class MainController
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly NetworkStorm _networkStorm;
        private readonly Button _startButton;
        private readonly Button _stopButton;
        private readonly Label _statusLabel;
        private readonly TextBox _logArea;
        private readonly Window _mainWindow;

        public MainController(
            NetworkStorm networkStorm,
            Button startButton,
            Button stopButton,
            Label statusLabel,
            TextBox logArea,
            Window mainWindow)
        {
            _networkStorm = networkStorm ?? throw new ArgumentNullException(nameof(networkStorm));
            _startButton = startButton ?? throw new ArgumentNullException(nameof(startButton));
            _stopButton = stopButton ?? throw new ArgumentNullException(nameof(stopButton));
            _statusLabel = statusLabel ?? throw new ArgumentNullException(nameof(statusLabel));
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _mainWindow = mainWindow ?? throw new ArgumentNullException(nameof(mainWindow));
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            if (_networkStorm.IsAttackRunning)
            {
                Log("Attack already in progress.");
                return;
            }

            _startButton.IsEnabled = false;
            _stopButton.IsEnabled = true;
            _statusLabel.Content = "Status: Attacking";

            try
            {
                await _networkStorm.StartAttackAsync(attackType, targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Attack failed to start.");
                Log($"Attack failed to start: {ex.Message}");
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Idle";
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_networkStorm.IsAttackRunning)
            {
                Log("No attack is running.");
                return;
            }

            _stopButton.IsEnabled = false;
            _statusLabel.Content = "Status: Stopping...";

            await _networkStorm.StopAttackAsync();

            _startButton.IsEnabled = true;
            _statusLabel.Content = "Status: Idle";
            Log("Attack has been stopped.");
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
                    .FirstOrDefault(addr => addr.Address.AddressFamily == AddressFamily.InterNetwork);

                if (unicastAddr == null)
                {
                    Log($"No IPv4 address found for interface '{interfaceName}'.");
                    return;
                }

                _networkStorm.SetSourceIp(unicastAddr.Address.ToString());
                _networkStorm.SetSourceMac(networkInterface.GetPhysicalAddress().GetAddressBytes());

                Log($"Updated network interface to '{interfaceName}' with IP {unicastAddr.Address} and MAC {BytesToMacString(networkInterface.GetPhysicalAddress().GetAddressBytes())}.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error updating network interface.");
                Log($"Error updating network interface: {ex.Message}");
            }

            await Task.CompletedTask;
        }

        private void Log(string message)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var logMessage = $"[{timestamp}] {message}\n";

                _logArea.Dispatcher.Invoke(() => _logArea.AppendText(logMessage));
                _logArea.Dispatcher.Invoke(() => _logArea.ScrollToEnd());

                Logger.Debug(message);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Logging failed.");
            }
        }

        private string BytesToMacString(byte[] macBytes)
        {
            return string.Join(":", macBytes.Select(b => b.ToString("X2")));
        }
    }
} 