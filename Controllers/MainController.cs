using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Models;
using Dorothy.Views;
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
        private readonly MainWindow _mainWindow;

        public MainController(
            NetworkStorm networkStorm,
            Button startButton,
            Button stopButton,
            Label statusLabel,
            TextBox logArea,
            MainWindow mainWindow)
        {
            _networkStorm = networkStorm ?? throw new ArgumentNullException(nameof(networkStorm));
            _startButton = startButton ?? throw new ArgumentNullException(nameof(startButton));
            _stopButton = stopButton ?? throw new ArgumentNullException(nameof(stopButton));
            _statusLabel = statusLabel ?? throw new ArgumentNullException(nameof(statusLabel));
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _mainWindow = mainWindow ?? throw new ArgumentNullException(nameof(mainWindow));
        }

        public async Task StartAttackAsync(string attackType, string targetIp, int targetPort, long megabitsPerSecond)
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
                Log($"Started {attackType} attack on {targetIp}:{targetPort} at {megabitsPerSecond} Mbps.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error starting attack.");
                Log($"Error starting attack: {ex.Message}");
            }
            finally
            {
                _startButton.IsEnabled = true;
                _stopButton.IsEnabled = false;
                _statusLabel.Content = "Status: Ready";
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
            _startButton.IsEnabled = true;
            _statusLabel.Content = "Status: Stopping...";

            try
            {
                await _networkStorm.StopAttackAsync();
                Log("Attack stopped.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error stopping attack.");
                Log($"Error stopping attack: {ex.Message}");
            }
            finally
            {
                _statusLabel.Content = "Status: Ready";
            }
        }

        public void UpdateNetworkInterface(string interfaceName)
        {
            try
            {
                var networkInterface = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

                if (networkInterface != null)
                {
                    var ipProps = networkInterface.GetIPProperties();
                    var ipv4Addr = ipProps.UnicastAddresses
                        .FirstOrDefault(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                    if (ipv4Addr != null)
                    {
                        _mainWindow.SetSourceIp(ipv4Addr.Address.ToString());
                    }

                    System.Net.NetworkInformation.PhysicalAddress mac = networkInterface.GetPhysicalAddress();
                    _mainWindow.SetSourceMac(mac.GetAddressBytes());
                }
                else
                {
                    Log($"Network interface '{interfaceName}' not found.");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error updating network interface.");
                Log($"Error updating network interface: {ex.Message}");
            }
        }

        private void Log(string message)
        {
            try
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var logMessage = $"[{timestamp}] {message}\n";

                Application.Current.Dispatcher.Invoke(() =>
                {
                    _logArea.AppendText(logMessage);
                    _logArea.ScrollToEnd();
                });

                Logger.Debug(message);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Logging error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
} 