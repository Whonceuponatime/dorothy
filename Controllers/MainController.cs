using System;
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

        public MainController(
            NetworkStorm networkStorm,
            Button startButton,
            Button stopButton,
            Label statusLabel,
            TextBox logArea)
        {
            _networkStorm = networkStorm;
            _startButton = startButton;
            _stopButton = stopButton;
            _statusLabel = statusLabel;
            _logArea = logArea;
            
            _networkStorm.SetLogArea(_logArea);
        }

        public async Task StartAttackAsync(string attackType, string targetIp, int targetPort, long targetBytesPerSecond)
        {
            if (_networkStorm.IsAttackRunning)
            {
                Log("Attack already in progress");
                return;
            }

            try
            {
                switch (attackType)
                {
                    case "UDP Flood":
                        await _networkStorm.StartUdpFloodAsync(targetIp, targetPort, targetBytesPerSecond);
                        break;
                    case "ICMP Flood":
                        await _networkStorm.StartIcmpFloodAsync(targetIp, targetBytesPerSecond);
                        break;
                    default:
                        Log($"Unknown attack type selected: {attackType}");
                        return;
                }

                Application.Current.Dispatcher.Invoke(() =>
                {
                    _startButton.IsEnabled = false;
                    _stopButton.IsEnabled = true;
                    _statusLabel.Content = "Status: Attack Started";
                });
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error starting attack");
                Log($"Error starting attack: {ex.Message}");
                
                // Reset UI state on error
                Application.Current.Dispatcher.Invoke(() =>
                {
                    _startButton.IsEnabled = true;
                    _stopButton.IsEnabled = false;
                    _statusLabel.Content = "Status: Error";
                });
            }
        }

        public async Task StopAttackAsync()
        {
            try
            {
                await _networkStorm.StopAttackAsync();
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    _startButton.IsEnabled = true;
                    _stopButton.IsEnabled = false;
                    _statusLabel.Content = "Status: Attack Stopped";
                });
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error stopping attack");
                Log($"Error stopping attack: {ex.Message}");
            }
        }

        private void Log(string message)
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                _logArea.AppendText($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}\n");
                _logArea.ScrollToEnd();
            });
        }
    }
} 