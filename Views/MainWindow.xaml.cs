using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Dorothy.Controllers;
using Dorothy.Models;
using Dorothy.Network;
using Dorothy.Network.Headers;
using Microsoft.Win32;
using NLog;

namespace Dorothy.Views
{
    public partial class MainWindow : Window
    {
        private readonly MainController _mainController;
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();
        private readonly NetworkStorm _networkStorm;
        private readonly AttackLogger _attackLogger;
        private bool _isAdvancedMode;
        private CancellationTokenSource? _targetIpDebounceTokenSource;

        public MainWindow()
        {
            InitializeComponent();
            _attackLogger = new AttackLogger(LogTextBox);
            _networkStorm = new NetworkStorm(LogTextBox);
            _mainController = new MainController(_networkStorm, StartButton, StopButton, StatusLabel, LogTextBox, this);

            var result = MessageBox.Show(
                "DISCLAIMER:\n" +
                "======================\n" +
                "This is a DoS (Denial of Service) Testing Program for AUTHORIZED USE ONLY.\n" +
                "This tool is intended solely for authorized testing in controlled environments with explicit permission.\n" +
                "SeaNet and its affiliates assume no responsibility for any misuse, unauthorized access, or damages resulting from the use of this program.\n" +
                "By using this program, you acknowledge that you have the necessary authorization and accept full responsibility.\n" +
                "======================\n\n" +
                "Do you accept these terms?",
                "Warning",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.No)
            {
                Close();
                return;
            }

            PopulateNetworkInterfaces();
            PopulateAttackTypes();

            AttackTypeComboBox.SelectedIndex = 0;
            AdvancedAttackTypeComboBox.SelectedIndex = 0;
        }

        private void LogError(string message)
        {
            _attackLogger.LogError(message);
        }

        private void LogWarning(string message)
        {
            _attackLogger.LogWarning(message);
        }

        private void SaveLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                    DefaultExt = ".txt",
                    FileName = $"attack_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    File.WriteAllText(saveFileDialog.FileName, LogTextBox.Text);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving log: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error saving log: {ex.Message}");
            }
        }

        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            LogTextBox.Clear();
        }

        private void TaskManagerButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Process.Start("taskmgr.exe");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening Task Manager: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error opening Task Manager: {ex.Message}");
            }
        }

        private async void PingButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                PingButton.IsEnabled = false;
                PingButton.Content = "Pinging...";
                PingButton.Background = SystemColors.ControlBrush;

                var targetIp = TargetIpTextBox.Text;
                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    PingButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    return;
                }

                var result = await _mainController.PingHostAsync(targetIp);
                if (result.Success)
                {
                    _attackLogger.LogInfo($"Ping to {targetIp} successful. Roundtrip time: {result.RoundtripTime}ms");
                    PingButton.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                }
                else
                {
                    _attackLogger.LogPing(targetIp, false);
                    PingButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Ping error: {ex}");
                PingButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
            }
            finally
            {
                PingButton.IsEnabled = true;
                PingButton.Content = "Ping";
            }
        }

        private async void ResolveMacButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ResolveMacButton.IsEnabled = false;
                ResolveMacButton.Content = "Resolving...";
                ResolveMacButton.Background = SystemColors.ControlBrush;

                var sourceIp = SourceIpTextBox.Text;
                var gatewayIp = GatewayIpTextBox.Text;
                var targetIp = TargetIpTextBox.Text;

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    return;
                }

                if (!IPAddress.TryParse(targetIp, out var targetIpObj))
                {
                    ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    return;
                }

                if (!IPAddress.TryParse(sourceIp, out var sourceIpObj))
                {
                    ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    return;
                }

                // Check if target is on same subnet
                byte[] subnet = new byte[] { 255, 255, 255, 0 }; // Default subnet mask
                byte[] sourceBytes = sourceIpObj.GetAddressBytes();
                byte[] targetBytes = targetIpObj.GetAddressBytes();
                bool sameSubnet = true;

                for (int i = 0; i < 4; i++)
                {
                    if ((sourceBytes[i] & subnet[i]) != (targetBytes[i] & subnet[i]))
                    {
                        sameSubnet = false;
                        break;
                    }
                }

                if (sameSubnet)
                {
                    // For targets on same subnet, resolve target MAC directly
                    var macBytes = await _networkStorm.GetMacAddressAsync(targetIp);
                    if (macBytes.Length > 0)
                    {
                        var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                        TargetMacTextBox.Text = macAddress;
                        _attackLogger.LogMacResolution(targetIp, macAddress);
                        ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                    }
                    else
                    {
                        _attackLogger.LogError("Failed to resolve target MAC address");
                        ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    }
                }
                else
                {
                    // For targets on different subnet, resolve gateway MAC
                    if (string.IsNullOrWhiteSpace(gatewayIp))
                    {
                        ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                        return;
                    }

                    if (!IPAddress.TryParse(gatewayIp, out _))
                    {
                        ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                        return;
                    }

                    var macBytes = await _networkStorm.GetMacAddressAsync(gatewayIp);
                    if (macBytes.Length > 0)
                    {
                        var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                        TargetMacTextBox.Text = macAddress;
                        _attackLogger.LogMacResolution(gatewayIp, macAddress, true);
                        ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                    }
                    else
                    {
                        _attackLogger.LogError("Failed to resolve gateway MAC address");
                        ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error resolving MAC address: {ex}");
                ResolveMacButton.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
            }
            finally
            {
                ResolveMacButton.IsEnabled = true;
                ResolveMacButton.Content = "Resolve MAC";
            }
        }

        private void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var targetIp = TargetIpTextBox.Text;
                if (!int.TryParse(TargetPortTextBox.Text, out int targetPort))
                {
                    MessageBox.Show("Please enter a valid port number.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!long.TryParse(MegabitsPerSecondTextBox.Text, out long megabitsPerSecond))
                {
                    MessageBox.Show("Please enter a valid rate in Mbps.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var selectedAttackType = (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                if (string.IsNullOrEmpty(selectedAttackType))
                {
                    MessageBox.Show("Please select an attack type.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                AttackType attackType = selectedAttackType switch
                {
                    "TCP SYN Flood" => AttackType.SynFlood,
                    "UDP Flood" => AttackType.UdpFlood,
                    "ICMP Flood" => AttackType.IcmpFlood,
                    _ => throw new ArgumentException($"Unsupported attack type: {selectedAttackType}")
                };

                _mainController.StartAttackAsync(attackType, targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Attack failed: {ex}");
            }
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _mainController.StopAttackAsync();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error stopping attack: {ex}");
            }
        }

        private void PopulateNetworkInterfaces()
        {
            try
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Select(n => new
                    {
                        Interface = n,
                        IpAddress = n.GetIPProperties().UnicastAddresses
                            .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address
                    })
                    .Where(x => x.IpAddress != null)
                    .ToList();

                NetworkInterfaceComboBox.ItemsSource = interfaces;
                NetworkInterfaceComboBox.DisplayMemberPath = "Interface.Description";
                NetworkInterfaceComboBox.SelectedIndex = 0;

                if (interfaces.Any())
                {
                    var selectedInterface = interfaces.First();
                    SourceIpTextBox.Text = selectedInterface.IpAddress?.ToString();
                    var macBytes = selectedInterface.Interface.GetPhysicalAddress().GetAddressBytes();
                    SourceMacTextBox.Text = BitConverter.ToString(macBytes).Replace("-", ":");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error populating network interfaces: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error populating network interfaces: {ex}");
            }
        }

        private void PopulateAttackTypes()
        {
            try
            {
                AttackTypeComboBox.Items.Clear();
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "TCP SYN Flood" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "UDP Flood" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "ICMP Flood" });

                AdvancedAttackTypeComboBox.Items.Clear();
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "ARP Spoofing" });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error populating attack types: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error populating attack types: {ex}");
            }
        }

        private void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                if (NetworkInterfaceComboBox.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    var ipAddress = selectedInterface.IpAddress.ToString();
                    var macBytes = selectedInterface.Interface.GetPhysicalAddress().GetAddressBytes();
                    var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");

                    SourceIpTextBox.Text = ipAddress;
                    SourceMacTextBox.Text = macAddress;
                    _networkStorm.SetSourceInfo(ipAddress, macBytes);
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error selecting network interface: {ex}");
            }
        }

        private void AdvancedTab_PreviewMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (!_isAdvancedMode)
            {
                e.Handled = true;
                var result = MessageBox.Show(
                    "Advanced mode contains powerful features that could potentially harm network devices if misused. " +
                    "Are you sure you want to enable advanced mode?",
                    "Warning",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    _isAdvancedMode = true;
                    MainTabControl.SelectedItem = AdvancedTab;
                    _attackLogger.LogWarning("Advanced mode enabled.");
                }
            }
        }

        private void GatewayIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(GatewayIpTextBox.Text))
                {
                    GatewayIpTextBox.Background = SystemColors.WindowBrush;
                    return;
                }

                if (IPAddress.TryParse(GatewayIpTextBox.Text, out _))
                {
                    GatewayIpTextBox.Background = SystemColors.WindowBrush;
                    _networkStorm.SetGatewayIp(GatewayIpTextBox.Text);
                }
                else
                {
                    GatewayIpTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error updating gateway IP: {ex.Message}");
            }
        }

        private void AddRouteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(GatewayIpTextBox.Text))
                {
                    MessageBox.Show("Please enter a gateway IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var gatewayIp = GatewayIpTextBox.Text;
                var sourceIp = SourceIpTextBox.Text;
                var targetIp = TargetIpTextBox.Text;

                if (!IPAddress.TryParse(gatewayIp, out _))
                {
                    MessageBox.Show("Please enter a valid gateway IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!IPAddress.TryParse(sourceIp, out _))
                {
                    MessageBox.Show("Please enter a valid source IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!IPAddress.TryParse(targetIp, out _))
                {
                    MessageBox.Show("Please enter a valid target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "route",
                        Arguments = $"add {targetIp} mask 255.255.255.255 {gatewayIp}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        Verb = "runas"
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    _attackLogger.LogInfo($"Route added successfully: {targetIp} via {gatewayIp}");
                    MessageBox.Show("Route added successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                {
                    var errorMessage = !string.IsNullOrEmpty(error) ? error : output;
                    _attackLogger.LogError($"Failed to add route: {errorMessage}");
                    MessageBox.Show($"Failed to add route: {errorMessage}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error adding route: {ex}");
            }
        }

        private void TargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                // Cancel any previous timer
                _targetIpDebounceTokenSource?.Cancel();
                _targetIpDebounceTokenSource?.Dispose();
                _targetIpDebounceTokenSource = new CancellationTokenSource();

                if (string.IsNullOrWhiteSpace(TargetIpTextBox.Text))
                {
                    TargetIpTextBox.Background = SystemColors.WindowBrush;
                    GatewayIpTextBox.IsEnabled = true;
                    return;
                }

                // Basic format validation without subnet check
                if (!IPAddress.TryParse(TargetIpTextBox.Text, out _))
                {
                    TargetIpTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    GatewayIpTextBox.IsEnabled = true;
                    return;
                }

                TargetIpTextBox.Background = SystemColors.WindowBrush;

                // Delay the subnet check
                Task.Delay(500, _targetIpDebounceTokenSource.Token).ContinueWith(t =>
                {
                    if (t.IsCanceled) return;

                    Dispatcher.Invoke(() =>
                    {
                        if (IPAddress.TryParse(TargetIpTextBox.Text, out var targetIp) && 
                            IPAddress.TryParse(SourceIpTextBox.Text, out var sourceIp))
                        {
                            // Check if target is on same subnet
                            byte[] subnet = new byte[] { 255, 255, 255, 0 }; // Default subnet mask
                            byte[] sourceBytes = sourceIp.GetAddressBytes();
                            byte[] targetBytes = targetIp.GetAddressBytes();
                            bool sameSubnet = true;

                            for (int i = 0; i < 4; i++)
                            {
                                if ((sourceBytes[i] & subnet[i]) != (targetBytes[i] & subnet[i]))
                                {
                                    sameSubnet = false;
                                    break;
                                }
                            }

                            if (sameSubnet)
                            {
                                // If on same subnet, disable gateway input as it's not needed
                                GatewayIpTextBox.IsEnabled = false;
                                GatewayIpTextBox.Background = SystemColors.ControlLightBrush;
                            }
                            else
                            {
                                // If on different subnet, enable gateway input as it's required
                                GatewayIpTextBox.IsEnabled = true;
                                GatewayIpTextBox.Background = SystemColors.WindowBrush;
                            }
                        }
                    });
                });
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating target IP: {ex.Message}");
                GatewayIpTextBox.IsEnabled = true;
            }
        }

        private void AttackTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Remove logging
        }

        private void AdvTargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (sender is TextBox textBox)
                {
                    if (string.IsNullOrWhiteSpace(textBox.Text))
                    {
                        textBox.Background = SystemColors.WindowBrush;
                        return;
                    }

                    if (IPAddress.TryParse(textBox.Text, out _))
                    {
                        textBox.Background = SystemColors.WindowBrush;
                    }
                    else
                    {
                        textBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating advanced target IP: {ex.Message}");
            }
        }

        private void AdvancedAttackTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Remove logging
        }

        private void SpoofedMacTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (sender is TextBox textBox)
                {
                    if (string.IsNullOrWhiteSpace(textBox.Text))
                    {
                        textBox.Background = SystemColors.WindowBrush;
                        return;
                    }

                    var macRegex = new Regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
                    if (macRegex.IsMatch(textBox.Text))
                    {
                        textBox.Background = SystemColors.WindowBrush;
                    }
                    else
                    {
                        textBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating spoofed MAC address: {ex.Message}");
            }
        }

        private async void StartAdvancedAttack_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem)
                {
                    var attackType = selectedItem.Content.ToString();
                    switch (attackType)
                    {
                        case "ARP Spoofing":
                            await StartArpSpoofingAttack();
                            break;
                        default:
                            MessageBox.Show($"Unsupported attack type: {attackType}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error starting advanced attack: {ex}");
            }
        }

        private async void StopAdvancedAttack_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem)
                {
                    var attackType = selectedItem.Content.ToString();
                    switch (attackType)
                    {
                        case "ARP Spoofing":
                            await _mainController.StopArpSpoofingAsync();
                            break;
                        default:
                            MessageBox.Show($"Unsupported attack type: {attackType}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error stopping advanced attack: {ex}");
            }
        }

        private async Task StartArpSpoofingAttack()
        {
            var sourceIp = SourceIpTextBox.Text;
            var sourceMac = SourceMacTextBox.Text;
            var targetIp = TargetIpTextBox.Text;
            var targetMac = TargetMacTextBox.Text;
            var spoofedMac = SpoofedMacTextBox.Text;

            if (string.IsNullOrWhiteSpace(sourceIp) || string.IsNullOrWhiteSpace(sourceMac) ||
                string.IsNullOrWhiteSpace(targetIp) || string.IsNullOrWhiteSpace(targetMac) ||
                string.IsNullOrWhiteSpace(spoofedMac))
            {
                MessageBox.Show("Please fill in all required fields.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!IPAddress.TryParse(sourceIp, out _) || !IPAddress.TryParse(targetIp, out _))
            {
                MessageBox.Show("Please enter valid IP addresses.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var macRegex = new Regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
            if (!macRegex.IsMatch(sourceMac) || !macRegex.IsMatch(targetMac) || !macRegex.IsMatch(spoofedMac))
            {
                MessageBox.Show("Please enter valid MAC addresses in the format XX:XX:XX:XX:XX:XX", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            await _mainController.StartArpSpoofingAsync(sourceIp, sourceMac, targetIp, targetMac, spoofedMac);
        }

        private void SourceIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(SourceIpTextBox.Text))
                {
                    SourceIpTextBox.Background = SystemColors.WindowBrush;
                    return;
                }

                if (IPAddress.TryParse(SourceIpTextBox.Text, out _))
                {
                    SourceIpTextBox.Background = SystemColors.WindowBrush;
                }
                else
                {
                    SourceIpTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating source IP: {ex.Message}");
            }
        }
    }
} 