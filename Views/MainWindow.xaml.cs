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
using SharpPcap;

namespace Dorothy.Views
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly MainController _mainController;
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();
        private readonly NetworkStorm _networkStorm;
        private readonly AttackLogger _attackLogger;
        private readonly TraceRoute _traceRoute;
        private bool _isAdvancedMode;
        private bool? _lastSubnetStatus;
        private string? _lastSubnetMessage;
        private DateTime _lastSubnetLogTime = DateTime.MinValue;
        private const int SUBNET_LOG_THROTTLE_MS = 1000; // Throttle duplicate messages within 1 second
        private CancellationTokenSource? _targetIpDebounceTokenSource;
        private const string NOTE_PLACEHOLDER = "Add a note to the attack log... (Ctrl+Enter to save)";

        public MainWindow()
        {
            InitializeComponent();
            
            // Initialize logger first
            _attackLogger = new AttackLogger(LogTextBox);
            
            // Then initialize components that depend on logger
            _networkStorm = new NetworkStorm(_attackLogger);
            _traceRoute = new TraceRoute(_attackLogger);
            _mainController = new MainController(_networkStorm, StartButton, StopButton, StatusLabel, LogTextBox, this);

            // Show disclaimer
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

            // Initialize UI components
            PopulateNetworkInterfaces();
            PopulateAttackTypes();

            AttackTypeComboBox.SelectedIndex = 0;
            AdvancedAttackTypeComboBox.SelectedIndex = 0;

            // Set placeholder text
            NoteTextBox.Text = NOTE_PLACEHOLDER;
            NoteTextBox.Foreground = SystemColors.GrayTextBrush;
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
                var button = sender as Button;
                if (button == null) return;
                
            try
            {
                button.IsEnabled = false;
                button.Content = "Pinging...";

                var targetIp = (sender == PingButton) ? TargetIpTextBox.Text : AdvTargetIpTextBox.Text;
                var targetTextBox = (sender == PingButton) ? TargetIpTextBox : AdvTargetIpTextBox;

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Check subnet and gateway requirement before pinging
                if (!CheckSubnetAndGatewayRequirement(targetIp))
                {
                    MessageBox.Show("Gateway IP is required for targets on different subnets.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = await _mainController.PingHostAsync(targetIp);
                if (result.Success)
                {
                    targetTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                    _attackLogger.LogInfo($"Ping to {targetIp} successful. Roundtrip time: {result.RoundtripTime}ms");
                    
                    // If ARP Spoofing is selected, sync the other tab's IP field color
                    if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem && 
                        selectedItem.Content.ToString() == "ARP Spoofing")
                    {
                        var otherTextBox = (sender == PingButton) ? AdvTargetIpTextBox : TargetIpTextBox;
                        otherTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                    }
                }
                else
                {
                    targetTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    _attackLogger.LogInfo($"Ping {targetIp}: failed");
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Ping error: {ex}");
                if (sender == PingButton)
                    TargetIpTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                else
                    AdvTargetIpTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
            }
            finally
            {
                button.IsEnabled = true;
                button.Content = "Ping";
            }
        }

        private bool CheckSubnetAndGatewayRequirement(string targetIp, bool isResolvingMac = false)
        {
            try
            {
                var sourceIp = SourceIpTextBox.Text;

                if (string.IsNullOrWhiteSpace(sourceIp) || string.IsNullOrWhiteSpace(targetIp))
                {
                    return false;
                }

                if (!IPAddress.TryParse(sourceIp, out var sourceIpAddress) ||
                    !IPAddress.TryParse(targetIp, out var targetIpAddress))
                {
                    return false;
                }

                // Get the network interface for the source IP
                var selectedInterface = NetworkInterfaceComboBox.SelectedItem as dynamic;
                if (selectedInterface?.Interface is NetworkInterface nic)
                {
                    var ipProps = nic.GetIPProperties();
                    var unicastInfo = ipProps.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (unicastInfo != null)
                    {
                        // Convert subnet mask to uint32
                        var maskBytes = unicastInfo.IPv4Mask.GetAddressBytes();
                        Array.Reverse(maskBytes);
                        var mask = BitConverter.ToUInt32(maskBytes, 0);

                        // Convert IPs to uint32
                        var sourceBytes = sourceIpAddress.GetAddressBytes();
                        var targetBytes = targetIpAddress.GetAddressBytes();
                        Array.Reverse(sourceBytes);
                        Array.Reverse(targetBytes);
                        var sourceInt = BitConverter.ToUInt32(sourceBytes, 0);
                        var targetInt = BitConverter.ToUInt32(targetBytes, 0);

                        // Compare network portions
                        var sameSubnet = (sourceInt & mask) == (targetInt & mask);
                        
                        if (!sameSubnet)
                        {
                            if (isResolvingMac)
                            {
                                // For MAC resolution, we can't resolve MACs for IPs outside our local network
                                _attackLogger.LogInfo($"Cannot resolve MAC address for {targetIp} - Not on local network");
                                return false;
                            }
                            else
                            {
                                _attackLogger.LogInfo("Source and target are on different subnets. Gateway required.");
                                if (string.IsNullOrWhiteSpace(GatewayIpTextBox.Text))
                                {
                                    return false;
                                }
                            }
                        }

                        // Update gateway field
                        GatewayIpTextBox.IsEnabled = !sameSubnet;
                        if (sameSubnet)
                        {
                            GatewayIpTextBox.Text = string.Empty;
                            GatewayIpTextBox.Background = SystemColors.ControlBrush;
                        }
                        else
                        {
                            GatewayIpTextBox.Background = SystemColors.WindowBrush;
                        }

                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error checking subnet: {ex.Message}");
                return false;
            }
        }

        private async void ResolveMacButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            try
            {
                if (button != null)
                button.Content = "Resolving...";

                var targetIp = (sender == ResolveMacButton) ? TargetIpTextBox.Text : AdvTargetIpTextBox.Text;
                var targetMacTextBox = (sender == ResolveMacButton) ? TargetMacTextBox : AdvTargetMacTextBox;

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Check if target is on different subnet
                if (!CheckSubnetAndGatewayRequirement(targetIp, true))
                {
                    // For external IPs, use the gateway MAC without showing a warning
                    var gatewayMac = await _mainController.GetMacAddressAsync(_networkStorm.GatewayIp);
                    if (gatewayMac.Length > 0)
                    {
                        var macAddress = BitConverter.ToString(gatewayMac).Replace("-", ":");
                        targetMacTextBox.Text = macAddress;
                        targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                        _attackLogger.LogInfo($"Using gateway MAC for external target: {macAddress}");

                        // If ARP Spoofing is selected, sync the other tab's MAC field
                        if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem && 
                            selectedItem.Content.ToString() == "ARP Spoofing")
                        {
                            var otherMacTextBox = (sender == ResolveMacButton) ? AdvTargetMacTextBox : TargetMacTextBox;
                            otherMacTextBox.Text = macAddress;
                            otherMacTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                        }
                    }
                    else
                    {
                        _attackLogger.LogError("Failed to resolve gateway MAC address");
                        targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    }
                }
                else
                {
                    // For local IPs, resolve the actual MAC
                    var macBytes = await _mainController.GetMacAddressAsync(targetIp);
                if (macBytes.Length > 0)
                {
                    var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                    targetMacTextBox.Text = macAddress;
                    targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));

                    // If ARP Spoofing is selected, sync the other tab's MAC field
                    if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem && 
                        selectedItem.Content.ToString() == "ARP Spoofing")
                    {
                        var otherMacTextBox = (sender == ResolveMacButton) ? AdvTargetMacTextBox : TargetMacTextBox;
                        otherMacTextBox.Text = macAddress;
                        otherMacTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                    }
                }
                else
                {
                    targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error resolving MAC address: {ex}");
                if (sender == ResolveMacButton)
                    TargetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                else
                    AdvTargetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
            }
            finally
            {
                if (button != null)
                    button.Content = "Resolve";
            }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Get the selected attack type based on current tab
                var attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();

                if (string.IsNullOrEmpty(attackType))
                {
                    MessageBox.Show("Please select an attack type.", "Missing Attack Type", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                switch (attackType)
                {
                    case "ARP Spoofing":
                        await StartArpSpoofingAttack();
                        break;

                    case "UDP Flood":
                    case "TCP SYN Flood":
                    case "ICMP Flood":
                        await StartFloodAttack(attackType);
                        break;

                    case "Broadcast":
                        await StartBroadcastAttack();
                        break;

                    default:
                        MessageBox.Show($"Unsupported attack type: {attackType}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        break;
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to start attack: {ex.Message}");
            }
        }

        private async Task StartFloodAttack(string attackType)
        {
            try
            {
                string targetIp;
                int targetPort;
                long megabitsPerSecond;

                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    if (!int.TryParse(AdvTargetPortTextBox.Text, out targetPort))
                    {
                        MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out megabitsPerSecond))
                    {
                        MessageBox.Show("Invalid rate (Mbps).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }
                else
                {
                    targetIp = TargetIpTextBox.Text.Trim();
                    if (!int.TryParse(TargetPortTextBox.Text, out targetPort))
                    {
                        MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    if (!long.TryParse(MegabitsPerSecondTextBox.Text, out megabitsPerSecond))
                    {
                        MessageBox.Show("Invalid rate (Mbps).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }

                var selectedAttackType = attackType switch
                {
                    "UDP Flood" => AttackType.UdpFlood,
                    "TCP SYN Flood" => AttackType.TcpSynFlood,
                    "ICMP Flood" => AttackType.IcmpFlood,
                    _ => throw new ArgumentException($"Unsupported flood attack type: {attackType}")
                };

                await _mainController.StartAttackAsync(selectedAttackType, targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to start flood attack: {ex.Message}");
                throw;
            }
        }

        private async Task StartBroadcastAttack()
        {
            try
            {
                string targetIp;
                int targetPort;
                long megabitsPerSecond;

                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    if (!int.TryParse(AdvTargetPortTextBox.Text, out targetPort))
                    {
                        MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                    if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out megabitsPerSecond))
                {
                        MessageBox.Show("Invalid rate (Mbps).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                }
                else
                {
                    targetIp = TargetIpTextBox.Text.Trim();
                    if (!int.TryParse(TargetPortTextBox.Text, out targetPort))
                    {
                        MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                    if (!long.TryParse(MegabitsPerSecondTextBox.Text, out megabitsPerSecond))
                    {
                        MessageBox.Show("Invalid rate (Mbps).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }

                await _mainController.StartBroadcastAttackAsync(targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to start broadcast attack: {ex.Message}");
                throw;
            }
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await _mainController.StopAttackAsync();
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
                        Description = $"{n.Description} ({n.Name})",
                        Interface = n,
                        IpAddress = n.GetIPProperties().UnicastAddresses
                            .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address
                    })
                    .Where(x => x.IpAddress != null)
                    .ToList();

                NetworkInterfaceComboBox.ItemsSource = interfaces;
                AdvNetworkInterfaceComboBox.ItemsSource = interfaces;
                NetworkInterfaceComboBox.DisplayMemberPath = "Description";
                AdvNetworkInterfaceComboBox.DisplayMemberPath = "Description";
                NetworkInterfaceComboBox.SelectedIndex = 0;
                AdvNetworkInterfaceComboBox.SelectedIndex = 0;

                if (interfaces.Any())
                {
                    var selectedInterface = interfaces.First();
                    SourceIpTextBox.Text = selectedInterface.IpAddress?.ToString();
                    AdvSourceIpTextBox.Text = selectedInterface.IpAddress?.ToString();
                    var macBytes = selectedInterface.Interface.GetPhysicalAddress().GetAddressBytes();
                    var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                    SourceMacTextBox.Text = macAddress;
                    AdvSourceMacTextBox.Text = macAddress;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
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
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Unicast" });
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Multicast" });
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Broadcast" });
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
                var comboBox = sender as ComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    var ipAddress = selectedInterface.IpAddress.ToString();
                    var macBytes = selectedInterface.Interface.GetPhysicalAddress().GetAddressBytes();
                    var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");

                    // Update both basic and advanced settings
                    SourceIpTextBox.Text = ipAddress;
                    SourceMacTextBox.Text = macAddress;
                    AdvSourceIpTextBox.Text = ipAddress;
                    AdvSourceMacTextBox.Text = macAddress;
                    
                    // Sync the other combobox selection
                    if (comboBox == NetworkInterfaceComboBox)
                    {
                        AdvNetworkInterfaceComboBox.SelectedIndex = NetworkInterfaceComboBox.SelectedIndex;
                    }
                    else
                    {
                        NetworkInterfaceComboBox.SelectedIndex = AdvNetworkInterfaceComboBox.SelectedIndex;
                    }

                    _networkStorm.SetSourceInfo(ipAddress, macBytes);
                    
                    // Check subnet for the new interface
                    CheckSubnetAndUpdateGatewayField();
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

                CheckSubnetAndUpdateGatewayField();
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating source IP: {ex.Message}");
            }
        }

        private void TargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(TargetIpTextBox.Text))
                {
                    TargetIpTextBox.Background = SystemColors.WindowBrush;
                    return;
                }

                if (IPAddress.TryParse(TargetIpTextBox.Text, out _))
                {
                    TargetIpTextBox.Background = SystemColors.WindowBrush;
                }
                else
                {
                    TargetIpTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in TargetIpTextBox_TextChanged");
            }
        }

        private void TargetMacTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                var textBox = sender as TextBox;
                if (string.IsNullOrWhiteSpace(textBox.Text))
                {
                    textBox.Background = SystemColors.WindowBrush;
                    return;
                }

                var macRegex = new Regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
                if (macRegex.IsMatch(textBox.Text))
                {
                    textBox.Background = SystemColors.WindowBrush;
                    // Sync between basic and advanced if ARP Spoofing is selected
                    if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem && 
                        selectedItem.Content.ToString() == "ARP Spoofing")
                    {
                        if (sender == TargetMacTextBox)
                            AdvTargetMacTextBox.Text = textBox.Text;
                        else
                            TargetMacTextBox.Text = textBox.Text;
                    }
                            }
                            else
                            {
                    textBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                            }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating target MAC: {ex.Message}");
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
            try
            {
                if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem)
                {
                    var attackType = selectedItem.Content.ToString();
                    switch (attackType)
                    {
                        case "ARP Spoofing":
                            AdvTargetPortTextBox.IsEnabled = false;
                            AdvMegabitsPerSecondTextBox.IsEnabled = false;
                            AdvTargetMacTextBox.IsEnabled = true;
                            SpoofedMacTextBox.IsEnabled = true;  // Enable spoofed MAC only for ARP Spoofing
                            // Sync all target information with basic settings
                            AdvTargetIpTextBox.Text = TargetIpTextBox.Text;
                            AdvTargetMacTextBox.Text = TargetMacTextBox.Text;
                            AdvSourceIpTextBox.Text = SourceIpTextBox.Text;
                            AdvSourceMacTextBox.Text = SourceMacTextBox.Text;
                            break;
                        case "Ethernet Unicast":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;  // Disable spoofed MAC for Ethernet attacks
                            break;
                        case "Ethernet Multicast":
                        case "Ethernet Broadcast":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;  // Disable spoofed MAC for Ethernet attacks
                            break;
                        default:
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;  // Disable spoofed MAC by default
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error changing advanced attack type: {ex}");
            }
        }

        private void SpoofedMacTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (sender is TextBox textBox)
                {
                    int currentCaretIndex = textBox.CaretIndex;
                    string originalText = textBox.Text;

                    if (string.IsNullOrWhiteSpace(textBox.Text))
                    {
                        textBox.Background = SystemColors.WindowBrush;
                        return;
                    }

                    // Remove any non-hex characters and colons
                    string cleanText = new string(textBox.Text.Where(c => 
                        (c >= '0' && c <= '9') || 
                        (c >= 'a' && c <= 'f') || 
                        (c >= 'A' && c <= 'F') || 
                        c == ':').ToArray()).ToUpper();

                    // Handle the case where user types colons manually
                    if (cleanText.Contains(':'))
                    {
                        var parts = cleanText.Split(':');
                        cleanText = string.Join("", parts);
                    }

                    // Format MAC address
                    var formattedMac = new StringBuilder();
                    for (int i = 0; i < cleanText.Length && i < 12; i++)
                    {
                        if (i > 0 && i % 2 == 0 && formattedMac.Length < 17)
                        {
                            formattedMac.Append(':');
                        }
                        formattedMac.Append(cleanText[i]);
                    }

                    string result = formattedMac.ToString();

                    // Only update if text has changed
                    if (result != originalText)
                    {
                        textBox.Text = result;
                        
                        // Calculate new cursor position based on the number of characters typed
                        int hexDigitsBeforeCaret = originalText.Take(currentCaretIndex)
                            .Count(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));
                        
                        // Calculate how many colons should be before the cursor
                        int colonCount = hexDigitsBeforeCaret / 2;
                        if (hexDigitsBeforeCaret > 0 && hexDigitsBeforeCaret % 2 == 0 && hexDigitsBeforeCaret < 12)
                        {
                            colonCount--;
                        }
                        
                        // Set new cursor position
                        int newPosition = hexDigitsBeforeCaret + colonCount;
                        if (newPosition > result.Length)
                        {
                            newPosition = result.Length;
                        }
                        
                        textBox.CaretIndex = newPosition;
                    }

                    // Validate the MAC address format
                    var isComplete = new Regex("^([0-9A-F]{2}:){5}[0-9A-F]{2}$").IsMatch(result);
                    var isPartial = new Regex("^([0-9A-F]{2}:)*[0-9A-F]{0,2}$").IsMatch(result);

                    if (isComplete)
                    {
                        textBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                    }
                    else if (isPartial)
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
                        case "Ethernet Unicast":
                            await StartEthernetAttack(EthernetFlood.EthernetPacketType.Unicast);
                            break;
                        case "Ethernet Multicast":
                            await StartEthernetAttack(EthernetFlood.EthernetPacketType.Multicast);
                            break;
                        case "Ethernet Broadcast":
                            await StartEthernetAttack(EthernetFlood.EthernetPacketType.Broadcast);
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

        private async Task StartEthernetAttack(EthernetFlood.EthernetPacketType packetType)
        {
            try
            {
                string targetIp = AdvTargetIpTextBox.Text.Trim();
                if (!int.TryParse(AdvTargetPortTextBox.Text, out int targetPort))
                {
                    MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out long megabitsPerSecond))
                {
                    MessageBox.Show("Invalid rate (Mbps).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                StartAdvancedAttackButton.IsEnabled = false;
                StopAdvancedAttackButton.IsEnabled = true;

                var sourceMac = await _mainController.GetLocalMacAddressAsync();
                var sourceIp = await _mainController.GetLocalIpAddressAsync();
                byte[] targetMac;

                targetMac = packetType switch
                {
                    EthernetFlood.EthernetPacketType.Unicast => await _mainController.GetMacAddressAsync(targetIp),
                    EthernetFlood.EthernetPacketType.Multicast => new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 },
                    EthernetFlood.EthernetPacketType.Broadcast => new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
                    _ => throw new ArgumentException("Invalid Ethernet packet type")
                };

                _attackLogger.StartEthernetAttack(
                    packetType,
                    sourceIp,
                    sourceMac,
                    targetIp,
                    targetMac,
                    megabitsPerSecond
                );

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, megabitsPerSecond, packetType);
            }
            catch (Exception ex)
            {
                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
                _attackLogger.LogError($"Failed to start Ethernet {packetType} attack: {ex.Message}");
                throw;
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
                        case "Ethernet Unicast":
                        case "Ethernet Multicast":
                        case "Ethernet Broadcast":
                            await _networkStorm.StopAttackAsync();
                            _attackLogger.LogInfo($"Stopped {attackType} attack");
                            // Reset button states after stopping attack
                            StartAdvancedAttackButton.IsEnabled = true;
                            StopAdvancedAttackButton.IsEnabled = false;
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
                // Reset button states on error
                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
            }
        }

        private async Task StartArpSpoofingAttack()
        {
            try
            {
                string sourceIp, sourceMac, targetIp, targetMac, spoofedMac;

                // Check which tab is active and get values accordingly
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    sourceIp = AdvSourceIpTextBox.Text.Trim();
                    sourceMac = AdvSourceMacTextBox.Text.Trim();
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    targetMac = AdvTargetMacTextBox.Text.Trim();
                    spoofedMac = SpoofedMacTextBox.Text.Trim();
                }
                else
                {
                    sourceIp = SourceIpTextBox.Text.Trim();
                    sourceMac = SourceMacTextBox.Text.Trim();
                    targetIp = TargetIpTextBox.Text.Trim();
                    targetMac = TargetMacTextBox.Text.Trim();
                    spoofedMac = SpoofedMacTextBox.Text.Trim();
                }

                // Validate all required fields
                var missingFields = new List<string>();
                if (string.IsNullOrWhiteSpace(sourceIp)) missingFields.Add("Source IP");
                if (string.IsNullOrWhiteSpace(sourceMac)) missingFields.Add("Source MAC");
                if (string.IsNullOrWhiteSpace(targetIp)) missingFields.Add("Target IP");
                if (string.IsNullOrWhiteSpace(targetMac)) missingFields.Add("Target MAC");
                if (string.IsNullOrWhiteSpace(spoofedMac)) missingFields.Add("Spoofed MAC");

                if (missingFields.Any())
                {
                    MessageBox.Show(
                        $"Please fill in all required fields:\n{string.Join("\n", missingFields)}", 
                        "Missing Fields", 
                        MessageBoxButton.OK, 
                        MessageBoxImage.Warning);
                return;
            }

                // Check network interface status
                var selectedInterface = MainTabControl.SelectedItem == AdvancedTab ? 
                    AdvNetworkInterfaceComboBox.SelectedItem as dynamic : 
                    NetworkInterfaceComboBox.SelectedItem as dynamic;

                if (selectedInterface?.Interface.OperationalStatus != OperationalStatus.Up)
                {
                    MessageBox.Show(
                        "Selected network interface is not active.\nPlease check your network connection.", 
                        "Network Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

                _attackLogger.LogInfo($"Starting ARP spoofing attack with parameters:");
                _attackLogger.LogInfo($"Source IP: {sourceIp}, Source MAC: {sourceMac}");
                _attackLogger.LogInfo($"Target IP: {targetIp}, Target MAC: {targetMac}");
                _attackLogger.LogInfo($"Spoofed MAC: {spoofedMac}");

            await _mainController.StartArpSpoofingAsync(sourceIp, sourceMac, targetIp, targetMac, spoofedMac);
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to start ARP spoofing: {ex.Message}");
            }
        }

        private void CheckSubnetAndUpdateGatewayField()
        {
            try
            {
                var sourceIp = SourceIpTextBox.Text;
                var targetIp = TargetIpTextBox.Text;

                if (string.IsNullOrWhiteSpace(sourceIp) || string.IsNullOrWhiteSpace(targetIp))
                {
                    GatewayIpTextBox.IsEnabled = true;
                    _lastSubnetStatus = null;
                    _lastSubnetMessage = null;
                    return;
                }

                if (!IPAddress.TryParse(sourceIp, out var sourceIpAddress) || 
                    !IPAddress.TryParse(targetIp, out var targetIpAddress))
                {
                    GatewayIpTextBox.IsEnabled = true;
                    _lastSubnetStatus = null;
                    _lastSubnetMessage = null;
                    return;
                }

                // Get the network interface for the source IP
                var selectedInterface = NetworkInterfaceComboBox.SelectedItem as dynamic;
                if (selectedInterface?.Interface is NetworkInterface nic)
                {
                    var ipProps = nic.GetIPProperties();
                    var unicastInfo = ipProps.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (unicastInfo != null)
                    {
                        // Convert subnet mask to uint32
                        var maskBytes = unicastInfo.IPv4Mask.GetAddressBytes();
                        Array.Reverse(maskBytes);
                        var mask = BitConverter.ToUInt32(maskBytes, 0);

                        // Convert IPs to uint32
                        var sourceBytes = sourceIpAddress.GetAddressBytes();
                        var targetBytes = targetIpAddress.GetAddressBytes();
                        Array.Reverse(sourceBytes);
                        Array.Reverse(targetBytes);
                        var sourceInt = BitConverter.ToUInt32(sourceBytes, 0);
                        var targetInt = BitConverter.ToUInt32(targetBytes, 0);

                        // Compare network portions
                        var sameSubnet = (sourceInt & mask) == (targetInt & mask);
                        var currentMessage = sameSubnet ? 
                            "Source and target are on the same subnet. Gateway not required." :
                            "Source and target are on different subnets. Gateway required.";

                        // Only log if the subnet status has changed or enough time has passed
                        var now = DateTime.Now;
                        if (_lastSubnetStatus != sameSubnet || 
                            _lastSubnetMessage != currentMessage ||
                            (now - _lastSubnetLogTime).TotalMilliseconds > SUBNET_LOG_THROTTLE_MS)
                        {
                            _lastSubnetStatus = sameSubnet;
                            _lastSubnetMessage = currentMessage;
                            _lastSubnetLogTime = now;
                            _attackLogger.LogInfo(currentMessage);
                        }

                        // Update gateway field
                        GatewayIpTextBox.IsEnabled = !sameSubnet;
                        if (sameSubnet)
                        {
                            GatewayIpTextBox.Text = string.Empty;
                            GatewayIpTextBox.Background = SystemColors.ControlBrush;
                        }
                        else
                        {
                            GatewayIpTextBox.Background = SystemColors.WindowBrush;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error checking subnet: {ex.Message}");
                GatewayIpTextBox.IsEnabled = true;
                _lastSubnetStatus = null;
                _lastSubnetMessage = null;
            }
        }

        private void MainTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                if (e.Source is TabControl)
                {
                    if (MainTabControl.SelectedItem == AdvancedTab)
                    {
                        // Sync from basic to advanced tab
                        AdvTargetIpTextBox.Text = TargetIpTextBox.Text;
                        AdvTargetMacTextBox.Text = TargetMacTextBox.Text;
                        AdvSourceIpTextBox.Text = SourceIpTextBox.Text;
                        AdvSourceMacTextBox.Text = SourceMacTextBox.Text;
                        AdvGatewayIpTextBox.Text = GatewayIpTextBox.Text;
                        
                        // Sync network interface selection
                        if (NetworkInterfaceComboBox.SelectedItem != null)
                        {
                            AdvNetworkInterfaceComboBox.SelectedItem = NetworkInterfaceComboBox.SelectedItem;
                        }
                    }
                    else
                    {
                        // Sync from advanced to basic tab
                        TargetIpTextBox.Text = AdvTargetIpTextBox.Text;
                        TargetMacTextBox.Text = AdvTargetMacTextBox.Text;
                        SourceIpTextBox.Text = AdvSourceIpTextBox.Text;
                        SourceMacTextBox.Text = AdvSourceMacTextBox.Text;
                        GatewayIpTextBox.Text = AdvGatewayIpTextBox.Text;
                        
                        // Sync network interface selection
                        if (AdvNetworkInterfaceComboBox.SelectedItem != null)
                        {
                            NetworkInterfaceComboBox.SelectedItem = AdvNetworkInterfaceComboBox.SelectedItem;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error syncing settings between tabs: {ex}");
            }
        }

        private void NoteTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            var textBox = (TextBox)sender;
            if (textBox.Text == NOTE_PLACEHOLDER)
            {
                textBox.Text = string.Empty;
                textBox.Foreground = SystemColors.WindowTextBrush;
            }
        }

        private void NoteTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            var textBox = (TextBox)sender;
            if (string.IsNullOrWhiteSpace(textBox.Text))
            {
                textBox.Text = NOTE_PLACEHOLDER;
                textBox.Foreground = SystemColors.GrayTextBrush;
            }
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            // Initialize placeholder text
            NoteTextBox.Text = NOTE_PLACEHOLDER;
            NoteTextBox.Foreground = SystemColors.GrayTextBrush;
        }

        private void AddNoteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(NoteTextBox.Text) || NoteTextBox.Text == NOTE_PLACEHOLDER)
                {
                    MessageBox.Show("Please enter a note before adding.", "Empty Note", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var note = NoteTextBox.Text.Trim();
                
                var formattedNote = $"\n📝 USER NOTE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                                   $"Time: {timestamp}\n" +
                                   $"Note: {note}\n" +
                                   $"━━━━━━━━━━━━━━━━━━━━━━━━━━━━ END NOTE 📝\n";

                _attackLogger.LogNote(formattedNote);
                NoteTextBox.Text = NOTE_PLACEHOLDER;
                NoteTextBox.Foreground = SystemColors.GrayTextBrush;
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error adding note: {ex.Message}");
                MessageBox.Show($"Error adding note: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Add keyboard shortcut for adding notes
        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            
            if (e.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                if (NoteTextBox.IsFocused)
                {
                    AddNoteButton_Click(this, new RoutedEventArgs());
                    e.Handled = true;
                }
            }
        }

        private async void TraceRouteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetIp;
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                }
                else
                {
                    targetIp = TargetIpTextBox.Text.Trim();
                }

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!IPAddress.TryParse(targetIp, out _))
                {
                    MessageBox.Show("Please enter a valid IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Disable the button while trace route is running
                var button = sender as Button;
                if (button != null)
                {
                    button.IsEnabled = false;
                }

                StatusLabel.Content = "Status: Running Trace Route";
                await _traceRoute.ExecuteTraceRouteAsync(targetIp);
                StatusLabel.Content = "Status: Ready";

                // Re-enable the button
                if (button != null)
                {
                    button.IsEnabled = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error executing trace route: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Trace route failed: {ex}");
                StatusLabel.Content = "Status: Error";
            }
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var progressBar = button == ScanButton ? ScanProgressBar : AdvScanProgressBar;
            try
            {
                // Get target IP based on which tab is active
                string targetIp = MainTabControl.SelectedItem == AdvancedTab ? 
                    AdvTargetIpTextBox.Text.Trim() : 
                    TargetIpTextBox.Text.Trim();

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!IPAddress.TryParse(targetIp, out _))
                {
                    MessageBox.Show("Please enter a valid IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Show warning message
                var result = MessageBox.Show(
                    "Port scanning may take several minutes to complete and could be detected by security systems.\n\n" +
                    "The scan will check all TCP ports (1-65535).\n\n" +
                    "Do you want to continue?",
                    "Port Scan Warning",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning
                );

                if (result != MessageBoxResult.Yes)
                {
                    return;
                }

                if (button != null)
                {
                    button.IsEnabled = false;
                    button.Content = "Scanning...";
                }

                // Show progress bar and status
                if (progressBar != null)
                {
                    progressBar.Value = 0;
                    progressBar.IsIndeterminate = true;
                    progressBar.Visibility = Visibility.Visible;
                }

                _attackLogger.LogInfo($"Starting port scan on {targetIp}...");
                _attackLogger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

                // Run nmap scan
                await Task.Run(() =>
                {
                    try
                    {
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "nmap",
                                Arguments = $"-sS -T4 -p- -v -oN - {targetIp}",  // Added -oN - to output to stdout instead of file
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                CreateNoWindow = true
                            }
                        };

                        process.OutputDataReceived += (s, args) =>
                        {
                            if (!string.IsNullOrEmpty(args.Data))
                            {
                                _attackLogger.LogInfo(args.Data);
                                
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    if (progressBar != null)
                                    {
                                        // Update status based on nmap output
                                        if (args.Data.Contains("Initiating"))
                                        {
                                            progressBar.IsIndeterminate = true;
                                        }
                                        else if (args.Data.Contains("Stats:"))
                                        {
                                            progressBar.IsIndeterminate = true;
                                            
                                            // Try to parse progress percentage
                                            if (args.Data.Contains("%"))
                                            {
                                                var percentStr = args.Data.Split('%')[0];
                                                percentStr = new string(percentStr.Reverse()
                                                    .TakeWhile(c => char.IsDigit(c) || c == '.')
                                                    .Reverse().ToArray());
                                                
                                                if (double.TryParse(percentStr, out double percent) && progressBar != null)
                                                {
                                                    progressBar.IsIndeterminate = false;
                                                    progressBar.Value = percent;
                                                }
                                            }
                                        }
                                        else if (args.Data.Contains("Completed"))
                                        {
                                            progressBar.IsIndeterminate = true;
                                        }
                                    }
                                });
                            }
                        };

                        process.ErrorDataReceived += (s, args) =>
                        {
                            if (!string.IsNullOrEmpty(args.Data))
                            {
                                _attackLogger.LogError(args.Data);
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    if (progressBar != null)
                                    {
                                        progressBar.IsIndeterminate = true;
                                    }
                                });
                            }
                        };

                        process.Start();
                        process.BeginOutputReadLine();
                        process.BeginErrorReadLine();
                        process.WaitForExit();

                        if (process.ExitCode != 0)
                        {
                            throw new Exception($"nmap exited with code {process.ExitCode}");
                        }
                    }
                    catch (Exception ex) when (ex.Message.Contains("nmap"))
                    {
                        _attackLogger.LogError("nmap is not installed. Please install nmap to use the port scanning feature.");
                        _attackLogger.LogInfo("You can download nmap from: https://nmap.org/download.html");
                        throw;
                    }
                });

                _attackLogger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                _attackLogger.LogInfo("Port scan completed.");
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (progressBar != null)
                    {
                        progressBar.Value = 0;
                        progressBar.Visibility = Visibility.Collapsed;
                    }
                });
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Port scan failed: {ex.Message}");
                MessageBox.Show($"Error during port scan: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (progressBar != null)
                    {
                        progressBar.Value = 0;
                        progressBar.Visibility = Visibility.Collapsed;
                    }
                });
            }
            finally
            {
                if (button != null)
                {
                    button.IsEnabled = true;
                    button.Content = "Scan";
                }
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (progressBar != null)
                    {
                        progressBar.Value = 0;
                        progressBar.Visibility = Visibility.Collapsed;
                    }
                });
            }
        }
    }
} 