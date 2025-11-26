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

        // Statistics tracking
        private long _totalPacketsSent = 0;
        private DateTime _attackStartTime;
        private System.Windows.Threading.DispatcherTimer? _statsTimer;
        private long _targetMbps = 0;

        // Settings
        private string _logFileLocation = string.Empty;
        private int _fontSizeIndex = 1;
        private int _themeIndex = 0;

        public MainWindow()
        {
            InitializeComponent();
            
            // Initialize logger first
            _attackLogger = new AttackLogger(LogTextBox);
            
            // Then initialize components that depend on logger
            _networkStorm = new NetworkStorm(_attackLogger);
            _traceRoute = new TraceRoute(_attackLogger);
            _mainController = new MainController(_networkStorm, StartButton, StopButton, StatusBadge, StatusBadgeText, StatusDot, LogTextBox, this);
            
            // Subscribe to packet sent events for statistics
            _networkStorm.PacketSent += NetworkStorm_PacketSent;
            
            // Initialize statistics timer
            _statsTimer = new System.Windows.Threading.DispatcherTimer();
            _statsTimer.Interval = TimeSpan.FromMilliseconds(100); // Update every 100ms
            _statsTimer.Tick += StatsTimer_Tick;

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
            UpdateProfileSummary();
            LoadSettings();

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

        private void UpdateStatusBadge(string status, string statusType)
        {
            StatusBadgeText.Text = status;
            
            // Update badge style and color based on status type
            switch (statusType.ToLower())
            {
                case "ready":
                case "idle":
                    StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D1FAE5"));
                    StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#059669"));
                    StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#059669"));
                    break;
                case "attacking":
                case "running":
                case "active":
                    StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FEE2E2"));
                    StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E45757"));
                    StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E45757"));
                    break;
                case "error":
                    StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FEE2E2"));
                    StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E45757"));
                    StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E45757"));
                    break;
                default:
                    StatusBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D1FAE5"));
                    StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#059669"));
                    StatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#059669"));
                    break;
            }
        }

        private void NetworkStorm_PacketSent(object? sender, Models.PacketEventArgs e)
        {
            _totalPacketsSent++;
            _attackLogger.IncrementPacketCount();
        }

        private void StatsTimer_Tick(object? sender, EventArgs e)
        {
            if (_attackStartTime != default)
            {
                var elapsed = DateTime.Now - _attackStartTime;
                ElapsedTimeText.Text = elapsed.ToString(@"hh\:mm\:ss");
                
                // Calculate Mbps sent (approximate based on packets and elapsed time)
                if (elapsed.TotalSeconds > 0)
                {
                    // Rough estimate: assume average packet size ~64 bytes (minimum Ethernet frame)
                    // This is a simplified calculation - actual Mbps depends on packet size
                    var bytesSent = _totalPacketsSent * 64; // Approximate
                    var mbpsSent = (bytesSent * 8.0) / (elapsed.TotalSeconds * 1_000_000);
                    MbpsSentText.Text = mbpsSent.ToString("F2");
                }
                
                PacketsSentText.Text = _totalPacketsSent.ToString("N0");
            }
        }

        private void ResetStatistics()
        {
            _totalPacketsSent = 0;
            _attackStartTime = default;
            PacketsSentText.Text = "0";
            ElapsedTimeText.Text = "00:00:00";
            MbpsSentText.Text = "0.00";
        }

        private void UpdateProfileSummary()
        {
            try
            {
                var parts = new List<string>();
                
                // Get attack type
                string attackType = "None";
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    var advType = (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString();
                    if (!string.IsNullOrEmpty(advType))
                        attackType = advType;
                }
                else
                {
                    var basicType = (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString();
                    if (!string.IsNullOrEmpty(basicType))
                        attackType = basicType;
                }

                // Get Mbps
                string mbps = "0";
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    mbps = AdvMegabitsPerSecondTextBox.Text;
                }
                else
                {
                    mbps = MegabitsPerSecondTextBox.Text;
                }

                if (attackType != "None" && !string.IsNullOrEmpty(mbps))
                {
                    parts.Add($"Profile: {attackType} ({mbps} Mbps)");
                }

                // Get NIC
                string nicName = "";
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    var advNic = AdvNetworkInterfaceComboBox.SelectedItem as dynamic;
                    nicName = advNic?.Interface?.Description ?? "";
                }
                else
                {
                    var basicNic = NetworkInterfaceComboBox.SelectedItem as dynamic;
                    nicName = basicNic?.Interface?.Description ?? "";
                }

                if (!string.IsNullOrEmpty(nicName))
                {
                    parts.Add($"NIC: {nicName}");
                }

                // Get Target
                string targetIp = "";
                string targetPort = "";
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text;
                    targetPort = AdvTargetPortTextBox.Text;
                }
                else
                {
                    targetIp = TargetIpTextBox.Text;
                    targetPort = TargetPortTextBox.Text;
                }

                if (!string.IsNullOrEmpty(targetIp))
                {
                    var targetStr = string.IsNullOrEmpty(targetPort) || targetPort == "0" 
                        ? targetIp 
                        : $"{targetIp}:{targetPort}";
                    parts.Add($"Target: {targetStr}");
                }

                // Get Mode
                string mode = MainTabControl.SelectedItem == AdvancedTab ? "Advanced" : "Basic";
                parts.Add($"Mode: {mode}");

                // Format profile on single line with proper spacing
                ProfileSummaryText.Text = string.Join("  |  ", parts);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error updating profile summary");
            }
        }

        private void SettingsButton_Click(object sender, RoutedEventArgs e)
        {
            var settingsWindow = new SettingsWindow(_logFileLocation, _fontSizeIndex, _themeIndex)
            {
                Owner = this
            };

            if (settingsWindow.ShowDialog() == true)
            {
                _logFileLocation = settingsWindow.LogLocation;
                _fontSizeIndex = settingsWindow.FontSizeIndex;
                _themeIndex = settingsWindow.ThemeIndex;
                SaveSettings();
                ApplyUISettings();
            }
        }

        private void LoadSettings()
        {
            try
            {
                // Load from user settings or use defaults
                var settingsFile = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "DoS SeaCure",
                    "settings.txt");

                if (System.IO.File.Exists(settingsFile))
                {
                    var lines = System.IO.File.ReadAllLines(settingsFile);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("LogLocation="))
                            _logFileLocation = line.Substring("LogLocation=".Length);
                        else if (line.StartsWith("FontSizeIndex="))
                            int.TryParse(line.Substring("FontSizeIndex=".Length), out _fontSizeIndex);
                        else if (line.StartsWith("ThemeIndex="))
                            int.TryParse(line.Substring("ThemeIndex=".Length), out _themeIndex);
                    }
                }
                else
                {
                    // Default to installation directory
                    _logFileLocation = AppDomain.CurrentDomain.BaseDirectory;
                }

                ApplyUISettings();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error loading settings");
                _logFileLocation = AppDomain.CurrentDomain.BaseDirectory;
            }
        }

        private void SaveSettings()
        {
            try
            {
                var settingsDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "DoS SeaCure");

                if (!System.IO.Directory.Exists(settingsDir))
                {
                    System.IO.Directory.CreateDirectory(settingsDir);
                }

                var settingsFile = System.IO.Path.Combine(settingsDir, "settings.txt");
                var lines = new[]
                {
                    $"LogLocation={_logFileLocation}",
                    $"FontSizeIndex={_fontSizeIndex}",
                    $"ThemeIndex={_themeIndex}"
                };

                System.IO.File.WriteAllLines(settingsFile, lines);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error saving settings");
                MessageBox.Show(
                    $"Error saving settings: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        private void ApplyUISettings()
        {
            try
            {
                // Apply font size
                double fontSize = _fontSizeIndex switch
                {
                    0 => 11,
                    1 => 12,
                    2 => 14,
                    _ => 12
                };

                // Apply to log textbox
                LogTextBox.FontSize = fontSize;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error applying UI settings");
            }
        }

        private void HelpButton_Click(object sender, RoutedEventArgs e)
        {
            var helpText = "DoS SeaCure - Network Attack Simulator\n\n" +
                "Version: 2.0.1\n\n" +
                "WHAT IS THIS PROGRAM?\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "DoS SeaCure is a professional network security testing tool designed " +
                "for authorized penetration testing and security assessment.\n\n" +
                "PURPOSE:\n" +
                "• Simulate various DoS (Denial of Service) attack scenarios\n" +
                "• Test network infrastructure resilience and security\n" +
                "• Validate firewall and intrusion detection systems\n" +
                "• Conduct authorized security assessments in controlled environments\n\n" +
                "FEATURES:\n" +
                "• Multiple attack types: TCP SYN Flood, UDP Flood, ICMP Flood, ARP Spoofing\n" +
                "• Ethernet-level attacks (Unicast, Multicast, Broadcast)\n" +
                "• Configurable attack rates and parameters\n" +
                "• Real-time statistics and logging\n" +
                "• Network interface selection and gateway routing\n\n" +
                "⚠️ WARNING:\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                "This tool is for AUTHORIZED TESTING ONLY.\n" +
                "• Use only in controlled lab/test environments\n" +
                "• Never use against production systems without explicit permission\n" +
                "• Unauthorized use may be illegal and result in criminal charges\n" +
                "• Users are responsible for compliance with all applicable laws\n\n" +
                "For more information, visit:\n" +
                "https://www.sea-net.co.kr/seacure\n\n" +
                "Copyright(C) SeaNet Co., Ltd. All right reserved";

            MessageBox.Show(
                helpText,
                "Help - About DoS SeaCure",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

        private void SaveLogButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Use saved log location or default to installation directory
                string logLocation = string.IsNullOrEmpty(_logFileLocation) 
                    ? AppDomain.CurrentDomain.BaseDirectory 
                    : _logFileLocation;
                
                var saveFileDialog = new SaveFileDialog
                {
                    Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                    DefaultExt = ".txt",
                    FileName = GenerateLogFileName(),
                    InitialDirectory = logLocation
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    System.IO.File.WriteAllText(saveFileDialog.FileName, LogTextBox.Text);
                    _attackLogger.LogSuccess($"Log saved to: {saveFileDialog.FileName}");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving log: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error saving log: {ex.Message}");
            }
        }

        private string GenerateLogFileName()
        {
            try
            {
                // Get current values
                string sourceIp = MainTabControl.SelectedItem == AdvancedTab 
                    ? AdvSourceIpTextBox.Text.Trim() 
                    : SourceIpTextBox.Text.Trim();
                
                string targetIp = MainTabControl.SelectedItem == AdvancedTab 
                    ? AdvTargetIpTextBox.Text.Trim() 
                    : TargetIpTextBox.Text.Trim();
                
                string attackType = "None";
                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    var advType = (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString();
                    if (!string.IsNullOrEmpty(advType))
                        attackType = advType.Replace(" ", "_");
                }
                else
                {
                    var basicType = (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString();
                    if (!string.IsNullOrEmpty(basicType))
                        attackType = basicType.Replace(" ", "_");
                }

                // Sanitize values for filename
                sourceIp = string.IsNullOrEmpty(sourceIp) ? "unknown" : sourceIp.Replace(".", "_");
                targetIp = string.IsNullOrEmpty(targetIp) ? "unknown" : targetIp.Replace(".", "_");
                attackType = string.IsNullOrEmpty(attackType) ? "None" : attackType.Replace(" ", "_").Replace("(", "").Replace(")", "");

                // Format: datetime_srcip_to_targetip_attacktype.txt
                var fileName = $"{DateTime.Now:yyyyMMdd_HHmmss}_{sourceIp}_to_{targetIp}_{attackType}.txt";
                
                // Remove invalid filename characters
                var invalidChars = System.IO.Path.GetInvalidFileNameChars();
                foreach (var c in invalidChars)
                {
                    fileName = fileName.Replace(c, '_');
                }

                return fileName;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error generating log filename");
                return $"attack_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
            }
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            try
            {
                // Stop statistics timer
                _statsTimer?.Stop();

                // Stop any running attacks
                if (StartButton.IsEnabled == false)
                {
                    try
                    {
                        _mainController.StopAttackAsync(_totalPacketsSent).Wait(TimeSpan.FromSeconds(2));
                    }
                    catch (Exception ex)
                    {
                        _logger.Warn(ex, "Error stopping attack on close");
                    }
                }

                // Auto-save log
                if (!string.IsNullOrEmpty(LogTextBox.Text))
                {
                    try
                    {
                        string logLocation = string.IsNullOrEmpty(_logFileLocation) 
                            ? AppDomain.CurrentDomain.BaseDirectory 
                            : _logFileLocation;

                        // Ensure directory exists
                        if (!System.IO.Directory.Exists(logLocation))
                        {
                            System.IO.Directory.CreateDirectory(logLocation);
                        }

                        string fileName = GenerateLogFileName();
                        string fullPath = System.IO.Path.Combine(logLocation, fileName);

                        System.IO.File.WriteAllText(fullPath, LogTextBox.Text);
                        _logger.Info($"Log auto-saved to: {fullPath}");
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(ex, "Error auto-saving log on close");
                        // Don't prevent window from closing if save fails
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in Window_Closing");
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
                    _attackLogger.LogPing(targetIp, true, (int)result.RoundtripTime);
                    
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
                    _attackLogger.LogPing(targetIp, false);
                    
                    // Auto-enable fallback mode when ping fails
                    var fallbackCheckBox = (sender == PingButton) ? MacFallbackCheckBox : AdvMacFallbackCheckBox;
                    if (fallbackCheckBox != null && (!fallbackCheckBox.IsChecked.HasValue || !fallbackCheckBox.IsChecked.Value))
                    {
                        fallbackCheckBox.IsChecked = true;
                        _attackLogger.LogInfo("📝 Fallback mode enabled automatically due to ping failure - Manual MAC entry available");
                    }
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
                                _attackLogger.LogWarning($"Cannot resolve MAC for {targetIp} - Not on local network");
                                return false;
                            }
                            else
                            {
                                _attackLogger.LogInfo("🌐 Source and target are on different subnets - Gateway required");
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
                var fallbackCheckBox = (sender == ResolveMacButton) ? MacFallbackCheckBox : AdvMacFallbackCheckBox;

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                _attackLogger.LogInfo($"🔍 Resolving MAC address for {targetIp}...");

                // First, try to ping the target to populate ARP cache
                var pingResult = await _mainController.PingHostAsync(targetIp);
                if (!pingResult.Success)
                {
                    _attackLogger.LogWarning($"Ping failed for {targetIp} - MAC resolution may fail. Fallback mode available for manual entry.");
                }

                // Check if target is on different subnet
                if (!CheckSubnetAndGatewayRequirement(targetIp, true))
                {
                    // For external IPs, use the gateway MAC
                    if (string.IsNullOrWhiteSpace(_networkStorm.GatewayIp))
                    {
                        _attackLogger.LogError("Gateway IP not configured. Cannot resolve MAC for external target.");
                        targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                        
                        // Enable fallback mode if not already enabled
                        if (fallbackCheckBox != null && (!fallbackCheckBox.IsChecked.HasValue || !fallbackCheckBox.IsChecked.Value))
                        {
                            fallbackCheckBox.IsChecked = true;
                            _attackLogger.LogInfo("📝 Fallback mode enabled - Please enter gateway MAC address manually");
                        }
                        return;
                    }

                    var gatewayMac = await _mainController.GetMacAddressAsync(_networkStorm.GatewayIp);
                    if (gatewayMac.Length > 0)
                    {
                        var macAddress = BitConverter.ToString(gatewayMac).Replace("-", ":");
                        targetMacTextBox.Text = macAddress;
                        targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(200, 255, 200));
                        _attackLogger.LogMacResolution(targetIp, macAddress, true);

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
                        _attackLogger.LogError($"Failed to resolve gateway MAC address for {_networkStorm.GatewayIp} - Required for routed target");
                        targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                        
                        // Enable fallback mode if not already enabled
                        if (fallbackCheckBox != null && (!fallbackCheckBox.IsChecked.HasValue || !fallbackCheckBox.IsChecked.Value))
                        {
                            fallbackCheckBox.IsChecked = true;
                            _attackLogger.LogInfo("📝 Fallback mode enabled - Please enter MAC address manually");
                        }
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
                        _attackLogger.LogMacResolution(targetIp, macAddress, false);

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
                        _attackLogger.LogWarning($"Could not resolve MAC address for {targetIp}. Target may be blocking ping/ARP or not responding.");
                        _attackLogger.LogInfo("This is normal if the target has firewall rules blocking ICMP or ARP requests.");
                    targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                        
                        // Enable fallback mode if not already enabled
                        if (fallbackCheckBox != null && (!fallbackCheckBox.IsChecked.HasValue || !fallbackCheckBox.IsChecked.Value))
                        {
                            fallbackCheckBox.IsChecked = true;
                            _attackLogger.LogInfo("📝 Fallback mode enabled - Target MAC field is now editable for manual entry");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error resolving MAC address: {ex.Message}");
                _attackLogger.LogInfo("This is normal if the target blocks ICMP/ARP requests. Use fallback mode to enter MAC manually.");
                var targetMacTextBox = (sender == ResolveMacButton) ? TargetMacTextBox : AdvTargetMacTextBox;
                var fallbackCheckBox = (sender == ResolveMacButton) ? MacFallbackCheckBox : AdvMacFallbackCheckBox;
                targetMacTextBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                
                // Enable fallback mode on error
                if (fallbackCheckBox != null && (!fallbackCheckBox.IsChecked.HasValue || !fallbackCheckBox.IsChecked.Value))
                {
                    fallbackCheckBox.IsChecked = true;
                    _attackLogger.LogInfo("Fallback mode enabled. Please enter MAC address manually.");
                }
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

                    case "Ethernet Unicast (IPv4)":
                    case "Ethernet Unicast (IPv6)":
                    case "Ethernet Multicast (IPv4)":
                    case "Ethernet Multicast (IPv6)":
                    case "Ethernet Broadcast (IPv4)":
                    case "Ethernet Broadcast (IPv6)":
                        await StartEthernetAttackFromBasic(attackType);
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

        private bool ValidateCrossSubnetGateway(string targetIp, string sourceIp)
        {
            try
            {
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
                        // Use actual subnet mask
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
                            // Check if gateway is set
                            var gatewayIp = GatewayIpTextBox.Text.Trim();
                            if (string.IsNullOrWhiteSpace(gatewayIp))
                            {
                                _attackLogger.LogError("Gateway IP is required for cross-subnet targets. Please configure gateway or use a target on the same subnet.");
                                MessageBox.Show("Gateway IP is required for targets on different subnets.\nPlease configure the gateway IP address.", 
                                    "Gateway Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                                return false;
                            }

                            if (!IPAddress.TryParse(gatewayIp, out _))
                            {
                                _attackLogger.LogError("Invalid gateway IP address format.");
                                MessageBox.Show("Invalid gateway IP address format.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                                return false;
                            }
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error validating cross-subnet gateway: {ex.Message}");
                return false;
            }
        }

        private async Task StartFloodAttack(string attackType)
        {
            try
            {
                string targetIp;
                string sourceIp;
                int targetPort;
                long megabitsPerSecond;

                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    sourceIp = AdvSourceIpTextBox.Text.Trim();
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
                    sourceIp = SourceIpTextBox.Text.Trim();
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

                // Validate cross-subnet gateway requirement
                if (!ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                    return;
                }

                var selectedAttackType = attackType switch
                {
                    "UDP Flood" => AttackType.UdpFlood,
                    "TCP SYN Flood" => AttackType.TcpSynFlood,
                    "ICMP Flood" => AttackType.IcmpFlood,
                    _ => throw new ArgumentException($"Unsupported flood attack type: {attackType}")
                };

                // Initialize statistics
                _totalPacketsSent = 0;
                _attackStartTime = DateTime.Now;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                // Get MAC addresses for logging
                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                var targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                
                // Log attack start with comprehensive details
                _attackLogger.StartAttack(selectedAttackType, sourceIp, sourceMacBytes, targetIp, targetMacBytes, megabitsPerSecond, targetPort);

                await _mainController.StartAttackAsync(selectedAttackType, targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to start flood attack: {ex.Message}");
                ResetStatistics();
                _statsTimer?.Stop();
                throw;
            }
        }

        private async Task StartBroadcastAttack()
        {
            try
            {
                string targetIp;
                string sourceIp;
                int targetPort;
                long megabitsPerSecond;

                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    sourceIp = AdvSourceIpTextBox.Text.Trim();
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
                    sourceIp = SourceIpTextBox.Text.Trim();
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

                // Validate cross-subnet gateway requirement
                if (!ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                    return;
                }

                // Initialize statistics
                _totalPacketsSent = 0;
                _attackStartTime = DateTime.Now;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                // Get MAC addresses for logging
                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                var targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                if (targetMacBytes.Length == 0)
                {
                    targetMacBytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // Broadcast MAC
                }

                // Log attack start with comprehensive details
                _attackLogger.StartAttack(AttackType.UdpFlood, sourceIp, sourceMacBytes, targetIp, targetMacBytes, megabitsPerSecond, targetPort);

                await _mainController.StartBroadcastAttackAsync(targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to start broadcast attack: {ex.Message}");
                ResetStatistics();
                _statsTimer?.Stop();
                throw;
            }
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _statsTimer?.Stop();
                
                // Determine which stop method to call based on current attack
                var attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                
                if (attackType == "Broadcast")
                {
                    await _mainController.StopBroadcastAttackAsync(_totalPacketsSent);
                }
                else if (attackType == "ARP Spoofing")
                {
                    await _mainController.StopArpSpoofingAsync(_totalPacketsSent);
                }
                else
                {
                    await _mainController.StopAttackAsync(_totalPacketsSent);
                }
                
                ResetStatistics();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error stopping attack: {ex}");
                ResetStatistics();
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
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Unicast (IPv4)" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Unicast (IPv6)" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Multicast (IPv4)" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Multicast (IPv6)" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Broadcast (IPv4)" });
                AttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Ethernet Broadcast (IPv6)" });

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
                var comboBox = sender as ComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    var ipAddress = selectedInterface.IpAddress.ToString();
                    var macBytes = selectedInterface.Interface.GetPhysicalAddress().GetAddressBytes();
                    var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");

                    // Get subnet mask from network interface
                    byte[] subnetMask = new byte[] { 255, 255, 255, 0 }; // Default fallback
                    NetworkInterface? selectedNic = null;
                    string nicDescription = "Unknown";
                    if (selectedInterface.Interface is NetworkInterface nic)
                    {
                        selectedNic = nic;
                        nicDescription = nic.Description;
                        var ipProps = nic.GetIPProperties();
                        var unicastInfo = ipProps.UnicastAddresses
                            .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                        if (unicastInfo?.IPv4Mask != null)
                        {
                            subnetMask = unicastInfo.IPv4Mask.GetAddressBytes();
                        }
                    }

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

                    _networkStorm.SetSourceInfo(ipAddress, macBytes, subnetMask);
                    
                    // Get gateway for the specific NIC
                    IPAddress? gatewayIp = null;
                    if (selectedNic != null)
                    {
                        gatewayIp = _mainController.GetGatewayForInterface(selectedNic);
                    }
                    
                    // Fallback to calculated gateway if NIC doesn't have one configured
                    if (gatewayIp == null)
                    {
                        gatewayIp = _mainController.CalculateDefaultGateway(ipAddress);
                    }
                    
                    // Always update gateway IP when NIC changes
                    if (gatewayIp != null)
                    {
                        GatewayIpTextBox.Text = gatewayIp.ToString();
                        AdvGatewayIpTextBox.Text = gatewayIp.ToString();
                        _networkStorm.SetGatewayIp(gatewayIp.ToString());
                        _attackLogger.LogSuccess($"Gateway updated: {gatewayIp} (NIC: {nicDescription})");
                    }
                    else
                    {
                        GatewayIpTextBox.Text = string.Empty;
                        AdvGatewayIpTextBox.Text = string.Empty;
                        _networkStorm.SetGatewayIp(string.Empty);
                        _attackLogger.LogWarning($"No gateway found for NIC: {nicDescription}");
                    }
                    
                    // Check subnet for the new interface
                    CheckSubnetAndUpdateGatewayField();
                    UpdateProfileSummary();
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
                    _attackLogger.LogInfo("⚙️  Advanced mode enabled");
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
                    UpdateProfileSummary();
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
                UpdateProfileSummary();
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
            UpdateProfileSummary();
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
                        UpdateProfileSummary();
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
                    UpdateProfileSummary();
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
                    UpdateProfileSummary();
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

        private async Task StartEthernetAttackFromBasic(string attackType)
        {
            try
            {
                string targetIp = TargetIpTextBox.Text.Trim();
                string sourceIp = SourceIpTextBox.Text.Trim();
                if (!int.TryParse(TargetPortTextBox.Text, out int targetPort))
                {
                    MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (!long.TryParse(MegabitsPerSecondTextBox.Text, out long megabitsPerSecond))
                {
                    MessageBox.Show("Invalid rate (Mbps).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Parse attack type to determine packet type and IP version
                bool useIPv6 = attackType.Contains("IPv6");
                EthernetFlood.EthernetPacketType packetType;
                
                if (attackType.Contains("Unicast"))
                    packetType = EthernetFlood.EthernetPacketType.Unicast;
                else if (attackType.Contains("Multicast"))
                    packetType = EthernetFlood.EthernetPacketType.Multicast;
                else if (attackType.Contains("Broadcast"))
                    packetType = EthernetFlood.EthernetPacketType.Broadcast;
                else
                    throw new ArgumentException($"Invalid Ethernet attack type: {attackType}");

                // Validate cross-subnet gateway requirement (only for Unicast IPv4)
                if (packetType == EthernetFlood.EthernetPacketType.Unicast && !useIPv6 && !ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                    return;
                }

                // Initialize statistics
                _totalPacketsSent = 0;
                _attackStartTime = DateTime.Now;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                StartButton.IsEnabled = false;
                StopButton.IsEnabled = true;

                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                var sourceMac = BitConverter.ToString(sourceMacBytes).Replace("-", ":");
                byte[] targetMac;

                if (packetType == EthernetFlood.EthernetPacketType.Unicast && !useIPv6)
                {
                    targetMac = await _mainController.GetMacAddressAsync(targetIp);
                    if (targetMac.Length == 0)
                    {
                        _attackLogger.LogError("Failed to resolve target MAC address. Please enable fallback mode and enter MAC manually.");
                        StartButton.IsEnabled = true;
                        StopButton.IsEnabled = false;
                        return;
                    }
                }
                else
                {
                    targetMac = packetType switch
                    {
                        EthernetFlood.EthernetPacketType.Multicast => useIPv6 
                            ? new byte[] { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 }
                            : new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 },
                        EthernetFlood.EthernetPacketType.Broadcast => new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
                        _ => new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
                    };
                }

                // Initialize statistics
                _totalPacketsSent = 0;
                _attackStartTime = DateTime.Now;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                _attackLogger.LogInfo($"Starting Ethernet {packetType} attack ({attackType})");
                _attackLogger.LogInfo($"Source: {sourceIp} ({sourceMac}), Target: {targetIp}, Rate: {megabitsPerSecond} Mbps");

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, megabitsPerSecond, packetType, useIPv6);
            }
            catch (Exception ex)
            {
                ResetStatistics();
                _statsTimer?.Stop();
                StartButton.IsEnabled = true;
                StopButton.IsEnabled = false;
                _attackLogger.LogError($"Failed to start Ethernet attack: {ex.Message}");
                throw;
            }
        }

        private async Task StartEthernetAttack(EthernetFlood.EthernetPacketType packetType)
        {
            try
            {
                string targetIp = AdvTargetIpTextBox.Text.Trim();
                string sourceIp = AdvSourceIpTextBox.Text.Trim();
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

                // Validate cross-subnet gateway requirement (only for Unicast)
                if (packetType == EthernetFlood.EthernetPacketType.Unicast && !ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                    return;
                }

                StartAdvancedAttackButton.IsEnabled = false;
                StopAdvancedAttackButton.IsEnabled = true;

                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                var localSourceIp = await _mainController.GetLocalIpAddressAsync();
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
                    localSourceIp,
                    sourceMacBytes,
                    targetIp,
                    targetMac,
                    megabitsPerSecond,
                    targetPort
                );

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, megabitsPerSecond, packetType, false);
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
                _statsTimer?.Stop();
                if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem)
                {
                    var attackType = selectedItem.Content.ToString();
                    switch (attackType)
                    {
                        case "ARP Spoofing":
                            await _mainController.StopArpSpoofingAsync(_totalPacketsSent);
                            break;
                        default:
                            MessageBox.Show($"Unsupported attack type: {attackType}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            break;
                    }
                }
                ResetStatistics();
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

                // Validate cross-subnet gateway requirement
                if (!ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
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

                // Initialize statistics for ARP Spoofing
                _totalPacketsSent = 0;
                _attackStartTime = DateTime.Now;
                _targetMbps = 0; // ARP spoofing doesn't have Mbps rate
                _statsTimer?.Start();

                // Convert MAC addresses for logging
                // Parse MAC addresses from string format
                byte[] sourceMacBytes = sourceMac.Split(':').Select(b => Convert.ToByte(b, 16)).ToArray();
                byte[] targetMacBytes = targetMac.Split(':').Select(b => Convert.ToByte(b, 16)).ToArray();

                // Log comprehensive ARP Spoofing start
                var arpStartMessage = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                                    $"⚡ Status: Attack Started\n" +
                                    $"📡 Protocol: ARP Spoofing\n" +
                                    $"📍 Source Host: {sourceIp}\n" +
                                    $"🔌 Source MAC: {sourceMac}\n" +
                                    $"🎯 Target Host: {targetIp}\n" +
                                    $"🔌 Target MAC: {targetMac}\n" +
                                    $"🎭 Spoofed MAC: {spoofedMac}\n" +
                                    $"🕐 Start Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
                _attackLogger.LogInfo(arpStartMessage);

            await _mainController.StartArpSpoofingAsync(sourceIp, sourceMac, targetIp, targetMac, spoofedMac);
            }
            catch (Exception ex)
            {
                ResetStatistics();
                _statsTimer?.Stop();
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
                            // Auto-populate gateway if empty
                            if (string.IsNullOrWhiteSpace(GatewayIpTextBox.Text))
                            {
                                var defaultGateway = _mainController.GetDefaultGatewayWithFallback(sourceIp);
                                if (defaultGateway != null)
                                {
                                    GatewayIpTextBox.Text = defaultGateway.ToString();
                                    _networkStorm.SetGatewayIp(defaultGateway.ToString());
                                    _attackLogger.LogSuccess($"Auto-populated gateway: {defaultGateway}");
                                }
                            }
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
                UpdateProfileSummary();
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

                UpdateStatusBadge("Running Trace Route", "running");
                await _traceRoute.ExecuteTraceRouteAsync(targetIp);
                UpdateStatusBadge("Ready", "ready");

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
                UpdateStatusBadge("Error", "error");
            }
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var progressBar = button == ScanButton ? ScanProgressBar : AdvScanProgressBar;
            var portTextBox = MainTabControl.SelectedItem == AdvancedTab ? AdvTargetPortTextBox : TargetPortTextBox;
            
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

                // Get selected attack type to determine protocol
                string attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();

                if (string.IsNullOrEmpty(attackType))
                {
                    MessageBox.Show("Please select an attack type first.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Determine protocol and common ports based on attack type
                ProtocolType protocol;
                int[] portsToScan;

                if (attackType.Contains("TCP") || attackType == "TCP SYN Flood" || attackType == "TcpRoutedFlood")
                {
                    protocol = ProtocolType.Tcp;
                    // Expanded TCP ports - common services and well-known ports
                    portsToScan = new int[] { 
                        // Web servers
                        80, 443, 8080, 8443, 8000, 8888, 9000,
                        // SSH/Telnet
                        22, 23, 2222,
                        // Email
                        25, 110, 143, 993, 995, 587, 465,
                        // DNS
                        53,
                        // FTP
                        21, 20, 2121,
                        // Database
                        3306, 5432, 1433, 1521, 27017, 6379,
                        // Remote Desktop
                        3389, 5900, 5901,
                        // HTTP/HTTPS alternatives
                        8001, 8002, 8081, 8444, 9001,
                        // SMB/File sharing
                        139, 445,
                        // RPC
                        135, 139, 445,
                        // Other common services
                        161, 162, 514, 636, 873, 2049, 3300, 5000, 5001, 5060, 5433, 5902, 5985, 5986, 7001, 7002, 8009, 8010, 8181, 8443, 8880, 9090, 9200, 9300, 10000
                    };
                }
                else if (attackType.Contains("UDP") || attackType == "UDP Flood")
                {
                    protocol = ProtocolType.Udp;
                    // Expanded UDP ports - common services
                    portsToScan = new int[] { 
                        // DNS
                        53,
                        // DHCP
                        67, 68,
                        // TFTP
                        69,
                        // NTP
                        123,
                        // SNMP
                        161, 162,
                        // VPN/IPSec
                        500, 4500,
                        // Syslog
                        514,
                        // RIP
                        520,
                        // NetBIOS
                        137, 138,
                        // UPnP/SSDP
                        1900, 5353,
                        // Other common UDP services
                        111, 1194, 1812, 1813, 2049, 5060, 5061, 10000
                    };
                }
                else if (attackType.Contains("ICMP") || attackType == "ICMP Flood")
                {
                    // ICMP doesn't use ports
                    MessageBox.Show("ICMP Flood does not use ports. Port scanning is not applicable.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                else if (attackType.Contains("Ethernet") || attackType == "ARP Spoofing" || attackType == "Broadcast")
                {
                    // These don't use ports
                    MessageBox.Show($"{attackType} does not use ports. Port scanning is not applicable.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                else
                {
                    // Default to TCP with expanded port list
                    protocol = ProtocolType.Tcp;
                    portsToScan = new int[] { 
                        // Web servers
                        80, 443, 8080, 8443, 8000, 8888, 9000,
                        // SSH/Telnet
                        22, 23, 2222,
                        // Email
                        25, 110, 143, 993, 995, 587, 465,
                        // DNS
                        53,
                        // FTP
                        21, 20, 2121,
                        // Database
                        3306, 5432, 1433, 1521, 27017, 6379,
                        // Remote Desktop
                        3389, 5900, 5901,
                        // HTTP/HTTPS alternatives
                        8001, 8002, 8081, 8444, 9001,
                        // SMB/File sharing
                        139, 445,
                        // RPC
                        135, 139, 445,
                        // Other common services
                        161, 162, 514, 636, 873, 2049, 3300, 5000, 5001, 5060, 5433, 5902, 5985, 5986, 7001, 7002, 8009, 8010, 8181, 8443, 8880, 9090, 9200, 9300, 10000
                    };
                }

                if (button != null)
                {
                    button.IsEnabled = false;
                    button.Content = "Scanning...";
                }

                // Show progress bar
                if (progressBar != null)
                {
                    progressBar.Value = 0;
                    progressBar.Maximum = portsToScan.Length;
                    progressBar.IsIndeterminate = false;
                    progressBar.Visibility = Visibility.Visible;
                }

                _attackLogger.LogInfo($"🔍 Quick {protocol} port scan on {targetIp}...");
                _attackLogger.LogInfo($"Scanning {portsToScan.Length} common {protocol} ports...");

                // Quick port scan
                int? foundPort = null;
                await Task.Run(async () =>
                {
                    try
                    {
                        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30)); // 30 second timeout
                        
                        foreach (var port in portsToScan)
                        {
                            if (cts.Token.IsCancellationRequested)
                                break;

                            try
                            {
                                bool isOpen = false;
                                
                                if (protocol == ProtocolType.Tcp)
                                {
                                    // TCP port check
                                    using (var client = new TcpClient())
                                    {
                                        var connectTask = client.ConnectAsync(targetIp, port);
                                        var timeoutTask = Task.Delay(500, cts.Token); // 500ms timeout per port
                                        var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                                        
                                        if (completedTask == connectTask && connectTask.IsCompletedSuccessfully)
                                        {
                                            isOpen = client.Connected;
                                        }
                                    }
                                }
                                else if (protocol == ProtocolType.Udp)
                                {
                                    // UDP port check - try to send and check for ICMP unreachable
                                    using (var client = new UdpClient())
                                    {
                                        try
                                        {
                                            client.Client.ReceiveTimeout = 500;
                                            client.Client.SendTimeout = 500;
                                            await client.SendAsync(new byte[] { 0 }, 1, targetIp, port);
                                            await Task.Delay(200, cts.Token);
                                            
                                            // If we can send without immediate error, port might be open
                                            // UDP is connectionless so we can't definitively know, but this is a quick scan
                                            isOpen = true;
                                        }
                                        catch (SocketException)
                                        {
                                            // ICMP unreachable or other error - port likely closed/filtered
                                            isOpen = false;
                                        }
                                        catch
                                        {
                                            isOpen = false;
                                        }
                                    }
                                }
                                
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    if (progressBar != null)
                                    {
                                        progressBar.Value++;
                                    }
                                });

                                if (isOpen)
                                {
                                    foundPort = port;
                                    _attackLogger.LogSuccess($"✅ Found open {protocol} port: {port}");
                                    cts.Cancel(); // Stop scanning once we find one
                                    break;
                                }
                            }
                            catch (Exception ex)
                            {
                                // Port is likely closed or filtered, continue
                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    if (progressBar != null)
                                    {
                                        progressBar.Value++;
                                    }
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _attackLogger.LogError($"Port scan error: {ex.Message}");
                    }
                });

                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (foundPort.HasValue)
                    {
                        portTextBox.Text = foundPort.Value.ToString();
                        _attackLogger.LogSuccess($"✅ Port {foundPort.Value} set in Target Port field");
                    }
                    else
                    {
                        _attackLogger.LogWarning($"⚠️ No open {protocol} ports found in common ports. Try scanning more ports or enter port manually.");
                    }

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

        private async void FullPortScanButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var progressBar = MainTabControl.SelectedItem == AdvancedTab ? AdvScanProgressBar : ScanProgressBar;
            var portTextBox = MainTabControl.SelectedItem == AdvancedTab ? AdvTargetPortTextBox : TargetPortTextBox;
            
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

                // Get selected attack type to determine protocol
                string attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();

                if (string.IsNullOrEmpty(attackType))
                {
                    MessageBox.Show("Please select an attack type first.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Determine protocol based on attack type
                ProtocolType protocol;

                if (attackType.Contains("TCP") || attackType == "TCP SYN Flood" || attackType == "TcpRoutedFlood")
                {
                    protocol = ProtocolType.Tcp;
                }
                else if (attackType.Contains("UDP") || attackType == "UDP Flood")
                {
                    protocol = ProtocolType.Udp;
                }
                else if (attackType.Contains("ICMP") || attackType == "ICMP Flood")
                {
                    MessageBox.Show("ICMP Flood does not use ports. Port scanning is not applicable.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                else if (attackType.Contains("Ethernet") || attackType == "ARP Spoofing" || attackType == "Broadcast")
                {
                    MessageBox.Show($"{attackType} does not use ports. Port scanning is not applicable.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                else
                {
                    protocol = ProtocolType.Tcp; // Default to TCP
                }

                // Show warning for full scan
                var result = MessageBox.Show(
                    $"Full port scan will check all {protocol} ports (1-65535).\n\n" +
                    "This may take several minutes and could be detected by security systems.\n\n" +
                    "Do you want to continue?",
                    "Full Port Scan Warning",
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

                // Show progress bar
                if (progressBar != null)
                {
                    progressBar.Value = 0;
                    progressBar.Maximum = 65535;
                    progressBar.IsIndeterminate = false;
                    progressBar.Visibility = Visibility.Visible;
                }

                _attackLogger.LogInfo($"🔍 Full {protocol} port scan on {targetIp}...");
                _attackLogger.LogInfo($"Scanning all {protocol} ports (1-65535). This may take several minutes...");
                _attackLogger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

                // Full port scan - scan all ports
                var openPorts = new List<int>();
                var cts = new CancellationTokenSource();
                
                await Task.Run(async () =>
                {
                    try
                    {
                        const int batchSize = 100; // Scan in batches for better progress updates
                        var semaphore = new SemaphoreSlim(50); // Limit concurrent connections
                        var tasks = new List<Task>();

                        for (int port = 1; port <= 65535; port++)
                        {
                            if (cts.Token.IsCancellationRequested)
                                break;

                            var currentPort = port;
                            await semaphore.WaitAsync(cts.Token);

                            tasks.Add(Task.Run(async () =>
                            {
                                try
                                {
                                    bool isOpen = false;

                                    if (protocol == ProtocolType.Tcp)
                                    {
                                        using (var client = new TcpClient())
                                        {
                                            var connectTask = client.ConnectAsync(targetIp, currentPort);
                                            var timeoutTask = Task.Delay(200, cts.Token); // 200ms timeout per port
                                            var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                                            if (completedTask == connectTask && connectTask.IsCompletedSuccessfully)
                                            {
                                                isOpen = client.Connected;
                                            }
                                        }
                                    }
                                    else if (protocol == ProtocolType.Udp)
                                    {
                                        using (var client = new UdpClient())
                                        {
                                            try
                                            {
                                                client.Client.ReceiveTimeout = 200;
                                                client.Client.SendTimeout = 200;
                                                await client.SendAsync(new byte[] { 0 }, 1, targetIp, currentPort);
                                                await Task.Delay(100, cts.Token);
                                                isOpen = true; // UDP is harder to detect
                                            }
                                            catch (SocketException)
                                            {
                                                isOpen = false;
                                            }
                                            catch
                                            {
                                                isOpen = false;
                                            }
                                        }
                                    }

                                    if (isOpen)
                                    {
                                        lock (openPorts)
                                        {
                                            openPorts.Add(currentPort);
                                        }
                                        Application.Current.Dispatcher.Invoke(() =>
                                        {
                                            _attackLogger.LogSuccess($"✅ Found open {protocol} port: {currentPort}");
                                        });
                                    }
                                }
                                catch
                                {
                                    // Port is likely closed, continue
                                }
                                finally
                                {
                                    semaphore.Release();
                
                Application.Current.Dispatcher.Invoke(() =>
                {
                                        if (progressBar != null)
                                        {
                                            progressBar.Value = currentPort;
                                        }
                                    });
                                }
                            }, cts.Token));

                            // Process completed tasks periodically to avoid memory buildup
                            if (tasks.Count >= 500)
                            {
                                var completed = tasks.Where(t => t.IsCompleted).ToList();
                                foreach (var task in completed)
                                {
                                    tasks.Remove(task);
                                }
                                await Task.Delay(10, cts.Token);
                            }
                        }

                        // Wait for remaining tasks
                        await Task.WhenAll(tasks);
                    }
                    catch (Exception ex)
                    {
                        _attackLogger.LogError($"Full port scan error: {ex.Message}");
                    }
                });

                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (openPorts.Any())
                    {
                        openPorts.Sort();
                        var firstPort = openPorts.First();
                        portTextBox.Text = firstPort.ToString();
                        
                        _attackLogger.LogSuccess($"━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        _attackLogger.LogSuccess($"✅ Full scan complete! Found {openPorts.Count} open {protocol} port(s):");
                        foreach (var port in openPorts)
                        {
                            _attackLogger.LogInfo($"   • Port {port}");
                        }
                        _attackLogger.LogSuccess($"✅ Port {firstPort} set in Target Port field");
                        _attackLogger.LogSuccess($"━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    }
                    else
                    {
                        _attackLogger.LogWarning($"⚠️ No open {protocol} ports found in full scan (1-65535).");
                    }

                    if (progressBar != null)
                    {
                        progressBar.Value = 0;
                        progressBar.Visibility = Visibility.Collapsed;
                    }
                });
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Full port scan failed: {ex.Message}");
                MessageBox.Show($"Error during full port scan: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                
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
                    button.Content = "Full Port Scan";
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

        private void MacFallbackCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            try
            {
                var checkBox = sender as System.Windows.Controls.CheckBox;
                if (checkBox == MacFallbackCheckBox)
                {
                    TargetMacTextBox.IsReadOnly = false;
                    _attackLogger.LogInfo("Fallback mode enabled - Target MAC field is now editable for manual entry");
                }
                else if (checkBox == AdvMacFallbackCheckBox)
                {
                    AdvTargetMacTextBox.IsReadOnly = false;
                    _attackLogger.LogInfo("Fallback mode enabled - Target MAC field is now editable for manual entry");
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error enabling fallback mode: {ex.Message}");
            }
        }

        private void MacFallbackCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                var checkBox = sender as System.Windows.Controls.CheckBox;
                if (checkBox == MacFallbackCheckBox)
                {
                    TargetMacTextBox.IsReadOnly = true;
                    _attackLogger.LogInfo("Fallback mode disabled - Target MAC field is now read-only");
                }
                else if (checkBox == AdvMacFallbackCheckBox)
                {
                    AdvTargetMacTextBox.IsReadOnly = true;
                    _attackLogger.LogInfo("Fallback mode disabled - Target MAC field is now read-only");
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error disabling fallback mode: {ex.Message}");
            }
        }

        private void RefreshSourceIpButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Determine which tab we're on
                var isAdvancedTab = MainTabControl.SelectedItem == AdvancedTab;
                var comboBox = isAdvancedTab ? AdvNetworkInterfaceComboBox : NetworkInterfaceComboBox;
                
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    
                    if (selectedInterface.Interface is NetworkInterface nic)
                    {
                        // Refresh IP address from the selected NIC
                        var ipProps = nic.GetIPProperties();
                        var unicastInfo = ipProps.UnicastAddresses
                            .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                        
                        if (unicastInfo?.Address != null)
                        {
                            var ipAddress = unicastInfo.Address.ToString();
                            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
                            var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                            
                            // Get subnet mask
                            byte[] subnetMask = new byte[] { 255, 255, 255, 0 };
                            if (unicastInfo.IPv4Mask != null)
                            {
                                subnetMask = unicastInfo.IPv4Mask.GetAddressBytes();
                            }
                            
                            // Update source IP and MAC in both tabs
                            SourceIpTextBox.Text = ipAddress;
                            SourceMacTextBox.Text = macAddress;
                            AdvSourceIpTextBox.Text = ipAddress;
                            AdvSourceMacTextBox.Text = macAddress;
                            
                            // Update NetworkStorm
                            _networkStorm.SetSourceInfo(ipAddress, macBytes, subnetMask);
                            
                            // Update gateway for this NIC
                            var gatewayIp = _mainController.GetGatewayForInterface(nic);
                            if (gatewayIp == null)
                            {
                                gatewayIp = _mainController.CalculateDefaultGateway(ipAddress);
                            }
                            
                            if (gatewayIp != null)
                            {
                                GatewayIpTextBox.Text = gatewayIp.ToString();
                                AdvGatewayIpTextBox.Text = gatewayIp.ToString();
                                _networkStorm.SetGatewayIp(gatewayIp.ToString());
                                _attackLogger.LogSuccess($"Refreshed - Source IP: {ipAddress} | Gateway: {gatewayIp}");
                            }
                            else
                            {
                                GatewayIpTextBox.Text = string.Empty;
                                AdvGatewayIpTextBox.Text = string.Empty;
                                _networkStorm.SetGatewayIp(string.Empty);
                                _attackLogger.LogInfo($"Refreshed - Source IP: {ipAddress} (no gateway found)");
                            }
                            
                            // Refresh network interface list to get latest info
                            var currentIndex = comboBox.SelectedIndex;
                            PopulateNetworkInterfaces();
                            
                            // Restore selection by index
                            if (currentIndex >= 0 && currentIndex < comboBox.Items.Count)
                            {
                                if (isAdvancedTab)
                                {
                                    AdvNetworkInterfaceComboBox.SelectedIndex = currentIndex;
                                }
                                else
                                {
                                    NetworkInterfaceComboBox.SelectedIndex = currentIndex;
                                }
                            }
                            
                            // Check subnet
                            CheckSubnetAndUpdateGatewayField();
                        }
                        else
                        {
                            _attackLogger.LogWarning("Selected network interface does not have an IPv4 address");
                            MessageBox.Show("Selected network interface does not have an IPv4 address.", 
                                "No IPv4 Address", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                }
                else
                {
                    _attackLogger.LogWarning("No network interface selected");
                    MessageBox.Show("Please select a network interface first.", 
                        "No Interface Selected", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error refreshing source IP: {ex.Message}");
                MessageBox.Show($"Error refreshing source IP: {ex.Message}", 
                    "Refresh Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
} 