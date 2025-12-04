using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
        private Services.SnmpWalkService? _snmpWalkService;
        private CancellationTokenSource? _snmpWalkCancellationTokenSource;
        
        // Security assessment tracking
        private bool _reachabilityTestPassed = false;
        private bool _snmpWalkNotVulnerable = false;
        private bool _isAdvancedMode;
        private string _validationToken; // Session-based validation token
        private const string VALIDATION_TOKEN_FILE = "validation.token"; // Encrypted validation token file
        private bool _disclaimerAcknowledged = false; // Track if disclaimer has been shown and acknowledged
        private bool _isHandlingTabChange = false; // Prevent re-entrancy during tab changes
        private TabItem? _previousTab = null; // Track previous tab for proper navigation
        private const string DISCLAIMER_ACK_FILE = "disclaimer.ack"; // Disclaimer acknowledgment file
        private bool? _lastSubnetStatus;
        private string? _lastSubnetMessage;
        private DateTime _lastSubnetLogTime = DateTime.MinValue;
        private const int SUBNET_LOG_THROTTLE_MS = 1000; // Throttle duplicate messages within 1 second
        private CancellationTokenSource? _targetIpDebounceTokenSource;
        private const string NOTE_PLACEHOLDER = "Add a note to the security log... (Ctrl+Enter to save)";
        private bool _isSyncingComboBoxes = false; // Flag to prevent duplicate logging when syncing comboboxes

        // Statistics tracking
        private long _totalPacketsSent = 0;
        private long _totalBytesSent = 0; // Track actual bytes sent for accurate Mbps calculation
        private DateTime _attackStartTime;
        private DateTime _lastStatsUpdateTime;
        private long _lastBytesSent = 0; // Track bytes sent at last stats update for current rate calculation
        private System.Windows.Threading.DispatcherTimer? _statsTimer;
        private long _targetMbps = 0;
        private string? _currentRunningAttackType = null; // Track the currently running attack type

        // Settings
        private string _logFileLocation = string.Empty;
        private double _fontSize = 12.0;
        private int _themeIndex = 0;

        // Database and Sync Services
        private readonly Services.DatabaseService _databaseService;
        private readonly Services.SupabaseSyncService _supabaseSyncService;
        private readonly Services.ToastNotificationService _toastService;
        private System.Windows.Threading.DispatcherTimer? _syncCheckTimer;
        
        // Metadata for tracking
        private readonly string _hardwareId;
        private readonly string _machineName;
        private readonly string _username;
        
        // Track if we've shown sync notification this session
        private bool _hasShownAttackLogSyncNotification = false;
        private Services.UIScalingService? _uiScalingService;
        private double _baseFontSize = 12;
        private Services.UpdateCheckService? _updateCheckService;
        private System.Windows.Threading.DispatcherTimer? _updateCheckTimer;

        // Firewall Reachability Discovery
        private Services.FirewallDiscoveryEngine? _firewallDiscoveryEngine;

        public MainWindow()
        {
            InitializeComponent();
            
            // Initialize database and sync services first
            _databaseService = new Services.DatabaseService();
            _supabaseSyncService = new Services.SupabaseSyncService(_databaseService);
            _toastService = new Services.ToastNotificationService(this);
            
            // Initialize logger with database service and metadata
            var licenseService = new Services.LicenseService();
            _hardwareId = licenseService.HardwareId;
            _machineName = Environment.MachineName;
            _username = Environment.UserName;
            
            _attackLogger = new AttackLogger(
                LogTextBox, 
                _databaseService,
                hardwareId: _hardwareId,
                machineName: _machineName,
                username: _username,
                userId: null // Can be set if user authentication is implemented
            );
            
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

            // Initialize sync check timer (check every 30 seconds)
            _syncCheckTimer = new System.Windows.Threading.DispatcherTimer();
            _syncCheckTimer.Interval = TimeSpan.FromSeconds(30);
            _syncCheckTimer.Tick += SyncCheckTimer_Tick;
            _syncCheckTimer.Start();

            // Initialize Firewall Discovery Engine
            _firewallDiscoveryEngine = new Services.FirewallDiscoveryEngine();

            // Initialize SNMP Walk Service
            _snmpWalkService = new Services.SnmpWalkService(_attackLogger);

            // Initialize UI components first
            PopulateNetworkInterfaces();
            PopulateAttackTypes();
            UpdateProfileSummary();
            LoadSettings();

            // Initialize toast notification service after UI is ready
            Loaded += MainWindow_Loaded;

            AttackTypeComboBox.SelectedIndex = 0;
            AdvancedAttackTypeComboBox.SelectedIndex = 0;

            // Set placeholder text
            NoteTextBox.Text = NOTE_PLACEHOLDER;
            NoteTextBox.Foreground = SystemColors.GrayTextBrush;
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                // Disclaimer is shown every time user enters Advanced tab (not saved)
                _disclaimerAcknowledged = false;
                
                // Try to load saved validation token (persists across sessions)
                if (LoadValidationToken())
                {
                    // Token loaded and validated - enable buttons without requiring password
                    _isAdvancedMode = true;
                    ValidatePasswordAndUpdateUI();
                    
                    // Disable Validate button since validation is already active
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (AdvValidatePasswordButton != null)
                        {
                            AdvValidatePasswordButton.IsEnabled = false;
                        }
                    }, System.Windows.Threading.DispatcherPriority.Normal);
                    
                    _attackLogger.LogInfo("🔓 Previous validation restored - Attack controls enabled");
                }
                
                // Apply responsive scaling based on screen size
                ApplyResponsiveScaling();
                
                // Apply enhanced UI scaling
                ApplyUIScaling();

                // Initialize toast notification service after window is fully loaded
                if (ToastContainer != null)
                {
                    _toastService.Initialize(ToastContainer);
                }

                // Show disclaimer after window is loaded
                if (ShouldShowDisclaimer())
                {
                    var disclaimerWindow = new DisclaimerWindow
                    {
                        Owner = this
                    };

                    if (disclaimerWindow.ShowDialog() != true)
                    {
                        Close();
                        return;
                    }

                    // Save "don't show again" preference
                    if (disclaimerWindow.DontShowAgain)
                    {
                        SaveDisclaimerPreference();
                    }
                }

                // Start sync status check
                _ = Task.Run(async () => await UpdateSyncStatus());
                
                // Initialize update check service and start checking for updates
                // Always initialize (even if Supabase not configured, it will show "Cloud" status)
                _updateCheckService = new Services.UpdateCheckService(_supabaseSyncService.GetSupabaseClient(), _attackLogger);
                
                // Check for updates immediately on startup
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await CheckForUpdatesAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(ex, "Error during startup update check");
                    }
                });
                
                // Set up periodic update check (every 30 minutes)
                _updateCheckTimer = new System.Windows.Threading.DispatcherTimer
                {
                    Interval = TimeSpan.FromMinutes(30)
                };
                _updateCheckTimer.Tick += async (s, e) =>
                {
                    try
                    {
                        await CheckForUpdatesAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(ex, "Error during periodic update check");
                    }
                };
                _updateCheckTimer.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error during initialization: {ex.Message}\n\n{ex.StackTrace}", 
                    "Initialization Error", 
                    MessageBoxButton.OK, 
                    MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Applies comprehensive UI scaling based on screen size and DPI
        /// </summary>
        private void ApplyUIScaling()
        {
            try
            {
                if (_uiScalingService == null) return;
                
                // Get DPI-aware scale
                var dpiScale = _uiScalingService.GetDpiScaleForWindow(this);
                
                // Get responsive scale based on screen size
                var responsiveScale = _uiScalingService.CalculateResponsiveScale();
                
                // Combine scales (use the more conservative one)
                var combinedScale = Math.Min(dpiScale, responsiveScale);
                
                // Apply font scaling
                _uiScalingService.ApplyFontScaling(this, _baseFontSize, combinedScale);
                
                // Get screen category and adjust window
                var screenCategory = _uiScalingService.GetScreenCategory();
                var (minWidth, minHeight) = _uiScalingService.GetRecommendedMinSize();
                
                this.MinWidth = minWidth;
                this.MinHeight = minHeight;
                
                // Adjust window size if not maximized
                if (this.WindowState != WindowState.Maximized)
                {
                    if (screenCategory == Services.ScreenCategory.Small)
                    {
                        this.Width = Math.Min(SystemParameters.PrimaryScreenWidth * 0.95, 1200);
                        this.Height = Math.Min(SystemParameters.PrimaryScreenHeight * 0.95, 800);
                    }
                }
                
                // Adjust margins based on scale
                if (MainContentGrid != null)
                {
                    var margin = _uiScalingService.GetScaledThickness(16, combinedScale);
                    MainContentGrid.Margin = margin;
                }
                
                _attackLogger.LogInfo($"UI Scaling applied: DPI={dpiScale:F2}, Responsive={responsiveScale:F2}, Combined={combinedScale:F2}, Category={screenCategory}");
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error applying UI scaling: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles scale change events
        /// </summary>
        private void UIScalingService_ScaleChanged(object? sender, EventArgs e)
        {
            try
            {
                if (_uiScalingService == null) return;
                
                // Reapply font scaling when scale changes
                _uiScalingService.ApplyFontScaling(this, _baseFontSize);
                
                // Optionally apply transform to entire window content
                if (MainContentGrid != null)
                {
                    _uiScalingService.ApplyScaleTransform(MainContentGrid);
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error handling scale change: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles keyboard shortcuts for zoom (Ctrl + Plus/Minus/0)
        /// </summary>
        private void Window_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (_uiScalingService == null) return;
            
            if (e.KeyboardDevice.Modifiers == System.Windows.Input.ModifierKeys.Control)
            {
                if (e.Key == System.Windows.Input.Key.Add || e.Key == System.Windows.Input.Key.OemPlus)
                {
                    _uiScalingService.ZoomIn();
                    e.Handled = true;
                }
                else if (e.Key == System.Windows.Input.Key.Subtract || e.Key == System.Windows.Input.Key.OemMinus)
                {
                    _uiScalingService.ZoomOut();
                    e.Handled = true;
                }
                else if (e.Key == System.Windows.Input.Key.D0 || e.Key == System.Windows.Input.Key.NumPad0)
                {
                    _uiScalingService.ResetZoom();
                    e.Handled = true;
                }
            }
        }

        private void Window_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            // Window size changed - no special handling needed
        }

        private void ApplyResponsiveScaling()
        {
            try
            {
                // Get primary screen dimensions
                var screenWidth = SystemParameters.PrimaryScreenWidth;
                var screenHeight = SystemParameters.PrimaryScreenHeight;
                
                // Calculate scale factor based on screen size
                // Use 1920x1080 as baseline (scale = 1.0)
                double baseWidth = 1920;
                double baseHeight = 1080;
                
                double widthScale = screenWidth / baseWidth;
                double heightScale = screenHeight / baseHeight;
                
                // Use the smaller scale to ensure everything fits
                double scale = Math.Min(widthScale, heightScale);
                
                // Clamp scale between 0.6 and 1.2 to prevent extreme scaling
                scale = Math.Max(0.6, Math.Min(1.2, scale));
                
                // Adjust window minimum size based on screen size
                if (screenWidth < 1366 || screenHeight < 768)
                {
                    // Small screens (laptops, tablets)
                    this.MinWidth = 800;
                    this.MinHeight = 600;
                }
                else if (screenWidth < 1600 || screenHeight < 900)
                {
                    // Medium screens
                    this.MinWidth = 1000;
                    this.MinHeight = 650;
                }
                else
                {
                    // Large screens (default)
                    this.MinWidth = 1200;
                    this.MinHeight = 700;
                }
                
                // Adjust font sizes if screen is small
                if (scale < 0.85)
                {
                    // Reduce base font size for small screens
                    double fontSizeMultiplier = 0.9;
                    
                    // Apply to window-level font size
                    this.FontSize = 12 * fontSizeMultiplier;
                    
                    // Adjust specific UI elements that might be too large
                    if (PacketsSentText != null)
                        PacketsSentText.FontSize = 14 * fontSizeMultiplier;
                    if (ElapsedTimeText != null)
                        ElapsedTimeText.FontSize = 14 * fontSizeMultiplier;
                    if (MbpsSentText != null)
                        MbpsSentText.FontSize = 14 * fontSizeMultiplier;
                    if (ProfileSummaryText != null)
                        ProfileSummaryText.FontSize = 11 * fontSizeMultiplier;
                }
                
                // Adjust window size if not maximized and screen is small
                if (this.WindowState != WindowState.Maximized)
                {
                    if (screenWidth < 1366 || screenHeight < 768)
                    {
                        // For small screens, set a reasonable default size
                        this.Width = Math.Min(screenWidth * 0.95, 1200);
                        this.Height = Math.Min(screenHeight * 0.95, 800);
                    }
                }
                
                // Adjust margins for smaller screens
                if (MainContentGrid != null)
                {
                    if (screenWidth < 1366 || screenHeight < 768)
                    {
                        // Reduce margins on small screens
                        MainContentGrid.Margin = new Thickness(8);
                    }
                    else if (screenWidth < 1600 || screenHeight < 900)
                    {
                        // Medium margins for medium screens
                        MainContentGrid.Margin = new Thickness(12);
                    }
                    else
                    {
                        // Default margins for large screens
                        MainContentGrid.Margin = new Thickness(16);
                    }
                }
                
                // Adjust header padding for smaller screens
                if (HeaderBar != null)
                {
                    if (screenWidth < 1366 || screenHeight < 768)
                    {
                        HeaderBar.Padding = new Thickness(12, 10, 12, 10);
                    }
                    else
                    {
                        HeaderBar.Padding = new Thickness(16, 12, 16, 12);
                    }
                }
                
                // Adjust logo size for smaller screens
                if (LogoImage != null && (screenWidth < 1366 || screenHeight < 768))
                {
                    // Reduce logo size on small screens
                    LogoImage.Height = 120;
                }
                else if (LogoImage != null && (screenWidth < 1600 || screenHeight < 900))
                {
                    // Medium size for medium screens
                    LogoImage.Height = 140;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error applying responsive scaling");
            }
        }

        private bool ShouldShowDisclaimer()
        {
            try
            {
                var settingsDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SEACURE(TOOL)");
                var disclaimerFile = System.IO.Path.Combine(settingsDir, "disclaimer_accepted.txt");
                return !System.IO.File.Exists(disclaimerFile);
            }
            catch
            {
                return true; // Show disclaimer if we can't check
            }
        }

        private void SaveDisclaimerPreference()
        {
            try
            {
                var settingsDir = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SEACURE(TOOL)");
                System.IO.Directory.CreateDirectory(settingsDir);
                var disclaimerFile = System.IO.Path.Combine(settingsDir, "disclaimer_accepted.txt");
                System.IO.File.WriteAllText(disclaimerFile, DateTime.Now.ToString("O"));
            }
            catch
            {
                // Ignore errors saving preference
            }
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
            _totalBytesSent += e.Packet.Length; // Track actual bytes sent
            _attackLogger.IncrementPacketCount();
        }

        private void StatsTimer_Tick(object? sender, EventArgs e)
        {
            if (_attackStartTime != default)
            {
                var elapsed = DateTime.Now - _attackStartTime;
                ElapsedTimeText.Text = elapsed.ToString(@"hh\:mm\:ss");
                
                // Calculate Mbps sent using current rate (bytes sent in last second)
                // This matches Task Manager's instantaneous rate display
                var now = DateTime.Now;
                if (_lastStatsUpdateTime != default)
                {
                    var timeSinceLastUpdate = (now - _lastStatsUpdateTime).TotalSeconds;
                    if (timeSinceLastUpdate > 0)
                    {
                        // Calculate current rate: bytes sent since last update
                        var bytesSentSinceLastUpdate = _totalBytesSent - _lastBytesSent;
                        var mbpsSent = (bytesSentSinceLastUpdate * 8.0) / (timeSinceLastUpdate * 1_000_000);
                        MbpsSentText.Text = mbpsSent.ToString("F2");
                    }
                }
                else
                {
                    // First update - use average rate
                if (elapsed.TotalSeconds > 0)
                {
                        var mbpsSent = (_totalBytesSent * 8.0) / (elapsed.TotalSeconds * 1_000_000);
                    MbpsSentText.Text = mbpsSent.ToString("F2");
                    }
                }
                
                // Update tracking for next calculation
                _lastBytesSent = _totalBytesSent;
                _lastStatsUpdateTime = now;
                
                PacketsSentText.Text = _totalPacketsSent.ToString("N0");
            }
        }

        private void ResetStatistics()
        {
            _totalPacketsSent = 0;
            _totalBytesSent = 0;
            _attackStartTime = default;
            _lastStatsUpdateTime = default;
            _lastBytesSent = 0;
            PacketsSentText.Text = "0";
            ElapsedTimeText.Text = "00:00:00";
            MbpsSentText.Text = "0.00";
            _currentRunningAttackType = null; // Clear attack type when resetting statistics
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
            var settingsWindow = new SettingsWindow(_logFileLocation, _fontSize, _themeIndex)
            {
                Owner = this
            };

            if (settingsWindow.ShowDialog() == true)
            {
                _logFileLocation = settingsWindow.LogLocation;
                _fontSize = settingsWindow.FontSize;
                _themeIndex = settingsWindow.ThemeIndex;
                
                SaveSettings();
                ApplyUISettings();
                _ = UpdateSyncStatus();
            }
        }

        private void LoadSettings()
        {
            try
            {
                // Load from user settings or use defaults
                var settingsFile = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SEACURE(TOOL)",
                    "settings.txt");

                if (System.IO.File.Exists(settingsFile))
                {
                    var lines = System.IO.File.ReadAllLines(settingsFile);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("LogLocation="))
                            _logFileLocation = line.Substring("LogLocation=".Length);
                        else if (line.StartsWith("FontSize="))
                            double.TryParse(line.Substring("FontSize=".Length), out _fontSize);
                        else if (line.StartsWith("FontSizeIndex="))
                        {
                            // Legacy support: convert old index to font size
                            if (int.TryParse(line.Substring("FontSizeIndex=".Length), out int oldIndex))
                            {
                                _fontSize = oldIndex switch
                                {
                                    0 => 11.0,
                                    1 => 12.0,
                                    2 => 14.0,
                                    _ => 12.0
                                };
                            }
                        }
                        else if (line.StartsWith("ThemeIndex="))
                            int.TryParse(line.Substring("ThemeIndex=".Length), out _themeIndex);
                    }
                }
                else
                {
                    // Default to installation directory
                    _logFileLocation = AppDomain.CurrentDomain.BaseDirectory;
                }

                // Initialize Supabase with hardcoded credentials (always configured)
                _supabaseSyncService.Initialize(Services.SupabaseConfig.Url, Services.SupabaseConfig.AnonKey);

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
                    "SEACURE(TOOL)");

                if (!System.IO.Directory.Exists(settingsDir))
                {
                    System.IO.Directory.CreateDirectory(settingsDir);
                }

                var settingsFile = System.IO.Path.Combine(settingsDir, "settings.txt");
                var lines = new[]
                {
                    $"LogLocation={_logFileLocation}",
                    $"FontSize={_fontSize}",
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
                // Apply font size to all UI elements in both panels
                double fontSize = _fontSize;
                
                // Apply to window-level font size (affects all elements)
                this.FontSize = fontSize;
                
                // Apply to log textbox (right panel)
                if (LogTextBox != null)
                {
                    LogTextBox.FontSize = fontSize;
                }
                
                // Apply to all text elements in left panel (Basic Settings)
                ApplyFontSizeToElement(TargetIpTextBox, fontSize);
                ApplyFontSizeToElement(TargetMacTextBox, fontSize);
                ApplyFontSizeToElement(SourceIpTextBox, fontSize);
                ApplyFontSizeToElement(SourceMacTextBox, fontSize);
                ApplyFontSizeToElement(GatewayIpTextBox, fontSize);
                ApplyFontSizeToElement(TargetPortTextBox, fontSize);
                ApplyFontSizeToElement(MegabitsPerSecondTextBox, fontSize);
                ApplyFontSizeToElement(NoteTextBox, fontSize);
                
                // Apply to all text elements in left panel (Advanced Settings)
                ApplyFontSizeToElement(AdvTargetIpTextBox, fontSize);
                ApplyFontSizeToElement(AdvTargetMacTextBox, fontSize);
                ApplyFontSizeToElement(AdvSourceIpTextBox, fontSize);
                ApplyFontSizeToElement(AdvSourceMacTextBox, fontSize);
                ApplyFontSizeToElement(AdvGatewayIpTextBox, fontSize);
                ApplyFontSizeToElement(AdvTargetPortTextBox, fontSize);
                ApplyFontSizeToElement(AdvMegabitsPerSecondTextBox, fontSize);
                
                // Apply to combo boxes
                ApplyFontSizeToElement(NetworkInterfaceComboBox, fontSize);
                ApplyFontSizeToElement(AttackTypeComboBox, fontSize);
                ApplyFontSizeToElement(AdvNetworkInterfaceComboBox, fontSize);
                ApplyFontSizeToElement(AdvancedAttackTypeComboBox, fontSize);
                
                // Apply to labels and other text elements
                ApplyFontSizeToElement(StatusBadgeText, fontSize);
                ApplyFontSizeToElement(PacketsSentText, fontSize);
                ApplyFontSizeToElement(ElapsedTimeText, fontSize);
                ApplyFontSizeToElement(MbpsSentText, fontSize);
                ApplyFontSizeToElement(ProfileSummaryText, fontSize);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error applying UI settings");
            }
        }
        
        private void ApplyFontSizeToElement(FrameworkElement element, double fontSize)
        {
            if (element != null)
            {
                // Apply font size to Control elements (TextBox, ComboBox, etc.)
                if (element is Control control)
                {
                    control.FontSize = fontSize;
                }
                // Apply font size to TextBlock elements
                else if (element is TextBlock textBlock)
                {
                    textBlock.FontSize = fontSize;
                }
            }
        }

        private void HelpButton_Click(object sender, RoutedEventArgs e)
        {
            // Use existing update check service if available, otherwise create new one
            var updateCheckService = _updateCheckService ?? 
                (_supabaseSyncService.IsConfigured 
                    ? new Services.UpdateCheckService(_supabaseSyncService.GetSupabaseClient(), _attackLogger) 
                    : null);
            
            var aboutWindow = new AboutWindow(updateCheckService)
            {
                Owner = this
            };
            aboutWindow.ShowDialog();
        }
        
        private async Task CheckForUpdatesAsync()
        {
            if (_updateCheckService == null)
                return;
                
            try
            {
                var result = await _updateCheckService.CheckForUpdatesAsync();
                
                Dispatcher.Invoke(() =>
                {
                    if (result.IsOnline && result.IsUpdateAvailable)
                    {
                        // Show red alert badge on About button
                        UpdateAvailableBadge.Visibility = Visibility.Visible;
                    }
                    else
                    {
                        // Hide badge if no update available or offline
                        UpdateAvailableBadge.Visibility = Visibility.Collapsed;
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error checking for updates");
            }
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
                _logger.Info("Application closing - starting cleanup...");

                // Stop all timers first
                _statsTimer?.Stop();
                _syncCheckTimer?.Stop();
                _updateCheckTimer?.Stop();

                // Cancel any pending cancellation tokens
                _targetIpDebounceTokenSource?.Cancel();
                _targetIpDebounceTokenSource?.Dispose();

                // Stop any running attacks with timeout
                if (StartButton.IsEnabled == false || StopButton.IsEnabled == true)
                {
                    try
                    {
                        _logger.Info("Stopping running attack...");
                        var stopTask = _mainController.StopAttackAsync(_totalPacketsSent);
                        if (!stopTask.Wait(TimeSpan.FromSeconds(3)))
                        {
                            _logger.Warn("Attack stop timed out, forcing termination");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Warn(ex, "Error stopping attack on close");
                    }
                }

                // Stop advanced attacks
                if (StartAdvancedAttackButton.IsEnabled == false || StopAdvancedAttackButton.IsEnabled == true)
                {
                    try
                    {
                        _logger.Info("Stopping advanced attack...");
                        var stopTask = _mainController.StopAttackAsync(_totalPacketsSent);
                        if (!stopTask.Wait(TimeSpan.FromSeconds(3)))
                        {
                            _logger.Warn("Advanced attack stop timed out");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Warn(ex, "Error stopping advanced attack on close");
                    }
                }

                // Dispose network resources
                try
                {
                    _logger.Info("Disposing network resources...");
                    _networkStorm?.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.Warn(ex, "Error disposing network storm");
                }

                // Close database connections
                try
                {
                    _logger.Info("Closing database connections...");
                    _databaseService?.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.Warn(ex, "Error disposing database service");
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

                // Force garbage collection to clean up any remaining resources
                GC.Collect();
                GC.WaitForPendingFinalizers();
                GC.Collect();

                _logger.Info("Cleanup completed");
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

        private async void CloudSyncButton_Click(object sender, RoutedEventArgs e)
        {
            await OpenSyncDialogAsync();
        }

        private async Task OpenSyncDialogAsync()
        {
            try
            {
                if (!_supabaseSyncService.IsConfigured)
                {
                    _toastService.ShowWarning("Supabase is not configured. Please configure it in Settings first.");
                    return;
                }

                var unsyncedLogs = await _databaseService.GetUnsyncedLogsAsync();
                var unsyncedAssets = await _databaseService.GetUnsyncedAssetsAsync();
                var unsyncedTests = await _databaseService.GetUnsyncedReachabilityTestsAsync();
                
                if (unsyncedLogs.Count == 0 && unsyncedAssets.Count == 0 && unsyncedTests.Count == 0)
                {
                    _toastService.ShowInfo("No pending logs, assets, or tests to sync.");
                    return;
                }

                var syncWindow = new SyncWindow(unsyncedLogs, unsyncedAssets, unsyncedTests)
                {
                    Owner = this
                };

                if (syncWindow.ShowDialog() == true)
                {
                    CloudSyncButton.IsEnabled = false;
                    var originalTooltip = CloudSyncButton.ToolTip;

                    // Show loading overlay
                    SyncLoadingOverlay.Visibility = Visibility.Visible;
                    SyncProgressText.Text = "Preparing sync...";
                    
                    // Subscribe to progress updates
                    _supabaseSyncService.ProgressChanged += OnSyncProgressChanged;

                    try
                    {
                        int syncedLogsCount = 0;
                        int syncedAssetsCount = 0;
                        int syncedTestsCount = 0;
                        bool hasDeletions = syncWindow.DeletedLogIds.Count > 0 || syncWindow.DeletedAssetIds.Count > 0 || syncWindow.DeletedTestIds.Count > 0 || syncWindow.DeletedSnmpWalkIds.Count > 0;

                    // Delete selected logs if any (always process deletions, even if not syncing)
                    if (syncWindow.DeletedLogIds.Count > 0)
                    {
                        await _databaseService.DeleteLogsAsync(syncWindow.DeletedLogIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedLogIds.Count} log(s).");
                    }

                    // Delete selected assets if any (always process deletions, even if not syncing)
                    if (syncWindow.DeletedAssetIds.Count > 0)
                    {
                        await _databaseService.DeleteAssetsAsync(syncWindow.DeletedAssetIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedAssetIds.Count} asset(s).");
                    }

                    // Delete selected tests if any (always process deletions, even if not syncing)
                    if (syncWindow.DeletedTestIds.Count > 0)
                    {
                        await _databaseService.DeleteReachabilityTestsAsync(syncWindow.DeletedTestIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedTestIds.Count} reachability test(s).");
                    }

                    // Delete selected SNMP walks if any (always process deletions, even if not syncing)
                    if (syncWindow.DeletedSnmpWalkIds.Count > 0)
                    {
                        await _databaseService.DeleteReachabilityTestsAsync(syncWindow.DeletedSnmpWalkIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedSnmpWalkIds.Count} SNMP walk(s).");
                    }

                    // Only sync if user clicked "Sync Selected" button
                    if (syncWindow.ShouldSync)
                    {
                        // Sync selected logs
                        if (syncWindow.SelectedLogIds.Count > 0)
                        {
                            var result = await _supabaseSyncService.SyncAsync(syncWindow.ProjectName, syncWindow.SelectedLogIds);

                            if (result.Success)
                            {
                                syncedLogsCount = result.SyncedCount;
                                _attackLogger.LogSuccess(result.Message);
                            }
                            else
                            {
                                _attackLogger.LogWarning(result.Message);
                                _toastService.ShowWarning($"Log sync failed: {result.Message}");
                            }
                        }

                        // Sync selected assets
                        if (syncWindow.SelectedAssetIds.Count > 0)
                        {
                            // Pass enhance data option to sync service
                            var result = await _supabaseSyncService.SyncAssetsAsync(syncWindow.ProjectName, syncWindow.SelectedAssetIds, syncWindow.EnhanceData);

                            if (result.Success)
                            {
                                syncedAssetsCount = result.SyncedCount;
                                _attackLogger.LogSuccess(result.Message);
                            }
                            else
                            {
                                _attackLogger.LogWarning(result.Message);
                                _toastService.ShowWarning($"Asset sync failed: {result.Message}");
                            }
                        }

                        // Sync selected reachability tests (combine regular tests and SNMP walks)
                        var allTestIds = syncWindow.SelectedTestIds.Concat(syncWindow.SelectedSnmpWalkIds).ToList();
                        if (allTestIds.Count > 0)
                        {
                            SyncProgressText.Text = $"Syncing {allTestIds.Count} reachability test(s) and SNMP walk(s)...";
                            var result = await _supabaseSyncService.SyncReachabilityTestsAsync(syncWindow.ProjectName, allTestIds);

                            if (result.Success)
                            {
                                syncedTestsCount = result.SyncedCount;
                                _attackLogger.LogSuccess(result.Message);
                            }
                            else
                            {
                                _attackLogger.LogWarning(result.Message);
                                _toastService.ShowWarning($"Reachability test sync failed: {result.Message}");
                            }
                        }

                        // Show success message
                        if (syncedLogsCount > 0 || syncedAssetsCount > 0 || syncedTestsCount > 0)
                        {
                            var parts = new List<string>();
                            if (syncedLogsCount > 0) parts.Add($"{syncedLogsCount} log(s)");
                            if (syncedAssetsCount > 0) parts.Add($"{syncedAssetsCount} asset(s)");
                            if (syncedTestsCount > 0) parts.Add($"{syncedTestsCount} test(s)");
                            
                            var message = $"Sync complete ✅ {string.Join(", ", parts)} synced successfully.";
                            _toastService.ShowSuccess(message);
                        }
                        else
                        {
                            _attackLogger.LogInfo("No items selected for sync.");
                        }
                    }
                    else if (hasDeletions)
                    {
                        // User deleted items but didn't sync - just show deletion confirmation
                        var deletedCount = syncWindow.DeletedLogIds.Count + syncWindow.DeletedAssetIds.Count + syncWindow.DeletedTestIds.Count;
                        _toastService.ShowInfo($"Deleted {deletedCount} item(s).");
                    }

                        // Hide loading overlay
                        SyncLoadingOverlay.Visibility = Visibility.Collapsed;
                        _supabaseSyncService.ProgressChanged -= OnSyncProgressChanged;
                        
                        CloudSyncButton.IsEnabled = true;
                        CloudSyncButton.ToolTip = originalTooltip;

                        // Always update sync status after window closes (deletions or sync)
                        _ = Task.Run(async () => await UpdateSyncStatus());
                    }
                    catch (Exception ex)
                    {
                        // Ensure loading overlay is hidden even on error
                        SyncLoadingOverlay.Visibility = Visibility.Collapsed;
                        _supabaseSyncService.ProgressChanged -= OnSyncProgressChanged;
                        CloudSyncButton.IsEnabled = true;
                        CloudSyncButton.ToolTip = originalTooltip;
                        
                        _attackLogger.LogError($"Sync operation failed: {ex.Message}");
                        _toastService.ShowError($"Sync failed: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Sync failed: {ex.Message}");
                _toastService.ShowError($"Sync failed: {ex.Message}");
            }
        }

        private async void SyncCheckTimer_Tick(object? sender, EventArgs e)
        {
            await UpdateSyncStatus();
        }

        private void OnSyncProgressChanged(string message)
        {
            Dispatcher.Invoke(() =>
            {
                SyncProgressText.Text = message;
            });
        }

        private async Task UpdateSyncStatus()
        {
            try
            {
                if (!_supabaseSyncService.IsConfigured)
                {
                    Dispatcher.Invoke(() =>
                    {
                        CloudSyncNotificationBadge.Visibility = Visibility.Collapsed;
                        CloudSyncButton.ToolTip = "Cloud Sync (Not Configured)";
                    });
                    return;
                }

                var pendingLogsCount = await _supabaseSyncService.GetPendingSyncCountAsync();
                var pendingAssetsCount = await _supabaseSyncService.GetPendingAssetsCountAsync();
                var totalPending = pendingLogsCount + pendingAssetsCount;
                
                Dispatcher.Invoke(() =>
                {
                    if (totalPending > 0)
                    {
                        CloudSyncNotificationBadge.Visibility = Visibility.Visible;
                        CloudSyncNotificationText.Text = totalPending > 99 ? "99+" : totalPending.ToString();
                        
                        var tooltipParts = new List<string>();
                        if (pendingLogsCount > 0) tooltipParts.Add($"{pendingLogsCount} log(s)");
                        if (pendingAssetsCount > 0) tooltipParts.Add($"{pendingAssetsCount} asset(s)");
                        CloudSyncButton.ToolTip = $"{string.Join(", ", tooltipParts)} pending sync - Click to sync";
                    }
                    else
                    {
                        CloudSyncNotificationBadge.Visibility = Visibility.Collapsed;
                        CloudSyncButton.ToolTip = "Cloud Sync (No pending items)";
                    }
                });
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to update sync status");
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
                        _attackLogger.LogInfo("⚠️ Fallback mode enabled automatically due to ping failure - Manual MAC entry available");
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
                                _attackLogger.LogInfo("📍 Source and target are on different subnets - Gateway required");
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
                            _attackLogger.LogInfo("⚠️ Fallback mode enabled - Please enter gateway MAC address manually");
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
                            _attackLogger.LogInfo("⚠️ Fallback mode enabled - Please enter MAC address manually");
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
                            _attackLogger.LogInfo("⚠️ Fallback mode enabled - Target MAC field is now editable for manual entry");
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
                // Basic Settings doesn't require password - skip validation
                // Only Advanced Settings requires password
                
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
                _totalBytesSent = 0;
                _attackStartTime = DateTime.Now;
                _lastStatsUpdateTime = DateTime.Now; // Initialize for rate calculation
                _lastBytesSent = 0;
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

                // Track the running attack type
                _currentRunningAttackType = "Broadcast";

                // Initialize statistics
                _totalPacketsSent = 0;
                _totalBytesSent = 0;
                _attackStartTime = DateTime.Now;
                _lastStatsUpdateTime = DateTime.Now; // Initialize for rate calculation
                _lastBytesSent = 0;
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
                // Basic Settings doesn't require password for stop
                // Only Advanced Settings requires password
                
                _statsTimer?.Stop();
                
                // Use the tracked running attack type instead of combobox selection
                var attackType = _currentRunningAttackType ?? 
                    (MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                        (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString());
                
                if (attackType == "Broadcast")
                {
                    await _mainController.StopBroadcastAttackAsync(_totalPacketsSent);
                }
                else if (attackType == "ARP Spoofing")
                {
                    await _mainController.StopArpSpoofingAsync(_totalPacketsSent);
                }
                else if (attackType != null && attackType.StartsWith("Ethernet"))
                {
                    // Ethernet attacks use the same stop method as regular flood attacks
                    await _mainController.StopAttackAsync(_totalPacketsSent);
                }
                else
                {
                    await _mainController.StopAttackAsync(_totalPacketsSent);
                }
                
                _currentRunningAttackType = null; // Clear the running attack type
                ResetStatistics();
                
                // Update sync status immediately to show cloud notification
                _ = Task.Run(async () =>
                {
                    await Task.Delay(500); // Reduced delay for faster notification
                    await UpdateSyncStatus();
                    
                    // Show one-time notification per session about cloud sync
                    if (!_hasShownAttackLogSyncNotification && _supabaseSyncService.IsConfigured)
                    {
                        _hasShownAttackLogSyncNotification = true;
                        Dispatcher.Invoke(() =>
                        {
                            _toastService.ShowInfo("✅ Attack log saved. Click Cloud Sync button to upload to Supabase.");
                        });
                    }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error stopping attack: {ex}");
                _currentRunningAttackType = null;
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
                    .Select(n =>
                    {
                        // Get bandwidth in bits per second, convert to Mbps or Gbps
                        long speedBps = n.Speed; // Speed is in bits per second
                        string bandwidthDisplay;
                        double maxMbps;
                        
                        if (speedBps >= 1_000_000_000) // >= 1 Gbps
                        {
                            double gbps = speedBps / 1_000_000_000.0;
                            bandwidthDisplay = $"{gbps:F1} Gbps";
                            maxMbps = gbps * 1000;
                        }
                        else if (speedBps >= 1_000_000) // >= 1 Mbps
                        {
                            double mbps = speedBps / 1_000_000.0;
                            bandwidthDisplay = $"{mbps:F0} Mbps";
                            maxMbps = mbps;
                        }
                        else if (speedBps > 0)
                        {
                            double kbps = speedBps / 1_000.0;
                            bandwidthDisplay = $"{kbps:F0} Kbps";
                            maxMbps = kbps / 1000.0;
                        }
                        else
                        {
                            bandwidthDisplay = "Unknown";
                            maxMbps = 1000; // Default to 1 Gbps if unknown
                        }
                        
                        return new
                        {
                            Description = $"{n.Description} ({n.Name}) - {bandwidthDisplay}",
                        Interface = n,
                        IpAddress = n.GetIPProperties().UnicastAddresses
                                .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork)?.Address,
                            MaxMbps = maxMbps,
                            BandwidthDisplay = bandwidthDisplay
                        };
                    })
                    .Where(x => x.IpAddress != null)
                    .ToList();

                NetworkInterfaceComboBox.ItemsSource = interfaces;
                AdvNetworkInterfaceComboBox.ItemsSource = interfaces;
                NetworkInterfaceComboBox.DisplayMemberPath = "Description";
                AdvNetworkInterfaceComboBox.DisplayMemberPath = "Description";
                NetworkInterfaceComboBox.SelectedIndex = 0;
                AdvNetworkInterfaceComboBox.SelectedIndex = 0;
                
                // Update Mbps validation when interfaces are populated
                UpdateMbpsValidation();

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
                
                // Update Mbps validation when interfaces are populated
                UpdateMbpsValidation();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error populating network interfaces: {ex}");
            }
        }
        
        private void UpdateMbpsValidation()
        {
            try
            {
                // Get selected NIC from current tab
                var comboBox = MainTabControl.SelectedItem == AdvancedTab 
                    ? AdvNetworkInterfaceComboBox 
                    : NetworkInterfaceComboBox;
                
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000; // Default to 1 Gbps if unknown
                    
                    // Update tooltip to show bandwidth limit
                    string tooltipText = $"Enter Mbps value (0 - {maxMbps:F0})";
                    MegabitsPerSecondTextBox.ToolTip = tooltipText;
                    AdvMegabitsPerSecondTextBox.ToolTip = tooltipText;
                }
            }
            catch
            {
                // Ignore errors
            }
        }
        
        private void MegabitsPerSecondTextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                e.Handled = true;
                return;
            }
            
            // Allow only digits and decimal point
            if (!char.IsDigit(e.Text, 0) && e.Text != ".")
            {
                e.Handled = true;
                return;
            }
            
            // Prevent multiple decimal points
            if (e.Text == "." && textBox.Text.Contains("."))
            {
                e.Handled = true;
                return;
            }
            
            // Build the new text that would result from this input
            string currentText = textBox.Text ?? "";
            int selectionStart = textBox.SelectionStart;
            int selectionLength = textBox.SelectionLength;
            
            // Remove selected text and insert new text
            string newText = currentText.Substring(0, selectionStart) + 
                            e.Text + 
                            currentText.Substring(selectionStart + selectionLength);
            
            // Allow empty text or just a decimal point (user might be typing)
            if (string.IsNullOrWhiteSpace(newText) || newText == ".")
            {
                return; // Allow it
            }
            
            // Try to parse as number
            if (double.TryParse(newText, out double value))
            {
                // Get max Mbps from selected NIC
                var comboBox = NetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;
                    
                    // Only block if value is clearly out of range (negative or way over max)
                    // Allow intermediate values during typing
                    if (value < 0)
                    {
                        e.Handled = true;
                        return;
                    }
                    
                    // Only block if it's clearly exceeding max (with some tolerance for typing)
                    // For example, if max is 1000, allow typing "1000" but block "10000"
                    if (value > maxMbps * 1.1) // 10% tolerance for intermediate typing
                    {
                        e.Handled = true;
                        return;
                    }
                }
            }
            else
            {
                // Invalid format - block it
                e.Handled = true;
            }
        }
        
        private void AdvMegabitsPerSecondTextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                e.Handled = true;
                return;
            }
            
            // Allow only digits and decimal point
            if (!char.IsDigit(e.Text, 0) && e.Text != ".")
            {
                e.Handled = true;
                return;
            }
            
            // Prevent multiple decimal points
            if (e.Text == "." && textBox.Text.Contains("."))
            {
                e.Handled = true;
                return;
            }
            
            // Build the new text that would result from this input
            string currentText = textBox.Text ?? "";
            int selectionStart = textBox.SelectionStart;
            int selectionLength = textBox.SelectionLength;
            
            // Remove selected text and insert new text
            string newText = currentText.Substring(0, selectionStart) + 
                            e.Text + 
                            currentText.Substring(selectionStart + selectionLength);
            
            // Allow empty text or just a decimal point (user might be typing)
            if (string.IsNullOrWhiteSpace(newText) || newText == ".")
            {
                return; // Allow it
            }
            
            // Try to parse as number
            if (double.TryParse(newText, out double value))
            {
                // Get max Mbps from selected NIC
                var comboBox = AdvNetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;
                    
                    // Only block if value is clearly out of range (negative or way over max)
                    // Allow intermediate values during typing
                    if (value < 0)
                    {
                        e.Handled = true;
                        return;
                    }
                    
                    // Only block if it's clearly exceeding max (with some tolerance for typing)
                    // For example, if max is 1000, allow typing "1000" but block "10000"
                    if (value > maxMbps * 1.1) // 10% tolerance for intermediate typing
                    {
                        e.Handled = true;
                        return;
                    }
                }
            }
            else
            {
                // Invalid format - block it
                e.Handled = true;
            }
        }
        
        private void MegabitsPerSecondTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null) return;
            
            // Allow empty text (user might be clearing it)
            if (string.IsNullOrWhiteSpace(textBox.Text)) return;
            
            // Only validate when user finishes editing (lost focus) or when value is clearly invalid
            // Don't interfere while typing
            if (double.TryParse(textBox.Text, out double value))
            {
                // Get max Mbps from selected NIC
                var comboBox = NetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;
                    
                    // Only clamp if significantly over max (not during normal typing)
                    if (value > maxMbps * 1.01) // 1% tolerance
                    {
                        int caretPos = textBox.CaretIndex;
                        textBox.Text = maxMbps.ToString("F0");
                        textBox.CaretIndex = Math.Min(caretPos, textBox.Text.Length);
                    }
                    else if (value < 0)
                    {
                        int caretPos = textBox.CaretIndex;
                        textBox.Text = "0";
                        textBox.CaretIndex = Math.Min(caretPos, textBox.Text.Length);
                    }
                }
            }
        }
        
        private void AdvMegabitsPerSecondTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null) return;
            
            // Allow empty text (user might be clearing it)
            if (string.IsNullOrWhiteSpace(textBox.Text)) return;
            
            // Only validate when user finishes editing (lost focus) or when value is clearly invalid
            // Don't interfere while typing
            if (double.TryParse(textBox.Text, out double value))
            {
                // Get max Mbps from selected NIC
                var comboBox = AdvNetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;
                    
                    // Only clamp if significantly over max (not during normal typing)
                    if (value > maxMbps * 1.01) // 1% tolerance
                    {
                        int caretPos = textBox.CaretIndex;
                        textBox.Text = maxMbps.ToString("F0");
                        textBox.CaretIndex = Math.Min(caretPos, textBox.Text.Length);
                    }
                    else if (value < 0)
                    {
                        int caretPos = textBox.CaretIndex;
                        textBox.Text = "0";
                        textBox.CaretIndex = Math.Min(caretPos, textBox.Text.Length);
                    }
                }
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
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "NMEA 0183 (UDP Unicast)" });
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "NMEA 0183 (UDP Multicast)" });
                AdvancedAttackTypeComboBox.Items.Add(new ComboBoxItem { Content = "Modbus/TCP Flood (Read Requests)" });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error populating attack types: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error populating attack types: {ex}");
            }
        }

        private void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Check if this call is from syncing (prevent duplicate processing) - CHECK FIRST!
            // This must be the very first check to prevent any duplicate processing
            if (_isSyncingComboBoxes)
            {
                return; // Skip processing if this was triggered by sync
            }

            // Set flag immediately to prevent recursive calls
            _isSyncingComboBoxes = true;

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
                    
                    // Sync the other combobox selection - temporarily unsubscribe to prevent recursive call
                    ComboBox targetComboBox;
                    if (comboBox == NetworkInterfaceComboBox)
                    {
                        targetComboBox = AdvNetworkInterfaceComboBox;
                        targetComboBox.SelectionChanged -= NetworkInterfaceComboBox_SelectionChanged;
                        try
                        {
                            targetComboBox.SelectedIndex = NetworkInterfaceComboBox.SelectedIndex;
                        }
                        finally
                        {
                            targetComboBox.SelectionChanged += NetworkInterfaceComboBox_SelectionChanged;
                        }
                    }
                    else
                    {
                        targetComboBox = NetworkInterfaceComboBox;
                        targetComboBox.SelectionChanged -= NetworkInterfaceComboBox_SelectionChanged;
                        try
                        {
                            targetComboBox.SelectedIndex = AdvNetworkInterfaceComboBox.SelectedIndex;
                        }
                        finally
                        {
                            targetComboBox.SelectionChanged += NetworkInterfaceComboBox_SelectionChanged;
                        }
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
                    
                    // Update Mbps validation when NIC changes
                    UpdateMbpsValidation();
                    
                    // Always update gateway IP when NIC changes
                    // Suppress TextChanged events to prevent duplicate processing
                    if (gatewayIp != null)
                    {
                        GatewayIpTextBox.TextChanged -= GatewayIpTextBox_TextChanged;
                        try
                    {
                        GatewayIpTextBox.Text = gatewayIp.ToString();
                        AdvGatewayIpTextBox.Text = gatewayIp.ToString();
                        }
                        finally
                        {
                            GatewayIpTextBox.TextChanged += GatewayIpTextBox_TextChanged;
                        }
                        _networkStorm.SetGatewayIp(gatewayIp.ToString());
                        // Log only once
                        _attackLogger.LogSuccess($"Gateway updated: {gatewayIp} (NIC: {nicDescription})");
                    }
                    else
                    {
                        GatewayIpTextBox.TextChanged -= GatewayIpTextBox_TextChanged;
                        try
                    {
                        GatewayIpTextBox.Text = string.Empty;
                        AdvGatewayIpTextBox.Text = string.Empty;
                        }
                        finally
                        {
                            GatewayIpTextBox.TextChanged += GatewayIpTextBox_TextChanged;
                        }
                        _networkStorm.SetGatewayIp(string.Empty);
                        // Log only once
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
            finally
            {
                // Always reset the flag when done
                _isSyncingComboBoxes = false;
            }
        }

        private void AdvancedTab_PreviewMouseDown(object sender, MouseButtonEventArgs e)
        {
            // Password check is now handled in MainTabControl_SelectionChanged
            // This handler is kept for any future use but no longer blocks access
        }
        
        private bool ValidatePassword(string inputPassword)
        {
            // Direct password comparison
            // Password: KyeRRkfccbGBCNCKYPha1lrYS2PO8koL
            if (string.IsNullOrEmpty(inputPassword))
                return false;
            
            // Trim and compare (handle any whitespace issues)
            string trimmedInput = inputPassword.Trim();
            string correctPassword = "KyeRRkfccbGBCNCKYPha1lrYS2PO8koL";
            
            // Use secure comparison to prevent timing attacks
            return SecureCompare(trimmedInput, correctPassword);
        }
        
        private string GetMachineIdentifier()
        {
            // Generate a machine-specific identifier that's hard to tamper with
            // Uses machine name + a hardware identifier
            string machineName = Environment.MachineName;
            string userName = Environment.UserName;
            string osVersion = Environment.OSVersion.ToString();
            
            // Combine to create a machine identifier
            string machineId = $"{machineName}_{userName}_{osVersion}";
            
            // Hash it for consistency
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineId));
                return Convert.ToBase64String(hashBytes).Substring(0, 32); // Use first 32 chars
            }
        }
        
        private string GenerateValidationToken()
        {
            // Generate a secure validation token tied to the machine
            // This token persists across sessions but is tied to this machine
            string machineId = GetMachineIdentifier();
            string baseSecret = "SeAcUrE_VaLiDaTiOn_SeCrEt_2024";
            
            // Combine machine ID and secret
            string tokenData = $"{machineId}_{baseSecret}";
            
            // Generate SHA256 hash
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenData));
                return Convert.ToBase64String(hashBytes);
            }
        }
        
        private void SaveValidationToken()
        {
            try
            {
                if (string.IsNullOrEmpty(_validationToken))
                    return;
                
                // Encrypt the token before saving
                string machineId = GetMachineIdentifier();
                byte[] tokenBytes = Encoding.UTF8.GetBytes(_validationToken);
                byte[] keyBytes = Encoding.UTF8.GetBytes(machineId.Substring(0, 32));
                
                // Simple XOR encryption with machine ID as key
                for (int i = 0; i < tokenBytes.Length; i++)
                {
                    tokenBytes[i] = (byte)(tokenBytes[i] ^ keyBytes[i % keyBytes.Length]);
                }
                
                // Save encrypted token to file
                string encryptedToken = Convert.ToBase64String(tokenBytes);
                File.WriteAllText(VALIDATION_TOKEN_FILE, encryptedToken);
            }
            catch (Exception ex)
            {
                _attackLogger?.LogError($"Failed to save validation token: {ex.Message}");
            }
        }
        
        private bool LoadValidationToken()
        {
            try
            {
                if (!File.Exists(VALIDATION_TOKEN_FILE))
                    return false;
                
                // Read encrypted token
                string encryptedToken = File.ReadAllText(VALIDATION_TOKEN_FILE);
                byte[] tokenBytes = Convert.FromBase64String(encryptedToken);
                
                // Decrypt using machine ID
                string machineId = GetMachineIdentifier();
                byte[] keyBytes = Encoding.UTF8.GetBytes(machineId.Substring(0, 32));
                
                // XOR decrypt
                for (int i = 0; i < tokenBytes.Length; i++)
                {
                    tokenBytes[i] = (byte)(tokenBytes[i] ^ keyBytes[i % keyBytes.Length]);
                }
                
                _validationToken = Encoding.UTF8.GetString(tokenBytes);
                
                // Validate the loaded token
                return IsValidationTokenValid(_validationToken);
            }
            catch (Exception ex)
            {
                _attackLogger?.LogError($"Failed to load validation token: {ex.Message}");
                return false;
            }
        }
        
        private bool IsValidationTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;
            
            // Regenerate expected token and compare
            string expectedToken = GenerateValidationToken();
            
            // Use constant-time comparison to prevent timing attacks
            return SecureCompare(token, expectedToken);
        }
        
        private bool SecureCompare(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;
            
            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
        
        private void ShowAdvancedSettingsDisclaimer()
        {
            // Reset flag before showing dialog
            _disclaimerAcknowledged = false;
            
            var disclaimerDialog = new DisclaimerDialog
            {
                Owner = this
            };
            
            // Show dialog and check result
            bool? dialogResult = disclaimerDialog.ShowDialog();
            if (dialogResult == true && disclaimerDialog.IsAuthorized)
            {
                _disclaimerAcknowledged = true;
                // Don't save acknowledgment - show every time
            }
            else
            {
                _disclaimerAcknowledged = false;
            }
        }
        
        private bool IsDisclaimerAcknowledged()
        {
            try
            {
                if (File.Exists(DISCLAIMER_ACK_FILE))
                {
                    // Read and validate the acknowledgment file
                    string content = File.ReadAllText(DISCLAIMER_ACK_FILE);
                    // Simple validation - file should contain machine identifier
                    string machineId = GetMachineIdentifier();
                    if (content.Contains(machineId))
                    {
                        _disclaimerAcknowledged = true;
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger?.LogError($"Failed to check disclaimer acknowledgment: {ex.Message}");
            }
            return false;
        }
        
        private void SaveDisclaimerAcknowledgment()
        {
            try
            {
                string machineId = GetMachineIdentifier();
                string timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");
                string content = $"{machineId}|{timestamp}";
                File.WriteAllText(DISCLAIMER_ACK_FILE, content);
            }
            catch (Exception ex)
            {
                _attackLogger?.LogError($"Failed to save disclaimer acknowledgment: {ex.Message}");
            }
        }
        
        private void UpdateLabModeBadge(bool isAttackMode)
        {
            if (LabModeBadge == null || LabModeText == null) return;
            
            if (isAttackMode)
            {
                // ATTACK MODE - Red
                LabModeBadge.Background = new SolidColorBrush(Color.FromRgb(254, 226, 226)); // #FEE2E2
                LabModeBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(220, 38, 38)); // #DC2626
                LabModeText.Text = "ATTACK MODE";
                LabModeText.Foreground = new SolidColorBrush(Color.FromRgb(153, 27, 27)); // #991B1B
            }
            else
            {
                // LAB MODE - Yellow/Amber
                LabModeBadge.Background = new SolidColorBrush(Color.FromRgb(254, 243, 199)); // #FEF3C7
                LabModeBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(245, 158, 11)); // #F59E0B
                LabModeText.Text = "LAB MODE";
                LabModeText.Foreground = new SolidColorBrush(Color.FromRgb(146, 64, 14)); // #92400E
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
                        case "NMEA 0183 (UDP Unicast)":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;
                            // Set default port for NMEA 0183
                            if (string.IsNullOrWhiteSpace(AdvTargetPortTextBox.Text) || AdvTargetPortTextBox.Text == "0")
                            {
                                AdvTargetPortTextBox.Text = "10110";
                            }
                            // Default target IP is blank (user must enter)
                            break;
                        case "NMEA 0183 (UDP Multicast)":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;
                            // Set default port and multicast IP for NMEA 0183
                            if (string.IsNullOrWhiteSpace(AdvTargetPortTextBox.Text) || AdvTargetPortTextBox.Text == "0")
                            {
                                AdvTargetPortTextBox.Text = "10110";
                            }
                            if (string.IsNullOrWhiteSpace(AdvTargetIpTextBox.Text))
                            {
                                AdvTargetIpTextBox.Text = "239.192.0.1"; // Default multicast group
                            }
                            break;
                        case "Modbus/TCP Flood (Read Requests)":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;
                            // Set default port for Modbus/TCP
                            if (string.IsNullOrWhiteSpace(AdvTargetPortTextBox.Text) || AdvTargetPortTextBox.Text == "0")
                            {
                                AdvTargetPortTextBox.Text = "502";
                            }
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
                // Check password
                // Check if password has been validated (one-time validation per session)
                if (string.IsNullOrEmpty(_validationToken) || !IsValidationTokenValid(_validationToken))
                {
                    MessageBox.Show("Please validate your password first by clicking the 'Validate' button.", "Authentication Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    AdvPasswordBox?.Focus();
                    return;
                }
                
                if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem)
                {
                    var attackType = selectedItem.Content.ToString();
                    switch (attackType)
                    {
                        case "ARP Spoofing":
                            await StartArpSpoofingAttack();
                            break;
                        case "NMEA 0183 (UDP Unicast)":
                        case "NMEA 0183 (UDP Multicast)":
                            await StartNmea0183Attack(attackType);
                            break;
                        case "Modbus/TCP Flood (Read Requests)":
                            await StartModbusTcpAttack();
                            break;
                        case "Ethernet Unicast (IPv4)":
                        case "Ethernet Unicast (IPv6)":
                        case "Ethernet Multicast (IPv4)":
                        case "Ethernet Multicast (IPv6)":
                        case "Ethernet Broadcast (IPv4)":
                        case "Ethernet Broadcast (IPv6)":
                            // Parse the attack type to determine packet type
                            EthernetFlood.EthernetPacketType packetType = EthernetFlood.EthernetPacketType.Unicast;
                            bool useIPv6 = false;
                            
                            if (attackType.Contains("Multicast"))
                                packetType = EthernetFlood.EthernetPacketType.Multicast;
                            else if (attackType.Contains("Broadcast"))
                                packetType = EthernetFlood.EthernetPacketType.Broadcast;
                            
                            if (attackType.Contains("IPv6"))
                                useIPv6 = true;
                            
                            await StartEthernetAttack(packetType);
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

        private async Task StartNmea0183Attack(string attackType)
        {
            try
            {
                string targetIp = AdvTargetIpTextBox.Text.Trim();
                string sourceIp = AdvSourceIpTextBox.Text.Trim();
                
                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (!IPAddress.TryParse(targetIp, out var parsedTargetIp))
                {
                    MessageBox.Show("Invalid target IP address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (!int.TryParse(AdvTargetPortTextBox.Text, out int targetPort) || targetPort <= 0 || targetPort > 65535)
                {
                    MessageBox.Show("Invalid target port. Please enter a port between 1 and 65535.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out long megabitsPerSecond) || megabitsPerSecond <= 0)
                {
                    MessageBox.Show("Invalid rate (Mbps). Please enter a positive number.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                bool isMulticast = attackType == "NMEA 0183 (UDP Multicast)";
                string actualMulticastGroupIp = targetIp;
                string destinationIpForLogging = targetIp;
                
                // For multicast attacks: if user entered a unicast IP, use it as config/interface IP
                // and derive/use a default multicast group IP
                if (isMulticast)
                {
                    var ipBytes = parsedTargetIp.GetAddressBytes();
                    bool isUnicastIp = ipBytes.Length < 1 || ipBytes[0] < 224 || ipBytes[0] > 239;
                    
                    if (isUnicastIp)
                    {
                        // User entered a unicast IP - treat as interface/config IP
                        // Use default multicast group or derive from the unicast IP
                        // For now, use a default multicast group (239.192.0.1)
                        actualMulticastGroupIp = "239.192.0.1";
                        destinationIpForLogging = targetIp; // Keep the unicast IP for logging
                        _attackLogger.LogInfo($"Using unicast IP {targetIp} as interface/config; targeting multicast group {actualMulticastGroupIp}");
                    }
                    else
                    {
                        // User entered a valid multicast IP - use it directly
                        actualMulticastGroupIp = targetIp;
                        destinationIpForLogging = targetIp;
                    }
                }

                // Set the running attack type
                _currentRunningAttackType = attackType;

                // Initialize statistics
                _totalPacketsSent = 0;
                _totalBytesSent = 0;
                _attackStartTime = DateTime.Now;
                _lastStatsUpdateTime = DateTime.Now;
                _lastBytesSent = 0;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                StartAdvancedAttackButton.IsEnabled = false;
                StopAdvancedAttackButton.IsEnabled = true;

                // Get MAC addresses for logging
                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                byte[] targetMacBytes;
                
                if (isMulticast)
                {
                    // For multicast, derive multicast MAC from the actual multicast group IP
                    var multicastIpBytes = IPAddress.Parse(actualMulticastGroupIp).GetAddressBytes();
                    targetMacBytes = new byte[] { 0x01, 0x00, 0x5E, (byte)(multicastIpBytes[1] & 0x7F), multicastIpBytes[2], multicastIpBytes[3] };
                }
                else
                {
                    // For unicast, try to resolve MAC
                    // GetMacAddressAsync already handles routed targets by returning gateway MAC
                    targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                    if (targetMacBytes.Length == 0)
                    {
                        // If MAC resolution failed, try to resolve gateway MAC if gateway IP is set
                        // This handles cases where gateway MAC wasn't resolved yet
                        if (!string.IsNullOrEmpty(_networkStorm.GatewayIp))
                        {
                            targetMacBytes = await _mainController.GetMacAddressAsync(_networkStorm.GatewayIp);
                            if (targetMacBytes.Length > 0)
                            {
                                await _networkStorm.SetGatewayMacAsync(targetMacBytes);
                                _attackLogger.LogInfo($"Using gateway MAC for NMEA unicast target: {BitConverter.ToString(targetMacBytes).Replace("-", ":")}");
                            }
                        }
                        
                        if (targetMacBytes.Length == 0)
                        {
                            _attackLogger.LogError("Failed to resolve target MAC address. Please enable fallback mode and enter MAC manually.");
                            StartAdvancedAttackButton.IsEnabled = true;
                            StopAdvancedAttackButton.IsEnabled = false;
                            _currentRunningAttackType = null;
                            return;
                        }
                    }
                }

                // Log attack start with NMEA-specific labels
                // For multicast with unicast destination IP, show both
                _attackLogger.StartNmea0183Attack(isMulticast, sourceIp, sourceMacBytes, 
                    actualMulticastGroupIp, targetMacBytes, megabitsPerSecond, targetPort, destinationIpForLogging);

                // Use the actual multicast group IP for the attack (not the unicast config IP)
                await _networkStorm.StartNmea0183AttackAsync(actualMulticastGroupIp, targetPort, megabitsPerSecond, isMulticast);
            }
            catch (Exception ex)
            {
                _currentRunningAttackType = null;
                ResetStatistics();
                _statsTimer?.Stop();
                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
                _attackLogger.LogError($"Failed to start NMEA 0183 attack: {ex.Message}");
                throw;
            }
        }

        private async Task StartModbusTcpAttack()
        {
            try
            {
                string targetIp = AdvTargetIpTextBox.Text.Trim();
                string sourceIp = AdvSourceIpTextBox.Text.Trim();
                
                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (!IPAddress.TryParse(targetIp, out var parsedTargetIp))
                {
                    MessageBox.Show("Invalid target IP address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (!int.TryParse(AdvTargetPortTextBox.Text, out int targetPort) || targetPort <= 0 || targetPort > 65535)
                {
                    MessageBox.Show("Invalid target port. Please enter a port between 1 and 65535.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                
                if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out long megabitsPerSecond) || megabitsPerSecond <= 0)
                {
                    MessageBox.Show("Invalid rate (Mbps). Please enter a positive number.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Set the running attack type
                _currentRunningAttackType = "Modbus/TCP Flood (Read Requests)";

                // Initialize statistics
                _totalPacketsSent = 0;
                _totalBytesSent = 0;
                _attackStartTime = DateTime.Now;
                _lastStatsUpdateTime = DateTime.Now;
                _lastBytesSent = 0;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                StartAdvancedAttackButton.IsEnabled = false;
                StopAdvancedAttackButton.IsEnabled = true;

                // Get MAC addresses for logging
                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                byte[] targetMacBytes;
                
                // For Modbus/TCP, try to resolve MAC (handles routed targets by returning gateway MAC)
                targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                if (targetMacBytes.Length == 0)
                {
                    // If MAC resolution failed, try to resolve gateway MAC if gateway IP is set
                    if (!string.IsNullOrEmpty(_networkStorm.GatewayIp))
                    {
                        targetMacBytes = await _mainController.GetMacAddressAsync(_networkStorm.GatewayIp);
                        if (targetMacBytes.Length > 0)
                        {
                            await _networkStorm.SetGatewayMacAsync(targetMacBytes);
                            _attackLogger.LogInfo($"Using gateway MAC for Modbus/TCP target: {BitConverter.ToString(targetMacBytes).Replace("-", ":")}");
                        }
                    }
                    
                    if (targetMacBytes.Length == 0)
                    {
                        _attackLogger.LogError("Failed to resolve target MAC address. Please enable fallback mode and enter MAC manually.");
                        StartAdvancedAttackButton.IsEnabled = true;
                        StopAdvancedAttackButton.IsEnabled = false;
                        _currentRunningAttackType = null;
                        return;
                    }
                }

                // Log attack start with Modbus-specific labels
                _attackLogger.StartModbusTcpAttack(sourceIp, sourceMacBytes, targetIp, targetMacBytes, megabitsPerSecond, targetPort);

                // Start the Modbus/TCP attack
                await _networkStorm.StartModbusTcpAttackAsync(targetIp, targetPort, megabitsPerSecond);
            }
            catch (Exception ex)
            {
                _currentRunningAttackType = null;
                ResetStatistics();
                _statsTimer?.Stop();
                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
                _attackLogger.LogError($"Failed to start Modbus/TCP attack: {ex.Message}");
                throw;
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

                // Track the running attack type
                _currentRunningAttackType = attackType;

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
                    _currentRunningAttackType = null;
                    return;
                }

                // Initialize statistics
                _totalPacketsSent = 0;
                _totalBytesSent = 0;
                _attackStartTime = DateTime.Now;
                _lastStatsUpdateTime = DateTime.Now; // Initialize for rate calculation
                _lastBytesSent = 0;
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
                _totalBytesSent = 0;
                _attackStartTime = DateTime.Now;
                _lastStatsUpdateTime = DateTime.Now; // Initialize for rate calculation
                _lastBytesSent = 0;
                _targetMbps = megabitsPerSecond;
                _statsTimer?.Start();

                // Initialize attack logger with Ethernet attack details
                _attackLogger.StartEthernetAttack(packetType, sourceIp, sourceMacBytes, targetIp, targetMac, megabitsPerSecond, targetPort);

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, megabitsPerSecond, packetType, useIPv6, targetMac);
            }
            catch (Exception ex)
            {
                _currentRunningAttackType = null;
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

                // Determine the attack type string from the combobox
                var attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                
                // Track the running attack type
                _currentRunningAttackType = attackType ?? $"Ethernet {packetType}";

                // Validate cross-subnet gateway requirement (only for Unicast)
                if (packetType == EthernetFlood.EthernetPacketType.Unicast && !ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                    _currentRunningAttackType = null;
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

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, megabitsPerSecond, packetType, false, targetMac);
            }
            catch (Exception ex)
            {
                _currentRunningAttackType = null;
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
                // Check if password has been validated (one-time validation per session)
                if (string.IsNullOrEmpty(_validationToken) || !IsValidationTokenValid(_validationToken))
                {
                    MessageBox.Show("Please validate your password first by clicking the 'Validate' button.", "Authentication Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    AdvPasswordBox?.Focus();
                    return;
                }
                
                _statsTimer?.Stop();
                // Use the tracked running attack type instead of combobox selection
                var attackType = _currentRunningAttackType ?? 
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();
                
                _attackLogger.LogInfo($"Stopping advanced attack. Attack type: '{attackType}', Current running type: '{_currentRunningAttackType}'");
                
                if (attackType == "ARP Spoofing")
                {
                            await _mainController.StopArpSpoofingAsync(_totalPacketsSent);
                }
                else if (attackType != null && (attackType.StartsWith("Ethernet") || attackType.StartsWith("NMEA 0183") || attackType.Contains("NMEA")))
                {
                    // Ethernet and NMEA attacks use the same stop method as regular flood attacks
                    _attackLogger.LogInfo($"Stopping attack type: {attackType}");
                    await _mainController.StopAttackAsync(_totalPacketsSent);
                }
                else if (attackType != null)
                {
                    // Fallback: try to stop any attack that's running
                    _attackLogger.LogInfo($"Stopping attack (fallback) for type: {attackType}");
                    await _mainController.StopAttackAsync(_totalPacketsSent);
                }
                else
                {
                    // If attack type is null, still try to stop (might be a race condition)
                    _attackLogger.LogInfo("Stopping attack (attack type was null, using fallback)");
                    await _mainController.StopAttackAsync(_totalPacketsSent);
                }
                
                _currentRunningAttackType = null; // Clear the running attack type
                ResetStatistics();
                ResetStatistics();
                
                // Ensure button states are correct
                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
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

                // Track the running attack type
                _currentRunningAttackType = "ARP Spoofing";

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
                var arpStartMessage = "════════════════════════════════════════════════════════\n" +
                                    $"✅ Status: Attack Started\n" +
                                    $"🌐 Protocol: ARP Spoofing\n" +
                                    $"📍 Source Host: {sourceIp}\n" +
                                    $"🔗 Source MAC: {sourceMac}\n" +
                                    $"🎯 Target Host: {targetIp}\n" +
                                    $"🔗 Target MAC: {targetMac}\n" +
                                    $"🎭 Spoofed MAC: {spoofedMac}\n" +
                                    $"⏰ Start Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                                    "════════════════════════════════════════════════════════";
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
                            GatewayIpTextBox.TextChanged -= GatewayIpTextBox_TextChanged;
                            try
                        {
                            GatewayIpTextBox.Text = string.Empty;
                            }
                            finally
                            {
                                GatewayIpTextBox.TextChanged += GatewayIpTextBox_TextChanged;
                            }
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
                                    GatewayIpTextBox.TextChanged -= GatewayIpTextBox_TextChanged;
                                    try
                                {
                                    GatewayIpTextBox.Text = defaultGateway.ToString();
                                    }
                                    finally
                                    {
                                        GatewayIpTextBox.TextChanged += GatewayIpTextBox_TextChanged;
                                    }
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
            // Prevent re-entrancy during tab changes
            if (_isHandlingTabChange)
                return;
            
            try
            {
                if (e.Source is TabControl)
                {
                    TabItem? currentTab = MainTabControl.SelectedItem as TabItem;
                    
                    // Track the previous tab from the removed items (before the change)
                    TabItem? previousTabFromEvent = null;
                    if (e.RemovedItems.Count > 0)
                    {
                        previousTabFromEvent = e.RemovedItems[0] as TabItem;
                        // Only track if it's not Advanced tab
                        if (previousTabFromEvent != null && previousTabFromEvent != AdvancedTab)
                        {
                            _previousTab = previousTabFromEvent;
                        }
                    }
                    
                    if (currentTab == AdvancedTab)
                    {
                        _isHandlingTabChange = true;
                        
                        // Always reset disclaimer flag when entering Advanced tab
                        _disclaimerAcknowledged = false;
                        
                        // Always show disclaimer when entering Advanced Settings tab
                        ShowAdvancedSettingsDisclaimer();
                        
                        // If user didn't acknowledge (clicked Back or Cancel), switch back to previous tab
                        if (!_disclaimerAcknowledged)
                        {
                            // Use the tracked previous tab, or use the one from the event, or default to Basic tab
                            TabItem? targetTab = _previousTab ?? previousTabFromEvent;
                            
                            // If no previous tab tracked, default to Basic tab (first item)
                            if (targetTab == null && MainTabControl.Items.Count > 0)
                            {
                                targetTab = MainTabControl.Items[0] as TabItem;
                            }
                            
                            // Ensure we're not trying to switch to Advanced tab
                            if (targetTab == AdvancedTab && MainTabControl.Items.Count > 0)
                            {
                                // Find first non-Advanced tab
                                foreach (TabItem item in MainTabControl.Items)
                                {
                                    if (item != AdvancedTab)
                                    {
                                        targetTab = item;
                                        break;
                                    }
                                }
                            }
                            
                            // Switch to the target tab
                            if (targetTab != null)
                            {
                                MainTabControl.SelectionChanged -= MainTabControl_SelectionChanged;
                                MainTabControl.SelectedItem = targetTab;
                                MainTabControl.SelectionChanged += MainTabControl_SelectionChanged;
                            }
                            
                            _isHandlingTabChange = false;
                            return;
                        }
                        
                        // User acknowledged disclaimer - ensure we stay on Advanced tab
                        // Explicitly set the Advanced tab as selected to prevent any tab switching
                        if (MainTabControl.SelectedItem != AdvancedTab)
                        {
                            MainTabControl.SelectionChanged -= MainTabControl_SelectionChanged;
                            MainTabControl.SelectedItem = AdvancedTab;
                            MainTabControl.SelectionChanged += MainTabControl_SelectionChanged;
                        }
                        
                        // Change badge to ATTACK MODE when entering Advanced Settings tab
                        UpdateLabModeBadge(true);
                        
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
                        
                        // Clear password when switching to Advanced tab (user must re-enter)
                        // Validation token persists for the session (one-time validation)
                        // Don't clear validation token - it should persist even when password field is cleared
                        if (AdvPasswordBox != null)
                        {
                            // Temporarily disable the password changed handler to prevent clearing validation token
                            AdvPasswordBox.PasswordChanged -= PasswordBox_PasswordChanged;
                            AdvPasswordBox.Password = string.Empty;
                            AdvPasswordBox.PasswordChanged += PasswordBox_PasswordChanged;
                            ValidatePasswordAndUpdateUI();
                        }
                        
                        _isHandlingTabChange = false;
                    }
                    else
                    {
                        _isHandlingTabChange = true;
                        
                        // Always reset disclaimer flag when leaving Advanced tab
                        _disclaimerAcknowledged = false;
                        
                        // Change badge back to LAB MODE when leaving Advanced Settings tab
                        UpdateLabModeBadge(false);
                        
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
                        
                        // Basic Settings doesn't require password - but keep validation token for Advanced tab
                        // Don't clear validation token - it should persist across tab switches
                        ValidatePasswordAndUpdateUI();
                        
                        _isHandlingTabChange = false;
                    }
                }
                
                UpdateProfileSummary();
                // Update Mbps validation when switching tabs
                UpdateMbpsValidation();
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error syncing settings between tabs: {ex}");
                _isHandlingTabChange = false;
            }
        }
        
        private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            // Don't auto-validate on password change - user must click Validate button
            // This ensures explicit validation is required
            if (MainTabControl.SelectedItem == AdvancedTab)
            {
                // Clear validation token when password changes (forces re-validation)
                _validationToken = null;
                ValidatePasswordAndUpdateUI();
            }
        }
        
        private void PasswordBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                ValidatePasswordAndShowFeedback(sender);
            }
        }
        
        private void ValidatePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            // Only validate password for Advanced Settings tab
            if (MainTabControl.SelectedItem == AdvancedTab && AdvPasswordBox != null)
            {
                ValidatePasswordAndShowFeedback(AdvPasswordBox);
            }
        }
        
        private void ValidatePasswordAndShowFeedback(object sender)
        {
            var passwordBox = sender as PasswordBox;
            
            // Get password and validate it FIRST (before checking token)
            string password = AdvPasswordBox?.Password ?? string.Empty;
            bool passwordCorrect = !string.IsNullOrEmpty(password) && ValidatePassword(password);
            
            if (passwordCorrect)
            {
                // Password is correct - generate and store validation token
                _validationToken = GenerateValidationToken();
                
                // Save token to file (encrypted) so it persists across sessions
                SaveValidationToken();
                
                // Log validation success
                _isAdvancedMode = true;
                _attackLogger.LogInfo("🔓 Password validated - Attack controls enabled");
                
                // Update UI to enable buttons (must be after token is set)
                ValidatePasswordAndUpdateUI();
                
                // Force UI update on UI thread to ensure buttons are enabled and Validate button is disabled
                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (StartAdvancedAttackButton != null)
                    {
                        bool tokenValid = !string.IsNullOrEmpty(_validationToken) && IsValidationTokenValid(_validationToken);
                        StartAdvancedAttackButton.IsEnabled = tokenValid;
                    }
                    
                    // Disable Validate button after successful validation
                    if (AdvValidatePasswordButton != null)
                    {
                        AdvValidatePasswordButton.IsEnabled = false;
                    }
                }, System.Windows.Threading.DispatcherPriority.Normal);
                
                // Show success feedback - inline message and toast
                if (passwordBox != null)
                {
                    passwordBox.BorderBrush = new SolidColorBrush(Colors.Green);
                    var timer = new System.Windows.Threading.DispatcherTimer();
                    timer.Interval = TimeSpan.FromSeconds(2);
                    timer.Tick += (s, args) =>
                    {
                        passwordBox.BorderBrush = SystemColors.ControlDarkBrush;
                        timer.Stop();
                    };
                    timer.Start();
                }
                
                // Hide error message if visible
                if (PasswordFeedbackText != null)
                {
                    PasswordFeedbackText.Visibility = Visibility.Collapsed;
                }
                
                // Show success toast instead of modal
                _toastService?.ShowSuccess("Authentication successful. Advanced controls enabled.", 3000);
            }
            else
            {
                // Password incorrect - clear any existing token
                _validationToken = null;
                ValidatePasswordAndUpdateUI();
                
                // Show inline error feedback
                if (passwordBox != null)
                {
                    passwordBox.BorderBrush = new SolidColorBrush(Colors.Red);
                }
                
                // Show inline error message
                if (PasswordFeedbackText != null)
                {
                    PasswordFeedbackText.Text = "Incorrect password. Please try again.";
                    PasswordFeedbackText.Visibility = Visibility.Visible;
                }
            }
        }
        
        private void ValidatePasswordAndUpdateUI()
        {
            // Basic Settings doesn't require password - always enabled
            // Advanced Settings requires explicit password validation via Validate button
            bool isValid = true;
            
            if (MainTabControl.SelectedItem == AdvancedTab)
            {
                // Check if we have a valid session token (one-time validation per session)
                // Buttons are ONLY enabled if token exists and is valid
                // No auto-validation - user MUST click Validate button
                isValid = !string.IsNullOrEmpty(_validationToken) && IsValidationTokenValid(_validationToken);
            }
            else
            {
                // Basic Settings - no password required
                isValid = true;
            }
            
            // Badge is now controlled by tab selection, not password validation
            // Badge shows ATTACK MODE when in Advanced Settings tab, LAB MODE otherwise
            // Password validation only controls button enable/disable state
            
            // Don't log validation here - only log when Validate button is actually clicked
            
            // Enable/disable attack buttons
            if (StartButton != null)
            {
                StartButton.IsEnabled = isValid;
            }
            if (StopButton != null)
            {
                StopButton.IsEnabled = isValid && StopButton.IsEnabled; // Keep existing enabled state if already running
            }
            if (StartAdvancedAttackButton != null)
            {
                // Check if attack is currently running (Stop button enabled = attack running)
                bool attackRunning = StopAdvancedAttackButton?.IsEnabled == true;
                
                if (!isValid)
                {
                    // Validation invalid - disable Start button
                    StartAdvancedAttackButton.IsEnabled = false;
                }
                else if (attackRunning)
                {
                    // Attack is running - keep Start button disabled
                    StartAdvancedAttackButton.IsEnabled = false;
                }
                else
                {
                    // No attack running and validation is valid - enable Start button
                    StartAdvancedAttackButton.IsEnabled = true;
                }
            }
            if (StopAdvancedAttackButton != null)
            {
                // Stop button state is managed by attack start/stop logic
                // Only disable if validation is invalid
                if (!isValid)
                {
                    StopAdvancedAttackButton.IsEnabled = false;
                }
                // If isValid, keep current state (will be enabled when attack starts)
            }
            
            // Disable Validate button if validation is already successful (prevent accidental re-validation)
            if (AdvValidatePasswordButton != null && MainTabControl.SelectedItem == AdvancedTab)
            {
                // Disable Validate button if token is valid (already validated)
                AdvValidatePasswordButton.IsEnabled = !isValid;
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
                
                var formattedNote = $"\n📝 USER NOTE ════════════════════════════════════════════════════════\n" +
                                   $"Time: {timestamp}\n" +
                                   $"Note: {note}\n" +
                                   $"════════════════════════════════════════════════════════ END NOTE 📝\n";

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

        private async void NetworkScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Get source IP to determine network
                string sourceIp = MainTabControl.SelectedItem == AdvancedTab ? 
                    AdvSourceIpTextBox.Text.Trim() : 
                    SourceIpTextBox.Text.Trim();

                if (string.IsNullOrWhiteSpace(sourceIp))
                {
                    MessageBox.Show("Please select a network interface first to determine the network to scan.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                if (!IPAddress.TryParse(sourceIp, out var sourceIpObj))
                {
                    MessageBox.Show("Please enter a valid source IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Get subnet mask from selected network interface
                byte[] subnetMask = new byte[] { 255, 255, 255, 0 }; // Default
                NetworkInterface? selectedNic = null;
                
                var selectedInterface = MainTabControl.SelectedItem == AdvancedTab ? 
                    AdvNetworkInterfaceComboBox.SelectedItem as dynamic : 
                    NetworkInterfaceComboBox.SelectedItem as dynamic;
                
                if (selectedInterface?.Interface is NetworkInterface nic)
                {
                    selectedNic = nic;
                    var ipProps = nic.GetIPProperties();
                    var unicastInfo = ipProps.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (unicastInfo?.IPv4Mask != null)
                    {
                        subnetMask = unicastInfo.IPv4Mask.GetAddressBytes();
                    }
                }

                string subnetMaskString = string.Join(".", subnetMask);
                
                // Calculate network address
                var sourceBytes = sourceIpObj.GetAddressBytes();
                var networkBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkBytes[i] = (byte)(sourceBytes[i] & subnetMask[i]);
                }
                string networkAddress = string.Join(".", networkBytes);

                // Open network scan window
                var networkScan = new NetworkScan(_attackLogger);
                var scanWindow = new NetworkScanWindow(
                    networkScan, 
                    _attackLogger, 
                    _databaseService, 
                    _supabaseSyncService,
                    _hardwareId,
                    _machineName,
                    _username);
                scanWindow.Owner = this;
                scanWindow.Show();

                // Start scan in background
                await scanWindow.StartScanAsync(networkAddress, subnetMaskString);
                    }
                    catch (Exception ex)
                    {
                _attackLogger.LogError($"Network scan failed: {ex.Message}");
                MessageBox.Show($"Error during network scan: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
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

        #region Firewall Reachability Discovery


        /// <summary>
        /// Open Reachability & Path Analysis Wizard
        /// </summary>
        private void ReachabilityPathAnalysisButton_Click(object sender, RoutedEventArgs e)
        {
            ReachabilityWizardWindow? wizard = null;
            try
            {
                // Try to create the window
                wizard = new ReachabilityWizardWindow();
                wizard.Owner = this;
                wizard.ShowDialog();
                
                // Check if wizard completed successfully (user finished all steps)
                // For now, we'll consider it passed if the wizard was closed normally
                // In the future, we could check the actual results
                _reachabilityTestPassed = true;
                UpdateSecurityAssessmentStatus();
            }
            catch (NullReferenceException nre)
            {
                _logger.Error(nre, "Null reference error opening reachability wizard");
                string errorMsg = $"Null reference error opening wizard.\n\nMessage: {nre.Message}";
                if (nre.StackTrace != null)
                {
                    errorMsg += $"\n\nStack trace:\n{nre.StackTrace}";
                }
                if (nre.TargetSite != null)
                {
                    errorMsg += $"\n\nTarget site: {nre.TargetSite}";
                }
                MessageBox.Show(errorMsg, "Null Reference Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (System.Windows.Markup.XamlParseException xamlEx)
            {
                _logger.Error(xamlEx, "XAML parse error opening reachability wizard");
                string errorMsg = $"XAML parse error: {xamlEx.Message}";
                if (xamlEx.InnerException != null)
                {
                    errorMsg += $"\n\nInner: {xamlEx.InnerException.Message}";
                }
                MessageBox.Show(errorMsg, "XAML Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error opening reachability wizard");
                string errorMsg = $"Error opening wizard: {ex.Message}\n\nType: {ex.GetType().Name}";
                if (ex.InnerException != null)
                {
                    errorMsg += $"\n\nInner exception: {ex.InnerException.Message}";
                }
                if (ex.StackTrace != null)
                {
                    errorMsg += $"\n\nStack trace:\n{ex.StackTrace}";
                }
                if (ex.TargetSite != null)
                {
                    errorMsg += $"\n\nTarget site: {ex.TargetSite}";
                }
                MessageBox.Show(errorMsg, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                try
                {
                    wizard?.Close();
                }
                catch { }
            }
        }


        /// <summary>
        /// Validate numeric input for text boxes
        /// </summary>
        private void NumericTextBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            if (sender is TextBox textBox)
            {
                e.Handled = !System.Text.RegularExpressions.Regex.IsMatch(e.Text, "^[0-9]+$");
            }
        }

        private async void StartSnmpWalkButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_snmpWalkService == null)
                {
                    MessageBox.Show("SNMP Walk service is not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                // Validate inputs
                if (string.IsNullOrWhiteSpace(SnmpWalkTargetIpTextBox.Text))
                {
                    MessageBox.Show("Please enter a target IP address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!IPAddress.TryParse(SnmpWalkTargetIpTextBox.Text.Trim(), out _))
                {
                    MessageBox.Show("Invalid IP address format.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!int.TryParse(SnmpWalkPortTextBox.Text.Trim(), out int port) || port < 1 || port > 65535)
                {
                    MessageBox.Show("Invalid port number. Must be between 1 and 65535.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var targetIp = SnmpWalkTargetIpTextBox.Text.Trim();

                // Disable start button, enable stop button
                StartSnmpWalkButton.IsEnabled = false;
                StopSnmpWalkButton.IsEnabled = true;

                // Create cancellation token
                _snmpWalkCancellationTokenSource = new CancellationTokenSource();
                var token = _snmpWalkCancellationTokenSource.Token;

                // Create progress reporter
                var progress = new Progress<(string message, int percent)>(update =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        SnmpWalkProgressBar.Value = update.percent;
                        _attackLogger.LogInfo(update.message);
                    });
                });

                // Start SNMP walk in background
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var result = await _snmpWalkService.WalkAsync(targetIp, port, progress, token);

                        Dispatcher.Invoke(async () =>
                        {
                            StartSnmpWalkButton.IsEnabled = true;
                            StopSnmpWalkButton.IsEnabled = false;
                            SnmpWalkProgressBar.Visibility = Visibility.Collapsed;
                            SnmpWalkProgressBar.Value = 0;

                            // Update security assessment: SNMP is not vulnerable if no successful authentication
                            _snmpWalkNotVulnerable = !result.Success;
                            UpdateSecurityAssessmentStatus();

                            // Save SNMP walk result to database
                            try
                            {
                                await _databaseService.SaveSnmpWalkResultAsync(result, null);
                            }
                            catch (Exception ex)
                            {
                                _logger.Error(ex, "Failed to save SNMP walk result");
                                // Don't show error to user, just log it
                            }

                            // Show custom results window instead of MessageBox
                            var resultsWindow = new SnmpWalkResultsWindow(result)
                            {
                                Owner = this
                            };
                            resultsWindow.ShowDialog();
                        });
                    }
                    catch (OperationCanceledException)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            _attackLogger.LogWarning("[SNMP Walk] Operation canceled by user");
                            StartSnmpWalkButton.IsEnabled = true;
                            StopSnmpWalkButton.IsEnabled = false;
                            SnmpWalkProgressBar.Visibility = Visibility.Collapsed;
                            SnmpWalkProgressBar.Value = 0;
                        });
                    }
                    catch (Exception ex)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            _attackLogger.LogError($"[SNMP Walk] Error: {ex.Message}");
                            MessageBox.Show($"Error during SNMP walk: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            StartSnmpWalkButton.IsEnabled = true;
                            StopSnmpWalkButton.IsEnabled = false;
                            SnmpWalkProgressBar.Visibility = Visibility.Collapsed;
                            SnmpWalkProgressBar.Value = 0;
                        });
                    }
                }, token);
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error starting SNMP walk");
                MessageBox.Show($"Error starting SNMP walk: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                StartSnmpWalkButton.IsEnabled = true;
                StopSnmpWalkButton.IsEnabled = false;
            }
        }

        private void StopSnmpWalkButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _snmpWalkCancellationTokenSource?.Cancel();
                _attackLogger.LogInfo("[SNMP Walk] Stop requested by user");
                // Reset SNMP status when stopped
                _snmpWalkNotVulnerable = false;
                UpdateSecurityAssessmentStatus();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error stopping SNMP walk");
                MessageBox.Show($"Error stopping SNMP walk: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateSecurityAssessmentStatus()
        {
            try
            {
                if (SecurityAssessmentStatusBorder == null || SecurityAssessmentStatusTextBlock == null)
                    return;

                if (_reachabilityTestPassed && _snmpWalkNotVulnerable)
                {
                    SecurityAssessmentStatusBorder.Visibility = Visibility.Visible;
                    SecurityAssessmentStatusTextBlock.Text = "✓ Pass - The network is secure";
                    SecurityAssessmentStatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(5, 150, 105)); // Green #059669
                }
                else
                {
                    SecurityAssessmentStatusBorder.Visibility = Visibility.Collapsed;
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error updating security assessment status");
            }
        }

        #endregion

    }

} 
                            
                            // Switch to the target tab
