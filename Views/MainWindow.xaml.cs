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
using Dorothy.Services.Reachability;
using Microsoft.Win32;
using NLog;
using SharpPcap;

namespace Dorothy.Views
{

    public partial class MainWindow : Window
    {
        private readonly MainController _mainController;
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();
        private readonly NetworkStorm _networkStorm;
        private readonly AttackLogger _attackLogger;
        private readonly TraceRoute _traceRoute;
        private Services.SnmpWalkService? _snmpWalkService;
        private CancellationTokenSource? _snmpWalkCancellationTokenSource;

        private bool _reachabilityTestPassed = false;
        private bool _snmpWalkNotVulnerable = false;
        private bool _isAdvancedMode;
        private string _validationToken;
        private const string VALIDATION_TOKEN_FILE = "validation.token";
        private bool _disclaimerAcknowledged = false;
        private bool _isHandlingTabChange = false;
        private TabItem? _previousTab = null;
        private const string DISCLAIMER_ACK_FILE = "disclaimer.ack";
        private bool? _lastSubnetStatus;
        private string? _lastSubnetMessage;
        private DateTime _lastSubnetLogTime = DateTime.MinValue;
        private const int SUBNET_LOG_THROTTLE_MS = 1000;
        private CancellationTokenSource? _targetIpDebounceTokenSource;
        private const string NOTE_PLACEHOLDER = "Add a note to the security log... (Ctrl+Enter to save)";
        private bool _isSyncingComboBoxes = false;

        private long _totalPacketsSent = 0;

        private long _targetWireBytesPerSec = 0;

        private DateTime _attackStartTime;

        private DateTime _runStartTime;

        private System.Windows.Threading.DispatcherTimer? _statsTimer;
        private string? _currentRunningAttackType = null;

        private bool _isTcpCalibrating = false;

        private Dorothy.Services.FloodRunStatus _currentRunStatus = Dorothy.Services.FloodRunStatus.Idle;

        private Dorothy.Services.FloodProtocolCapabilities _protocolCaps =
            Dorothy.Services.FloodProtocolCapabilities.None;

        private Dorothy.Services.RateUnit _currentRateUnit    = Dorothy.Services.RateUnit.Mbps;
        private Dorothy.Services.RateUnit _advCurrentRateUnit = Dorothy.Services.RateUnit.Mbps;

        private string _logFileLocation = string.Empty;
        private double _fontSize = 12.0;
        private int _themeIndex = 0;

        private readonly Services.DatabaseService _databaseService;
        private readonly Services.SupabaseSyncService _supabaseSyncService;
        private readonly Services.ToastNotificationService _toastService;
        private System.Windows.Threading.DispatcherTimer? _syncCheckTimer;

        private readonly string _hardwareId;
        private readonly string _machineName;
        private readonly string _username;

        private bool _hasShownAttackLogSyncNotification = false;
        private Services.UIScalingService? _uiScalingService;
        private double _baseFontSize = 12;
        private Services.UpdateCheckService? _updateCheckService;
        private System.Windows.Threading.DispatcherTimer? _updateCheckTimer;

        private Services.FirewallDiscoveryEngine? _firewallDiscoveryEngine;

        public MainWindow()
        {
            InitializeComponent();

            _databaseService = new Services.DatabaseService();
            _supabaseSyncService = new Services.SupabaseSyncService(_databaseService);
            _toastService = new Services.ToastNotificationService(this);

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
                userId: null
            );

            _networkStorm = new NetworkStorm(_attackLogger);
            _traceRoute = new TraceRoute(_attackLogger);

            _mainController = new MainController(
                _networkStorm,
                StartButton,
                StopButton,
                status => Dispatcher.Invoke(() => UpdateRunStatus(status)),
                LogTextBox,
                this);

            _networkStorm.PacketSent          += NetworkStorm_PacketSent;
            _networkStorm.StatsPublished      += NetworkStorm_StatsPublished;
            _networkStorm.TcpCalibrationStarted  += (_, _) => Dispatcher.BeginInvoke(() =>
            {
                _isTcpCalibrating = true;
                UpdateRunStatus(Dorothy.Services.FloodRunStatus.Calibrating);
            });
            _networkStorm.TcpCalibrationCompleted += (_, _) => Dispatcher.BeginInvoke(() =>
            {
                _isTcpCalibrating = false;

                _runStartTime = DateTime.Now;
                _mainController.Log("TCP calibration complete — main send loop starting");
                UpdateRunStatus(Dorothy.Services.FloodRunStatus.Running);
            });

            _statsTimer = new System.Windows.Threading.DispatcherTimer();
            _statsTimer.Interval = TimeSpan.FromMilliseconds(250);
            _statsTimer.Tick += StatsTimer_Tick;

            _syncCheckTimer = new System.Windows.Threading.DispatcherTimer();
            _syncCheckTimer.Interval = TimeSpan.FromSeconds(30);
            _syncCheckTimer.Tick += SyncCheckTimer_Tick;
            _syncCheckTimer.Start();

            _firewallDiscoveryEngine = new Services.FirewallDiscoveryEngine();

            _snmpWalkService = new Services.SnmpWalkService(_attackLogger);

            _uiScalingService = Services.UIScalingService.Instance;

            PopulateNetworkInterfaces();
            PopulateAttackTypes();
            UpdateProfileSummary();
            LoadSettings();

            Loaded += MainWindow_Loaded;

            AttackTypeComboBox.SelectedIndex = 0;
            AdvancedAttackTypeComboBox.SelectedIndex = 0;

            UpdateAttackTypeDescription();
            UpdateTcpSynModeSelection();

            NoteTextBox.Text = NOTE_PLACEHOLDER;
            NoteTextBox.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xAA));
        }

        private void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {

                _disclaimerAcknowledged = false;

                if (LoadValidationToken())
                {

                    _isAdvancedMode = true;
                    ValidatePasswordAndUpdateUI();

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        if (AdvValidatePasswordButton != null)
                        {
                            AdvValidatePasswordButton.IsEnabled = false;
                        }
                    }, System.Windows.Threading.DispatcherPriority.Normal);

                    _attackLogger.LogInfo("🔓 Previous validation restored - Attack controls enabled");
                }

                ApplyResponsiveScaling();

                ApplyUIScaling();

                if (ToastContainer != null)
                {
                    _toastService.Initialize(ToastContainer);
                }

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

                    if (disclaimerWindow.DontShowAgain)
                    {
                        SaveDisclaimerPreference();
                    }
                }

                _ = Task.Run(async () => await UpdateSyncStatus());

                _updateCheckService = new Services.UpdateCheckService(_attackLogger);

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

        private void ApplyUIScaling()
        {
            try
            {
                if (_uiScalingService == null) return;

                var dpiScale = _uiScalingService.GetDpiScaleForWindow(this);

                var (screenWidth, screenHeight) = _uiScalingService.GetScreenDimensionsForWindow(this);

                var responsiveScale = _uiScalingService.CalculateResponsiveScale(this);

                var screenCategory = _uiScalingService.GetScreenCategory(this);

                double combinedScale;

                double baselineWidth = 1920;
                double baselineHeight = 1080;
                double widthRatio = screenWidth / baselineWidth;
                double heightRatio = screenHeight / baselineHeight;
                double sizeRatio = Math.Min(widthRatio, heightRatio);

                if (screenCategory == Services.ScreenCategory.Small)
                {

                    combinedScale = Math.Min(dpiScale, sizeRatio * 0.75);
                    combinedScale = Math.Max(0.70, Math.Min(0.80, combinedScale));
                }
                else if (screenCategory == Services.ScreenCategory.Medium)
                {

                    combinedScale = Math.Min(dpiScale, sizeRatio * 0.85);
                    combinedScale = Math.Max(0.80, Math.Min(0.90, combinedScale));
                }
                else
                {

                    if (sizeRatio < 1.0)
                    {

                        combinedScale = Math.Min(dpiScale, sizeRatio * 0.95);
                        combinedScale = Math.Max(0.85, Math.Min(0.95, combinedScale));
                    }
                    else
                    {

                        combinedScale = Math.Min(dpiScale, responsiveScale);
                    }
                }

                _uiScalingService.ApplyFontScaling(this, _baseFontSize, combinedScale);

                var (minWidth, minHeight) = _uiScalingService.GetRecommendedMinSize(this);

                this.MinWidth = minWidth;
                this.MinHeight = minHeight;

                if (this.WindowState != WindowState.Maximized)
                {
                    if (screenCategory == Services.ScreenCategory.Small)
                    {

                        this.Width = Math.Min(screenWidth * 0.98, 1200);
                        this.Height = Math.Min(screenHeight * 0.95, 800);
                    }
                }

                if (MainContentGrid != null)
                {
                    var baseMargin = screenCategory == Services.ScreenCategory.Small ? 8.0 :
                                    screenCategory == Services.ScreenCategory.Medium ? 12.0 : 16.0;
                    var margin = _uiScalingService.GetScaledThickness(baseMargin, combinedScale);
                    MainContentGrid.Margin = margin;
                }

                if (MainContentGrid != null && MainContentGrid.ColumnDefinitions.Count >= 2)
                {
                    if (screenCategory == Services.ScreenCategory.Small)
                    {

                        MainContentGrid.ColumnDefinitions[0].MinWidth = 320;
                        MainContentGrid.ColumnDefinitions[1].MinWidth = 320;
                    }
                    else
                    {

                        MainContentGrid.ColumnDefinitions[0].MinWidth = 400;
                        MainContentGrid.ColumnDefinitions[1].MinWidth = 400;
                    }
                }

                if (MainTabControl != null)
                {

                    if (screenCategory == Services.ScreenCategory.Small)
                    {
                        MainTabControl.Margin = new Thickness(0, 0, 6, 0);
                    }
                    else if (screenCategory == Services.ScreenCategory.Medium)
                    {
                        MainTabControl.Margin = new Thickness(0, 0, 8, 0);
                    }
                    else
                    {
                        MainTabControl.Margin = new Thickness(0, 0, 12, 0);
                    }

                    double transformScale = combinedScale;
                    if (screenCategory == Services.ScreenCategory.Large || screenCategory == Services.ScreenCategory.ExtraLarge)
                    {

                        transformScale = Math.Max(0.90, Math.Min(1.0, combinedScale));
                    }

                    if (transformScale < 1.0)
                    {
                        var scaleTransform = new ScaleTransform(transformScale, transformScale);
                        scaleTransform.CenterX = 0;
                        scaleTransform.CenterY = 0;
                        MainTabControl.LayoutTransform = scaleTransform;
                    }
                    else
                    {

                        if (screenCategory == Services.ScreenCategory.Large || screenCategory == Services.ScreenCategory.ExtraLarge)
                        {
                            var scaleTransform = new ScaleTransform(0.95, 0.95);
                            scaleTransform.CenterX = 0;
                            scaleTransform.CenterY = 0;
                            MainTabControl.LayoutTransform = scaleTransform;
                        }
                        else
                        {
                            MainTabControl.LayoutTransform = null;
                        }
                    }
                }
            }
            catch (Exception ex)
            {

                System.Diagnostics.Debug.WriteLine($"Error applying UI scaling: {ex.Message}");
            }
        }

        private void UIScalingService_ScaleChanged(object? sender, EventArgs e)
        {
            try
            {
                if (_uiScalingService == null) return;

                _uiScalingService.ApplyFontScaling(this, _baseFontSize);

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

            if (IsLoaded)
            {
                ApplyUIScaling();
            }
        }

        private void Window_LocationChanged(object? sender, EventArgs e)
        {

            if (IsLoaded)
            {
                ApplyUIScaling();
            }
        }

        private void ApplyResponsiveScaling()
        {
            try
            {

                var screenWidth = SystemParameters.PrimaryScreenWidth;
                var screenHeight = SystemParameters.PrimaryScreenHeight;

                double baseWidth = 1920;
                double baseHeight = 1080;

                double widthScale = screenWidth / baseWidth;
                double heightScale = screenHeight / baseHeight;

                double scale = Math.Min(widthScale, heightScale);

                scale = Math.Max(0.6, Math.Min(1.2, scale));

                if (screenWidth < 1366 || screenHeight < 768)
                {

                    this.MinWidth = 800;
                    this.MinHeight = 600;
                }
                else if (screenWidth < 1600 || screenHeight < 900)
                {

                    this.MinWidth = 1000;
                    this.MinHeight = 650;
                }
                else
                {

                    this.MinWidth = 1200;
                    this.MinHeight = 700;
                }

                if (scale < 0.85)
                {

                    double fontSizeMultiplier = 0.9;

                    this.FontSize = 12 * fontSizeMultiplier;

                    if (PacketsSentText != null)
                        PacketsSentText.FontSize = 14 * fontSizeMultiplier;
                    if (ElapsedTimeText != null)
                        ElapsedTimeText.FontSize = 14 * fontSizeMultiplier;
                    if (MbpsSentText != null)
                        MbpsSentText.FontSize = 14 * fontSizeMultiplier;
                    if (ProfileSummaryText != null)
                        ProfileSummaryText.FontSize = 11 * fontSizeMultiplier;
                }

                if (this.WindowState != WindowState.Maximized)
                {
                    if (screenWidth < 1366 || screenHeight < 768)
                    {

                        this.Width = Math.Min(screenWidth * 0.95, 1200);
                        this.Height = Math.Min(screenHeight * 0.95, 800);
                    }
                }

                if (MainContentGrid != null)
                {
                    if (screenWidth < 1366 || screenHeight < 768)
                    {

                        MainContentGrid.Margin = new Thickness(8);
                    }
                    else if (screenWidth < 1600 || screenHeight < 900)
                    {

                        MainContentGrid.Margin = new Thickness(12);
                    }
                    else
                    {

                        MainContentGrid.Margin = new Thickness(16);
                    }
                }

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

                if (LogoImage != null && (screenWidth < 1366 || screenHeight < 768))
                {

                    LogoImage.Height = 120;
                }
                else if (LogoImage != null && (screenWidth < 1600 || screenHeight < 900))
                {

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
                return true;
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

        private void UpdateRunStatus(Dorothy.Services.FloodRunStatus status)
        {
            _currentRunStatus = status;
            switch (status)
            {
                case Dorothy.Services.FloodRunStatus.Idle:
                case Dorothy.Services.FloodRunStatus.Stopped:
                    ApplyBadge("Ready",        "#1A3A2A", "#4ADE80");
                    break;

                case Dorothy.Services.FloodRunStatus.Calibrating:
                    ApplyBadge("Calibrating…", "#3A3520", "#FBBF24");
                    break;

                case Dorothy.Services.FloodRunStatus.Running:
                    ApplyBadge("Running",      "#3A2020", "#F87171");
                    break;

                case Dorothy.Services.FloodRunStatus.UnderTarget:
                    ApplyBadge("Under Target", "#3A3520", "#FBBF24");
                    break;

                case Dorothy.Services.FloodRunStatus.Error:
                    ApplyBadge("Error",        "#3A2020", "#F87171");
                    break;
            }
        }

        private void ApplyBadge(string text, string bgHex, string fgHex, string? dotHex = null)
        {
            StatusBadge.Background     = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bgHex));
            StatusBadgeText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fgHex));
            StatusDot.Fill             = new SolidColorBrush((Color)ColorConverter.ConvertFromString(dotHex ?? fgHex));
            StatusBadgeText.Text       = text;
        }

        private void NetworkStorm_PacketSent(object? sender, Models.PacketEventArgs e)
        {

            _attackLogger.IncrementPacketCount();
        }

        private void NetworkStorm_StatsPublished(object? sender, Dorothy.Services.FloodSnapshot snapshot)
        {

            _totalPacketsSent = snapshot.PacketsSent;

            Dispatcher.InvokeAsync(() =>
            {

                MbpsSentText.Text   = $"{snapshot.ActualMbps:F1} Mbps";
                TargetRateText.Text = $"{snapshot.TargetMbps:F1} Mbps";

                if (snapshot.IsCalibrating || _isTcpCalibrating)
                {
                    RateDeltaText.Text = "Calibrating…";
                    RateDeltaText.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(217, 119, 6));
                    DiagnosticReasonText.Text = "Calibrating";
                    DiagnosticReasonText.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(107, 114, 128));
                    if (ConfidenceText != null) ConfidenceText.Text = "—";
                    if (DiagnosticReasonTooltipText != null)
                        DiagnosticReasonTooltipText.Text =
                            "TCP is measuring max PPS to size the payload. " +
                            "Rate comparison and diagnostics resume after calibration.";
                    return;
                }

                if (snapshot.TargetWireBytesPerSec == 0)
                {
                    RateDeltaText.Text       = "—";
                    RateDeltaText.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(107, 114, 128));
                }
                else
                {
                    double vs = snapshot.VsTargetPercent;
                    RateDeltaText.Text = $"{vs:F0}%";

                    System.Windows.Media.Color vsColor;
                    if (vs >= 95)      vsColor = System.Windows.Media.Color.FromRgb(5, 150, 105);
                    else if (vs >= 70) vsColor = System.Windows.Media.Color.FromRgb(217, 119, 6);
                    else               vsColor = System.Windows.Media.Color.FromRgb(220, 38, 38);
                    RateDeltaText.Foreground = new System.Windows.Media.SolidColorBrush(vsColor);

                    UpdateRunStatus(vs >= 95
                        ? Dorothy.Services.FloodRunStatus.Running
                        : Dorothy.Services.FloodRunStatus.UnderTarget);
                }

                string reason = string.IsNullOrWhiteSpace(snapshot.ReasonString)
                    ? "—"
                    : snapshot.ReasonString;

                System.Windows.Media.Color reasonColor = reason switch
                {
                    "On target"      => System.Windows.Media.Color.FromRgb(5, 150, 105),
                    "NIC saturated"  => System.Windows.Media.Color.FromRgb(220, 38, 38),
                    "CPU bound"      => System.Windows.Media.Color.FromRgb(217, 119, 6),
                    "Drain starved"  => System.Windows.Media.Color.FromRgb(217, 119, 6),
                    _                => System.Windows.Media.Color.FromRgb(107, 114, 128)
                };
                DiagnosticReasonText.Text = reason;
                DiagnosticReasonText.Foreground = new System.Windows.Media.SolidColorBrush(reasonColor);

                if (ConfidenceText != null)
                    ConfidenceText.Text =
                        $"Confidence: {Dorothy.Services.RateConverter.FormatConfidenceShort(snapshot.Confidence)}";

                if (DiagnosticReasonTooltipText != null)
                    DiagnosticReasonTooltipText.Text =
                        Dorothy.Services.RateConverter.ExplainFull(snapshot.LastReason) +
                        $"\n\nReason (plain): {reason}" +
                        $"\n[Code: {snapshot.LastReason}]" +
                        "\n\nAll diagnostics are heuristic inferences from counters, " +
                        "not directly measured root causes.";
            });
        }

        private void StatsTimer_Tick(object? sender, EventArgs e)
        {
            if (_attackStartTime == default) return;

            var runStart = _runStartTime != default ? _runStartTime : _attackStartTime;
            var elapsed  = DateTime.Now - runStart;
            ElapsedTimeText.Text = elapsed.ToString(@"hh\:mm\:ss");

            PacketsSentText.Text = _totalPacketsSent.ToString("N0");

            TargetRateText.Text = Dorothy.Services.RateConverter.Format(_targetWireBytesPerSec);

            var snap = _networkStorm.LatestSnapshot;
            if (snap == null)
            {
                if (_protocolCaps.SupportsRateSnapshots)
                {

                    MbpsSentText.Text = "—";
                }
                else
                {

                    MbpsSentText.Text         = "N/A";
                    RateDeltaText.Text        = "N/A";
                    RateDeltaText.Foreground  = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(107, 114, 128));
                    DiagnosticReasonText.Text = "—";
                    DiagnosticReasonText.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(107, 114, 128));
                    if (ConfidenceText != null) ConfidenceText.Text = "N/A";
                    if (DiagnosticReasonTooltipText != null)
                        DiagnosticReasonTooltipText.Text = _protocolCaps.UnavailableMessage;
                }
            }

            if (_isTcpCalibrating && _currentRunStatus != Dorothy.Services.FloodRunStatus.Calibrating)
                UpdateRunStatus(Dorothy.Services.FloodRunStatus.Calibrating);
        }

        private void ResetStatistics()
        {
            _totalPacketsSent      = 0;
            _attackStartTime       = default;
            _runStartTime          = default;
            _targetWireBytesPerSec = 0;
            _isTcpCalibrating      = false;
            _currentRunStatus      = Dorothy.Services.FloodRunStatus.Idle;
            _protocolCaps          = Dorothy.Services.FloodProtocolCapabilities.None;

            PacketsSentText.Text  = "0";
            ElapsedTimeText.Text  = "00:00:00";
            MbpsSentText.Text     = "—";
            TargetRateText.Text   = "—";
            RateDeltaText.Text    = "—";
            RateDeltaText.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(107, 114, 128));
            DiagnosticReasonText.Text = "—";
            DiagnosticReasonText.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(107, 114, 128));
            if (ConfidenceText != null) ConfidenceText.Text = "—";
            _currentRunningAttackType = null;
        }

        private void UpdateProfileSummary()
        {
            try
            {
                var parts = new List<string>();

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

                string mode = MainTabControl.SelectedItem == AdvancedTab ? "Advanced" : "Basic";
                parts.Add($"Mode: {mode}");

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

                    _logFileLocation = AppDomain.CurrentDomain.BaseDirectory;
                }

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

                double fontSize = _fontSize;

                this.FontSize = fontSize;

                if (LogTextBox != null)
                {
                    LogTextBox.FontSize = fontSize;
                }

                ApplyFontSizeToElement(TargetIpTextBox, fontSize);
                ApplyFontSizeToElement(TargetMacTextBox, fontSize);
                ApplyFontSizeToElement(SourceIpTextBox, fontSize);
                ApplyFontSizeToElement(SourceMacTextBox, fontSize);
                ApplyFontSizeToElement(GatewayIpTextBox, fontSize);
                ApplyFontSizeToElement(TargetPortTextBox, fontSize);
                ApplyFontSizeToElement(MegabitsPerSecondTextBox, fontSize);
                ApplyFontSizeToElement(NoteTextBox, fontSize);

                ApplyFontSizeToElement(AdvTargetIpTextBox, fontSize);
                ApplyFontSizeToElement(AdvTargetMacTextBox, fontSize);
                ApplyFontSizeToElement(AdvSourceIpTextBox, fontSize);
                ApplyFontSizeToElement(AdvSourceMacTextBox, fontSize);
                ApplyFontSizeToElement(AdvGatewayIpTextBox, fontSize);
                ApplyFontSizeToElement(AdvTargetPortTextBox, fontSize);
                ApplyFontSizeToElement(AdvMegabitsPerSecondTextBox, fontSize);

                ApplyFontSizeToElement(NetworkInterfaceComboBox, fontSize);
                ApplyFontSizeToElement(AttackTypeComboBox, fontSize);
                ApplyFontSizeToElement(AdvNetworkInterfaceComboBox, fontSize);
                ApplyFontSizeToElement(AdvancedAttackTypeComboBox, fontSize);

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

                if (element is Control control)
                {
                    control.FontSize = fontSize;
                }

                else if (element is TextBlock textBlock)
                {
                    textBlock.FontSize = fontSize;
                }
            }
        }

        private void ProtocolCard_Click(object sender, RoutedEventArgs e)
        {
            if (sender is FrameworkElement fe && fe.Tag is string tag && int.TryParse(tag, out int idx))
            {
                if (idx >= 0 && idx < AttackTypeComboBox.Items.Count)
                    AttackTypeComboBox.SelectedIndex = idx;
            }
        }

        private void UpdateProtocolCardSelection()
        {
            if (ProtocolCardsPanel == null || AttackTypeComboBox == null) return;
            int selected = AttackTypeComboBox.SelectedIndex;
            var accent = (SolidColorBrush)FindResource("AccentBlue");
            var selectedBg = new SolidColorBrush(Color.FromRgb(0x2E, 0x3F, 0x5C));
            foreach (var child in ProtocolCardsPanel.Children)
            {
                if (child is Border b && b.Tag is string tag && int.TryParse(tag, out int idx))
                {
                    if (idx == selected)
                    {
                        b.BorderBrush = accent;
                        b.BorderThickness = new Thickness(2);
                        b.Background = selectedBg;
                    }
                    else
                    {
                        b.ClearValue(Border.BorderBrushProperty);
                        b.ClearValue(Border.BorderThicknessProperty);
                        b.ClearValue(Border.BackgroundProperty);
                    }
                }
            }
        }

        private void HelpButton_Click(object sender, RoutedEventArgs e)
        {

            var updateCheckService = _updateCheckService ?? new Services.UpdateCheckService(_attackLogger);

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

                        UpdateAvailableBadge.Visibility = Visibility.Visible;
                    }
                    else
                    {

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

                sourceIp = string.IsNullOrEmpty(sourceIp) ? "unknown" : sourceIp.Replace(".", "_");
                targetIp = string.IsNullOrEmpty(targetIp) ? "unknown" : targetIp.Replace(".", "_");
                attackType = string.IsNullOrEmpty(attackType) ? "None" : attackType.Replace(" ", "_").Replace("(", "").Replace(")", "");

                var fileName = $"{DateTime.Now:yyyyMMdd_HHmmss}_{sourceIp}_to_{targetIp}_{attackType}.txt";

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

                _statsTimer?.Stop();
                _syncCheckTimer?.Stop();
                _updateCheckTimer?.Stop();

                _targetIpDebounceTokenSource?.Cancel();
                _targetIpDebounceTokenSource?.Dispose();

                if (StartButton.IsEnabled == false || StopButton.IsEnabled == true)
                {
                    try
                    {
                        _logger.Info("Stopping running attack...");
                        bool isAdvancedMode = MainTabControl.SelectedItem == AdvancedTab && _isAdvancedMode;
                        var stopTask = _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
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

                if (StartAdvancedAttackButton.IsEnabled == false || StopAdvancedAttackButton.IsEnabled == true)
                {
                    try
                    {
                        _logger.Info("Stopping advanced attack...");
                        bool isAdvancedMode = MainTabControl.SelectedItem == AdvancedTab && _isAdvancedMode;
                        var stopTask = _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
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

                try
                {
                    _logger.Info("Disposing network resources...");
                    _networkStorm?.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.Warn(ex, "Error disposing network storm");
                }

                try
                {
                    _logger.Info("Closing database connections...");
                    _databaseService?.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.Warn(ex, "Error disposing database service");
                }

                if (!string.IsNullOrEmpty(LogTextBox.Text))
                {
                    try
                    {
                        string logLocation = string.IsNullOrEmpty(_logFileLocation)
                            ? AppDomain.CurrentDomain.BaseDirectory
                            : _logFileLocation;

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

                    }
                }

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

                    SyncLoadingOverlay.Visibility = Visibility.Visible;
                    SyncProgressText.Text = "Preparing sync...";

                    _supabaseSyncService.ProgressChanged += OnSyncProgressChanged;

                    try
                    {
                        int syncedLogsCount = 0;
                        int syncedAssetsCount = 0;
                        int syncedTestsCount = 0;
                        bool hasDeletions = syncWindow.DeletedLogIds.Count > 0 || syncWindow.DeletedAssetIds.Count > 0 || syncWindow.DeletedTestIds.Count > 0 || syncWindow.DeletedSnmpWalkIds.Count > 0;

                    if (syncWindow.DeletedLogIds.Count > 0)
                    {
                        await _databaseService.DeleteLogsAsync(syncWindow.DeletedLogIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedLogIds.Count} log(s).");
                    }

                    if (syncWindow.DeletedAssetIds.Count > 0)
                    {
                        await _databaseService.DeleteAssetsAsync(syncWindow.DeletedAssetIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedAssetIds.Count} asset(s).");
                    }

                    if (syncWindow.DeletedTestIds.Count > 0)
                    {
                        await _databaseService.DeleteReachabilityTestsAsync(syncWindow.DeletedTestIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedTestIds.Count} reachability test(s).");
                    }

                    if (syncWindow.DeletedSnmpWalkIds.Count > 0)
                    {
                        await _databaseService.DeleteReachabilityTestsAsync(syncWindow.DeletedSnmpWalkIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedSnmpWalkIds.Count} SNMP walk(s).");
                    }

                    if (syncWindow.ShouldSync)
                    {

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

                        if (syncWindow.SelectedAssetIds.Count > 0)
                        {

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

                        var deletedCount = syncWindow.DeletedLogIds.Count + syncWindow.DeletedAssetIds.Count + syncWindow.DeletedTestIds.Count;
                        _toastService.ShowInfo($"Deleted {deletedCount} item(s).");
                    }

                        SyncLoadingOverlay.Visibility = Visibility.Collapsed;
                        _supabaseSyncService.ProgressChanged -= OnSyncProgressChanged;

                        CloudSyncButton.IsEnabled = true;
                        CloudSyncButton.ToolTip = originalTooltip;

                        _ = Task.Run(async () => await UpdateSyncStatus());
                    }
                    catch (Exception ex)
                    {

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
                var pendingTestsCount = await _supabaseSyncService.GetPendingReachabilityTestsCountAsync();
                var totalPending = pendingLogsCount + pendingAssetsCount + pendingTestsCount;

                Dispatcher.Invoke(() =>
                {
                    if (totalPending > 0)
                    {
                        CloudSyncNotificationBadge.Visibility = Visibility.Visible;
                        CloudSyncNotificationText.Text = totalPending > 99 ? "99+" : totalPending.ToString();

                        var tooltipParts = new List<string>();
                        if (pendingLogsCount > 0) tooltipParts.Add($"{pendingLogsCount} log(s)");
                        if (pendingAssetsCount > 0) tooltipParts.Add($"{pendingAssetsCount} asset(s)");
                        if (pendingTestsCount > 0) tooltipParts.Add($"{pendingTestsCount} test(s)");
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

                if (!CheckSubnetAndGatewayRequirement(targetIp))
                {
                    MessageBox.Show("Gateway IP is required for targets on different subnets.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = await _mainController.PingHostAsync(targetIp);

                if (sender == PingButton) UpdateMacRouteHint(targetIp);

                if (result.Success)
                {
                    targetTextBox.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                    targetTextBox.Foreground = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                    targetTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                    _attackLogger.LogPing(targetIp, true, (int)result.RoundtripTime);

                    if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedItem &&
                        selectedItem.Content.ToString() == "ARP Spoofing")
                    {
                        var otherTextBox = (sender == PingButton) ? AdvTargetIpTextBox : TargetIpTextBox;
                        otherTextBox.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                        otherTextBox.Foreground = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                        otherTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                    }
                }
                else
                {
                    targetTextBox.Background = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                    targetTextBox.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                    targetTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                    _attackLogger.LogPing(targetIp, false);

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
                var errorBox = (sender == PingButton) ? TargetIpTextBox : AdvTargetIpTextBox;
                errorBox.Background = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                errorBox.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                errorBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
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

                var selectedInterface = NetworkInterfaceComboBox.SelectedItem as dynamic;
                if (selectedInterface?.Interface is NetworkInterface nic)
                {
                    var ipProps = nic.GetIPProperties();
                    var unicastInfo = ipProps.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (unicastInfo != null)
                    {

                        var maskBytes = unicastInfo.IPv4Mask.GetAddressBytes();
                        Array.Reverse(maskBytes);
                        var mask = BitConverter.ToUInt32(maskBytes, 0);

                        var sourceBytes = sourceIpAddress.GetAddressBytes();
                        var targetBytes = targetIpAddress.GetAddressBytes();
                        Array.Reverse(sourceBytes);
                        Array.Reverse(targetBytes);
                        var sourceInt = BitConverter.ToUInt32(sourceBytes, 0);
                        var targetInt = BitConverter.ToUInt32(targetBytes, 0);

                        var sameSubnet = (sourceInt & mask) == (targetInt & mask);

                        if (!sameSubnet)
                        {
                            if (isResolvingMac)
                            {

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

                        GatewayIpTextBox.IsEnabled = !sameSubnet;
                        if (sameSubnet)
                        {
                            GatewayIpTextBox.Text = string.Empty;
                        }
                        GatewayIpTextBox.ClearValue(TextBox.BackgroundProperty);
                        GatewayIpTextBox.ClearValue(TextBox.ForegroundProperty);
                        GatewayIpTextBox.ClearValue(TextBox.BorderBrushProperty);

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
                if (button != null) button.Content = "Resolving...";

                bool isBasic        = sender == ResolveMacButton;
                var targetIp        = isBasic ? TargetIpTextBox.Text        : AdvTargetIpTextBox.Text;
                var sourceIpText    = isBasic ? SourceIpTextBox.Text         : AdvSourceIpTextBox.Text;
                var targetMacTB     = isBasic ? TargetMacTextBox             : AdvTargetMacTextBox;
                var fallbackCB      = isBasic ? MacFallbackCheckBox          : AdvMacFallbackCheckBox;

                if (string.IsNullOrWhiteSpace(targetIp))
                {
                    MessageBox.Show("Please enter a target IP address.", "Error",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var routeType = RouteType.Unknown;
                if (IPAddress.TryParse(targetIp, out var targetIpAddr) &&
                    IPAddress.TryParse(sourceIpText, out var sourceIpAddr))
                {
                    routeType = TargetExpansionService.DetermineRoute(sourceIpAddr, targetIpAddr);
                }

                if (routeType == RouteType.NoRoute)
                {
                    _attackLogger.LogError(
                        $"No route to {targetIp} from {sourceIpText} — raw packet send will fail. " +
                        "Check NIC selection and routing.");
                    MessageBox.Show(
                        $"No route to target {targetIp} from source IP {sourceIpText}.\n\n" +
                        "Raw packet transmission will fail. Check NIC selection and routing configuration.",
                        "No Route to Target", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (routeType == RouteType.Unknown)
                {
                    var proceed = MessageBox.Show(
                        $"Cannot determine route to {targetIp} from {sourceIpText}.\n\n" +
                        "If the target is on a different subnet, use the next-hop gateway MAC.\n" +
                        "The remote host MAC cannot be used as L2 destination across routed hops.\n\n" +
                        "Proceed with resolution attempt?",
                        "Route Unknown — Confirm", MessageBoxButton.YesNo, MessageBoxImage.Question);
                    if (proceed != MessageBoxResult.Yes) return;
                }

                if (!CheckSubnetAndGatewayRequirement(targetIp, true))
                {

                    if (string.IsNullOrWhiteSpace(_networkStorm.GatewayIp))
                    {
                        _attackLogger.LogError(
                            $"Routed target {targetIp} — gateway IP not configured. " +
                            "Cannot resolve remote host MAC across routed hops; next-hop gateway MAC is required.");
                        MessageBox.Show(
                            $"Cannot resolve MAC for routed target {targetIp}.\n\n" +
                            "The remote host MAC is NOT reachable at Layer 2 across routed hops.\n" +
                            "A Gateway IP must be configured so the next-hop MAC can be resolved.\n\n" +
                            "Please set Gateway IP in Network Configuration, then retry.",
                            "Gateway Required for Routed Target",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
                        if (fallbackCB != null && fallbackCB.IsChecked != true)
                        {
                            fallbackCB.IsChecked = true;
                            _attackLogger.LogInfo(
                                "⚠ Fallback mode enabled — enter next-hop gateway MAC manually");
                        }
                        return;
                    }

                    _attackLogger.LogInfo(
                        $"🔍 Resolving next-hop gateway MAC for {_networkStorm.GatewayIp} " +
                        $"(routed target {targetIp} — remote host MAC unreachable at L2)...");

                    var gatewayMac = await _mainController.GetMacAddressAsync(_networkStorm.GatewayIp);
                    if (gatewayMac.Length > 0)
                    {
                        var mac = BitConverter.ToString(gatewayMac).Replace("-", ":");
                        targetMacTB.Text       = mac;
                        targetMacTB.Background  = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                        targetMacTB.Foreground  = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                        targetMacTB.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                        _attackLogger.LogMacResolution(targetIp, mac, true);
                        _attackLogger.LogSuccess(
                            $"✓ Next-hop gateway MAC resolved: {mac}  (gateway: {_networkStorm.GatewayIp})");

                        if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem si &&
                            si.Content?.ToString() == "ARP Spoofing")
                        {
                            var other = isBasic ? AdvTargetMacTextBox : TargetMacTextBox;
                            other.Text = mac;
                            other.Background  = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                            other.Foreground  = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                            other.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                        }
                    }
                    else
                    {
                        _attackLogger.LogError(
                            $"Failed to resolve gateway MAC for {_networkStorm.GatewayIp}. " +
                            "Cannot resolve remote host MAC across routed hops — enter next-hop gateway MAC manually.");
                        targetMacTB.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                        targetMacTB.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                        targetMacTB.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                        if (fallbackCB != null && fallbackCB.IsChecked != true)
                        {
                            fallbackCB.IsChecked = true;
                            _attackLogger.LogInfo(
                                "⚠ Fallback mode enabled — enter next-hop gateway MAC manually");
                        }
                    }
                }
                else
                {

                    _attackLogger.LogInfo(
                        $"🔍 Resolving destination host MAC for {targetIp} (on-link target)...");

                    var pingResult = await _mainController.PingHostAsync(targetIp);
                    if (!pingResult.Success)
                        _attackLogger.LogWarning(
                            $"Ping to {targetIp} did not respond — ARP may still succeed if host is on-link");

                    var macBytes = await _mainController.GetMacAddressAsync(targetIp);
                    if (macBytes.Length > 0)
                    {
                        var mac = BitConverter.ToString(macBytes).Replace("-", ":");
                        targetMacTB.Text       = mac;
                        targetMacTB.Background  = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                        targetMacTB.Foreground  = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                        targetMacTB.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                        _attackLogger.LogMacResolution(targetIp, mac, false);
                        _attackLogger.LogSuccess($"✓ Destination host MAC resolved: {mac}");

                        if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem si &&
                            si.Content?.ToString() == "ARP Spoofing")
                        {
                            var other = isBasic ? AdvTargetMacTextBox : TargetMacTextBox;
                            other.Text = mac;
                            other.Background  = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                            other.Foreground  = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                            other.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                        }
                    }
                    else
                    {
                        _attackLogger.LogWarning(
                            $"Could not resolve destination host MAC for {targetIp} — " +
                            "host may block ARP, may not be on-link, or may be offline.");
                        targetMacTB.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                        targetMacTB.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                        targetMacTB.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                        if (fallbackCB != null && fallbackCB.IsChecked != true)
                        {
                            fallbackCB.IsChecked = true;
                            _attackLogger.LogInfo(
                                "⚠ Fallback mode enabled — enter destination host MAC manually");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error resolving MAC: {ex.Message}");
                var targetMacTB = (sender == ResolveMacButton) ? TargetMacTextBox : AdvTargetMacTextBox;
                var fallbackCB  = (sender == ResolveMacButton) ? MacFallbackCheckBox : AdvMacFallbackCheckBox;
                targetMacTB.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                targetMacTB.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                targetMacTB.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                if (fallbackCB != null && fallbackCB.IsChecked != true)
                {
                    fallbackCB.IsChecked = true;
                    _attackLogger.LogInfo("Fallback mode enabled — enter MAC address manually");
                }
            }
            finally
            {
                if (button != null) button.Content = "Resolve";
            }
        }

        private enum DestType { Unicast, Multicast, Broadcast }

        private DestType GetSelectedDestType()
        {
            if (BroadcastRadio?.IsChecked == true) return DestType.Broadcast;
            if (MulticastRadio?.IsChecked == true) return DestType.Multicast;
            return DestType.Unicast;
        }

        private void DestType_Changed(object sender, RoutedEventArgs e)
        {
            if (TargetIpTextBox == null || DestTypeHintText == null) return;

            var destType = GetSelectedDestType();
            string protocol = (AttackTypeComboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? string.Empty;

            if (destType == DestType.Broadcast)
            {
                string sourceIp = SourceIpTextBox?.Text?.Trim() ?? string.Empty;
                if (IPAddress.TryParse(sourceIp, out var srcIp) && srcIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var bytes = srcIp.GetAddressBytes();
                    bytes[3] = 255;
                    TargetIpTextBox.Text = new IPAddress(bytes).ToString();
                }
                else
                {
                    TargetIpTextBox.Text = "255.255.255.255";
                }
                if (TargetMacTextBox != null)
                    TargetMacTextBox.Text = "FF:FF:FF:FF:FF:FF";
                if (ResolveMacButton != null)
                    ResolveMacButton.IsEnabled = false;

                DestTypeHintText.Text = "Broadcast: packets sent to all hosts on the subnet. Dest MAC auto-set to FF:FF:FF:FF:FF:FF.";
            }
            else if (destType == DestType.Multicast)
            {
                TargetIpTextBox.Text = "224.0.0.1";
                if (TargetMacTextBox != null)
                    TargetMacTextBox.Text = ComputeMulticastMacString("224.0.0.1");
                if (ResolveMacButton != null)
                    ResolveMacButton.IsEnabled = false;

                DestTypeHintText.Text = "Multicast: packets sent to a multicast group (224.0.0.0/4). Dest MAC auto-derived as 01:00:5E + lower 23 bits of IP.";
            }
            else
            {
                string t = TargetIpTextBox.Text ?? string.Empty;
                if (t.StartsWith("224.") || t.StartsWith("239.") || t.EndsWith(".255") || t == "255.255.255.255")
                {
                    TargetIpTextBox.Text = string.Empty;
                }
                if (TargetMacTextBox != null && !string.IsNullOrEmpty(TargetMacTextBox.Text)
                    && (TargetMacTextBox.Text.StartsWith("FF:FF:FF") || TargetMacTextBox.Text.StartsWith("01:00:5E")))
                {
                    TargetMacTextBox.Text = string.Empty;
                    TargetMacTextBox.ClearValue(TextBox.BackgroundProperty);
                    TargetMacTextBox.ClearValue(TextBox.ForegroundProperty);
                    TargetMacTextBox.ClearValue(TextBox.BorderBrushProperty);
                }
                if (ResolveMacButton != null)
                    ResolveMacButton.IsEnabled = true;
                DestTypeHintText.Text = string.Empty;
            }

            if (protocol == "TCP SYN Flood" && destType != DestType.Unicast)
            {
                DestTypeHintText.Text += " Note: TCP SYN to broadcast/multicast is uncommon and may be dropped.";
            }
        }

        private static string ComputeMulticastMacString(string multicastIp)
        {
            if (!IPAddress.TryParse(multicastIp, out var ip)) return string.Empty;
            var b = ip.GetAddressBytes();
            return $"01:00:5E:{(b[1] & 0x7F):X2}:{b[2]:X2}:{b[3]:X2}";
        }

        private byte[]? ComputeDestinationMacOverride(string targetIp)
        {
            var destType = GetSelectedDestType();
            if (destType == DestType.Broadcast)
                return new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            if (destType == DestType.Multicast && IPAddress.TryParse(targetIp, out var ip))
            {
                var b = ip.GetAddressBytes();
                return new byte[] { 0x01, 0x00, 0x5E, (byte)(b[1] & 0x7F), b[2], b[3] };
            }
            return null;
        }

        private bool ValidateDestinationType(string targetIp)
        {
            var destType = GetSelectedDestType();
            if (destType == DestType.Unicast) return true;

            if (!IPAddress.TryParse(targetIp, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                MessageBox.Show("Invalid target IP address.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (destType == DestType.Multicast)
            {
                byte first = ip.GetAddressBytes()[0];
                if (first < 224 || first > 239)
                {
                    MessageBox.Show("Multicast requires an IP in range 224.0.0.0 - 239.255.255.255.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            else
            {
                if (!targetIp.EndsWith(".255") && targetIp != "255.255.255.255")
                {
                    MessageBox.Show("Broadcast requires a broadcast address (e.g. 192.168.1.255 or 255.255.255.255).", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return false;
                }
            }
            return true;
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {

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

                var selectedInterface = NetworkInterfaceComboBox.SelectedItem as dynamic;
                if (selectedInterface?.Interface is NetworkInterface nic)
                {
                    var ipProps = nic.GetIPProperties();
                    var unicastInfo = ipProps.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (unicastInfo != null)
                    {

                        var maskBytes = unicastInfo.IPv4Mask.GetAddressBytes();
                        Array.Reverse(maskBytes);
                        var mask = BitConverter.ToUInt32(maskBytes, 0);

                        var sourceBytes = sourceIpAddress.GetAddressBytes();
                        var targetBytes = targetIpAddress.GetAddressBytes();
                        Array.Reverse(sourceBytes);
                        Array.Reverse(targetBytes);
                        var sourceInt = BitConverter.ToUInt32(sourceBytes, 0);
                        var targetInt = BitConverter.ToUInt32(targetBytes, 0);

                        var sameSubnet = (sourceInt & mask) == (targetInt & mask);

                        if (!sameSubnet)
                        {

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
                long bytesPerSecond;

                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    sourceIp = AdvSourceIpTextBox.Text.Trim();
                    if (!int.TryParse(AdvTargetPortTextBox.Text, out targetPort))
                    {
                        MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    if (!TryParseRateInput(AdvMegabitsPerSecondTextBox, _advCurrentRateUnit, out bytesPerSecond))
                        return;
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
                    if (!TryParseRateInput(MegabitsPerSecondTextBox, _currentRateUnit, out bytesPerSecond))
                        return;
                }

                bool isBasicTab = MainTabControl.SelectedItem != AdvancedTab;
                if (isBasicTab && !ValidateDestinationType(targetIp))
                    return;

                byte[]? destMacOverride = isBasicTab ? ComputeDestinationMacOverride(targetIp) : null;

                if (destMacOverride == null && !ValidateCrossSubnetGateway(targetIp, sourceIp))
                    return;

                var selectedAttackType = attackType switch
                {
                    "UDP Flood"    => AttackType.UdpFlood,
                    "TCP SYN Flood"=> AttackType.TcpSynFlood,
                    "ICMP Flood"   => AttackType.IcmpFlood,
                    _ => throw new ArgumentException($"Unsupported flood attack type: {attackType}")
                };

                _totalPacketsSent      = 0;
                _attackStartTime       = DateTime.Now;
                _targetWireBytesPerSec = bytesPerSecond;

                bool isTcpAttack = selectedAttackType is AttackType.TcpSynFlood
                                                      or AttackType.TcpRoutedFlood;
                _runStartTime  = isTcpAttack ? default : DateTime.Now;
                _protocolCaps  = isTcpAttack
                    ? Dorothy.Services.FloodProtocolCapabilities.TcpWithCalibration
                    : Dorothy.Services.FloodProtocolCapabilities.FullScheduler;

                TargetRateText.Text = Dorothy.Services.RateConverter.Format(bytesPerSecond);
                _statsTimer?.Start();

                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                var targetMacBytes = destMacOverride
                                     ?? await _mainController.GetMacAddressAsync(targetIp);

                _attackLogger.StartAttack(selectedAttackType, sourceIp, sourceMacBytes, targetIp, targetMacBytes, bytesPerSecond, targetPort);

                _networkStorm.TcpFloodOptions = BuildFloodOptions();
                _networkStorm.DestinationMacOverride = destMacOverride;

                await _mainController.StartAttackAsync(selectedAttackType, targetIp, targetPort, bytesPerSecond);
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
                long bytesPerSecond;

                if (MainTabControl.SelectedItem == AdvancedTab)
                {
                    targetIp = AdvTargetIpTextBox.Text.Trim();
                    sourceIp = AdvSourceIpTextBox.Text.Trim();
                    if (!int.TryParse(AdvTargetPortTextBox.Text, out targetPort))
                    {
                        MessageBox.Show("Invalid target port.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                    if (!TryParseRateInput(AdvMegabitsPerSecondTextBox, _advCurrentRateUnit, out bytesPerSecond))
                        return;
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
                    if (!TryParseRateInput(MegabitsPerSecondTextBox, _currentRateUnit, out bytesPerSecond))
                        return;
                }

                if (!ValidateCrossSubnetGateway(targetIp, sourceIp))
                    return;

                _currentRunningAttackType = "Broadcast";
                _totalPacketsSent         = 0;
                _attackStartTime          = DateTime.Now;
                _runStartTime             = DateTime.Now;
                _targetWireBytesPerSec    = bytesPerSecond;
                _protocolCaps             = Dorothy.Services.FloodProtocolCapabilities.None;
                TargetRateText.Text       = Dorothy.Services.RateConverter.Format(bytesPerSecond);
                _statsTimer?.Start();

                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                var targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                if (targetMacBytes.Length == 0)
                    targetMacBytes = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

                _attackLogger.StartAttack(AttackType.UdpFlood, sourceIp, sourceMacBytes, targetIp, targetMacBytes, bytesPerSecond, targetPort);

                await _mainController.StartBroadcastAttackAsync(targetIp, targetPort, bytesPerSecond);
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

                var attackType = _currentRunningAttackType ??
                    (MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                        (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString());

                bool isAdvancedMode = MainTabControl.SelectedItem == AdvancedTab && _isAdvancedMode;

                if (attackType == "Broadcast")
                {
                    await _mainController.StopBroadcastAttackAsync(_totalPacketsSent, isAdvancedMode);
                }
                else if (attackType == "ARP Spoofing")
                {
                    await _mainController.StopArpSpoofingAsync(_totalPacketsSent, isAdvancedMode);
                }
                else if (attackType != null && attackType.StartsWith("Ethernet"))
                {

                    await _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
                }
                else
                {
                    await _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
                }

                _currentRunningAttackType = null;
                ResetStatistics();

                _ = Task.Run(async () =>
                {
                    await Task.Delay(500);
                    await UpdateSyncStatus();

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

                        long speedBps = n.Speed;
                        string bandwidthDisplay;
                        double maxMbps;

                        if (speedBps >= 1_000_000_000)
                        {
                            double gbps = speedBps / 1_000_000_000.0;
                            bandwidthDisplay = $"{gbps:F1} Gbps";
                            maxMbps = gbps * 1000;
                        }
                        else if (speedBps >= 1_000_000)
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
                            maxMbps = 1000;
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

                var comboBox = MainTabControl.SelectedItem == AdvancedTab
                    ? AdvNetworkInterfaceComboBox
                    : NetworkInterfaceComboBox;

                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;

                    string tooltipText = $"Enter Mbps value (0 - {maxMbps:F0})";
                    MegabitsPerSecondTextBox.ToolTip = tooltipText;
                    AdvMegabitsPerSecondTextBox.ToolTip = tooltipText;
                }
            }
            catch
            {

            }
        }

        private void RateUnitComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _currentRateUnit = GetSelectedRateUnit(RateUnitComboBox);
        }

        private void AdvRateUnitComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _advCurrentRateUnit = GetSelectedRateUnit(AdvRateUnitComboBox);
        }

        private static Dorothy.Services.RateUnit GetSelectedRateUnit(ComboBox box)
        {
            return (box?.SelectedItem as ComboBoxItem)?.Content?.ToString() switch
            {
                "Bps"  => Dorothy.Services.RateUnit.Bps,
                "Kbps" => Dorothy.Services.RateUnit.Kbps,
                "Gbps" => Dorothy.Services.RateUnit.Gbps,
                _      => Dorothy.Services.RateUnit.Mbps
            };
        }

        private bool TryParseRateInput(
            TextBox rateBox,
            Dorothy.Services.RateUnit unit,
            out long bytesPerSecond)
        {
            bytesPerSecond = 0;

            if (!double.TryParse(
                    rateBox.Text,
                    System.Globalization.NumberStyles.Any,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out double rateValue) || rateValue <= 0)
            {
                MessageBox.Show(
                    $"Please enter a valid positive rate value (e.g. 100 for 100 {unit}).",
                    "Invalid Rate",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return false;
            }

            bytesPerSecond = Dorothy.Services.RateConverter.ToWireBytesPerSec(rateValue, unit);

            if (bytesPerSecond <= 0)
            {
                MessageBox.Show(
                    "The rate value is too small. Enter a positive value in the selected unit.",
                    "Invalid Rate",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return false;
            }

            return true;
        }

        private string _tcpSynMode = "Basic";

        private void TcpSynModeCard_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (sender is FrameworkElement fe && fe.Tag is string tag)
            {
                _tcpSynMode = tag;
                UpdateTcpSynModeSelection();
            }
        }

        private void UpdateTcpSynModeSelection()
        {
            if (BasicModeCard == null || EvasionModeCard == null) return;
            var accent = (SolidColorBrush)FindResource("AccentBlue");
            var selectedBg = new SolidColorBrush(Color.FromRgb(0x2E, 0x3F, 0x5C));
            Border selected = _tcpSynMode == "Evasion" ? EvasionModeCard : BasicModeCard;
            Border unselected = _tcpSynMode == "Evasion" ? BasicModeCard : EvasionModeCard;
            selected.BorderBrush = accent;
            selected.BorderThickness = new Thickness(2);
            selected.Background = selectedBg;
            unselected.ClearValue(Border.BorderBrushProperty);
            unselected.ClearValue(Border.BorderThicknessProperty);
            unselected.ClearValue(Border.BackgroundProperty);

            if (TcpSynModeDescText != null)
            {
                TcpSynModeDescText.Text = _tcpSynMode == "Evasion"
                    ? "Per-packet randomised IP ID / TTL / window / MSS / timestamps plus software checksums. Slower but defeats default firewall heuristics."
                    : "Standard TCP SYN packets. Best for raw throughput tests against session tables.";
            }
        }

        private void FirewallBypassModeCheckBox_Changed(object sender, RoutedEventArgs e)      {  }
        private void ForceSoftwareChecksumCheckBox_Changed(object sender, RoutedEventArgs e)   {  }
        private void UseRealSourceIpCheckBox_Changed(object sender, RoutedEventArgs e)         {  }
        private void RandomizeWithinSubnetCheckBox_Changed(object sender, RoutedEventArgs e)   {  }

        private Dorothy.Services.FloodOptions BuildFloodOptions()
        {
            bool evasion = _tcpSynMode == "Evasion";
            return new Dorothy.Services.FloodOptions
            {
                FirewallBypassMode    = evasion || FirewallBypassModeCheckBox?.IsChecked == true,
                ForceSoftwareChecksum = evasion || ForceSoftwareChecksumCheckBox?.IsChecked == true,
                UseRealSourceIp       = UseRealSourceIpCheckBox?.IsChecked == true,
                RandomizeWithinSubnet = RandomizeWithinSubnetCheckBox?.IsChecked == true
            };
        }

        private void MegabitsPerSecondTextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                e.Handled = true;
                return;
            }

            if (!char.IsDigit(e.Text, 0) && e.Text != ".")
            {
                e.Handled = true;
                return;
            }

            if (e.Text == "." && textBox.Text.Contains("."))
            {
                e.Handled = true;
                return;
            }

            string currentText = textBox.Text ?? "";
            int selectionStart = textBox.SelectionStart;
            int selectionLength = textBox.SelectionLength;

            string newText = currentText.Substring(0, selectionStart) +
                            e.Text +
                            currentText.Substring(selectionStart + selectionLength);

            if (string.IsNullOrWhiteSpace(newText) || newText == ".")
            {
                return;
            }

            if (double.TryParse(newText, out double value))
            {

                var comboBox = NetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;

                    if (value < 0)
                    {
                        e.Handled = true;
                        return;
                    }

                    if (value > maxMbps * 1.1)
                    {
                        e.Handled = true;
                        return;
                    }
                }
            }
            else
            {

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

            if (!char.IsDigit(e.Text, 0) && e.Text != ".")
            {
                e.Handled = true;
                return;
            }

            if (e.Text == "." && textBox.Text.Contains("."))
            {
                e.Handled = true;
                return;
            }

            string currentText = textBox.Text ?? "";
            int selectionStart = textBox.SelectionStart;
            int selectionLength = textBox.SelectionLength;

            string newText = currentText.Substring(0, selectionStart) +
                            e.Text +
                            currentText.Substring(selectionStart + selectionLength);

            if (string.IsNullOrWhiteSpace(newText) || newText == ".")
            {
                return;
            }

            if (double.TryParse(newText, out double value))
            {

                var comboBox = AdvNetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;

                    if (value < 0)
                    {
                        e.Handled = true;
                        return;
                    }

                    if (value > maxMbps * 1.1)
                    {
                        e.Handled = true;
                        return;
                    }
                }
            }
            else
            {

                e.Handled = true;
            }
        }

        private void MegabitsPerSecondTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null) return;

            if (string.IsNullOrWhiteSpace(textBox.Text)) return;

            if (double.TryParse(textBox.Text, out double value))
            {

                var comboBox = NetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;

                    if (value > maxMbps * 1.01)
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

            if (string.IsNullOrWhiteSpace(textBox.Text)) return;

            if (double.TryParse(textBox.Text, out double value))
            {

                var comboBox = AdvNetworkInterfaceComboBox;
                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;
                    double maxMbps = selectedInterface.MaxMbps ?? 1000;

                    if (value > maxMbps * 1.01)
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

            if (_isSyncingComboBoxes)
            {
                return;
            }

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

                    byte[] subnetMask = new byte[] { 255, 255, 255, 0 };
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

                    SourceIpTextBox.Text = ipAddress;
                    SourceMacTextBox.Text = macAddress;
                    AdvSourceIpTextBox.Text = ipAddress;
                    AdvSourceMacTextBox.Text = macAddress;

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

                    IPAddress? gatewayIp = null;
                    if (selectedNic != null)
                    {
                        gatewayIp = _mainController.GetGatewayForInterface(selectedNic);
                    }

                    if (gatewayIp == null)
                    {
                        gatewayIp = _mainController.CalculateDefaultGateway(ipAddress);
                    }

                    UpdateMbpsValidation();

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

                        _attackLogger.LogWarning($"No gateway found for NIC: {nicDescription}");
                    }

                    CheckSubnetAndUpdateGatewayField();
                    UpdateProfileSummary();
                    UpdateMacRouteHint();
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error selecting network interface: {ex}");
            }
            finally
            {

                _isSyncingComboBoxes = false;
            }
        }

        private void AdvancedTab_PreviewMouseDown(object sender, MouseButtonEventArgs e)
        {

        }

        private bool ValidatePassword(string inputPassword)
        {

            if (string.IsNullOrEmpty(inputPassword))
                return false;

            string trimmedInput = inputPassword.Trim();
            string correctPassword = "KyeRRkfccbGBCNCKYPha1lrYS2PO8koL";

            return SecureCompare(trimmedInput, correctPassword);
        }

        private string GetMachineIdentifier()
        {

            string machineName = Environment.MachineName;
            string userName = Environment.UserName;
            string osVersion = Environment.OSVersion.ToString();

            string machineId = $"{machineName}_{userName}_{osVersion}";

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(machineId));
                return Convert.ToBase64String(hashBytes).Substring(0, 32);
            }
        }

        private string GenerateValidationToken()
        {

            string machineId = GetMachineIdentifier();
            string baseSecret = "SeAcUrE_VaLiDaTiOn_SeCrEt_2024";

            string tokenData = $"{machineId}_{baseSecret}";

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

                string machineId = GetMachineIdentifier();
                byte[] tokenBytes = Encoding.UTF8.GetBytes(_validationToken);
                byte[] keyBytes = Encoding.UTF8.GetBytes(machineId.Substring(0, 32));

                for (int i = 0; i < tokenBytes.Length; i++)
                {
                    tokenBytes[i] = (byte)(tokenBytes[i] ^ keyBytes[i % keyBytes.Length]);
                }

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

                string encryptedToken = File.ReadAllText(VALIDATION_TOKEN_FILE);
                byte[] tokenBytes = Convert.FromBase64String(encryptedToken);

                string machineId = GetMachineIdentifier();
                byte[] keyBytes = Encoding.UTF8.GetBytes(machineId.Substring(0, 32));

                for (int i = 0; i < tokenBytes.Length; i++)
                {
                    tokenBytes[i] = (byte)(tokenBytes[i] ^ keyBytes[i % keyBytes.Length]);
                }

                _validationToken = Encoding.UTF8.GetString(tokenBytes);

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

            string expectedToken = GenerateValidationToken();

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

            _disclaimerAcknowledged = false;

            var disclaimerDialog = new DisclaimerDialog
            {
                Owner = this
            };

            bool? dialogResult = disclaimerDialog.ShowDialog();
            if (dialogResult == true && disclaimerDialog.IsAuthorized)
            {
                _disclaimerAcknowledged = true;

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

                    string content = File.ReadAllText(DISCLAIMER_ACK_FILE);

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

                LabModeBadge.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                LabModeBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                LabModeText.Text = "ATTACK MODE";
                LabModeText.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
            }
            else
            {

                LabModeBadge.Background = new SolidColorBrush(Color.FromRgb(0x1e, 0x3a, 0x5f));
                LabModeBadge.BorderBrush = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xeb));
                LabModeText.Text = "LAB MODE";
                LabModeText.Foreground = new SolidColorBrush(Color.FromRgb(0x60, 0xa5, 0xfa));
            }
        }

        private void GatewayIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(GatewayIpTextBox.Text))
                {
                    GatewayIpTextBox.ClearValue(TextBox.BackgroundProperty);
                    GatewayIpTextBox.ClearValue(TextBox.ForegroundProperty);
                    GatewayIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                    return;
                }

                if (IPAddress.TryParse(GatewayIpTextBox.Text, out _))
                {
                    GatewayIpTextBox.ClearValue(TextBox.BackgroundProperty);
                    GatewayIpTextBox.ClearValue(TextBox.ForegroundProperty);
                    GatewayIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                    _networkStorm.SetGatewayIp(GatewayIpTextBox.Text);
                }
                else
                {
                    GatewayIpTextBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                    GatewayIpTextBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                    GatewayIpTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                }
                UpdateMacRouteHint();
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
                    SourceIpTextBox.ClearValue(TextBox.BackgroundProperty);
                    SourceIpTextBox.ClearValue(TextBox.ForegroundProperty);
                    SourceIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                    return;
                }

                if (IPAddress.TryParse(SourceIpTextBox.Text, out _))
                {
                    SourceIpTextBox.ClearValue(TextBox.BackgroundProperty);
                    SourceIpTextBox.ClearValue(TextBox.ForegroundProperty);
                    SourceIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                }
                else
                {
                    SourceIpTextBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                    SourceIpTextBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                    SourceIpTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                }

                CheckSubnetAndUpdateGatewayField();
                UpdateMacRouteHint();
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
                    TargetIpTextBox.ClearValue(TextBox.BackgroundProperty);
                    TargetIpTextBox.ClearValue(TextBox.ForegroundProperty);
                    TargetIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                    UpdateMacRouteHint(null);
                    UpdateProfileSummary();
                    return;
                }

                if (IPAddress.TryParse(TargetIpTextBox.Text, out _))
                {
                    TargetIpTextBox.ClearValue(TextBox.BackgroundProperty);
                    TargetIpTextBox.ClearValue(TextBox.ForegroundProperty);
                    TargetIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                }
                else
                {
                    TargetIpTextBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                    TargetIpTextBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                    TargetIpTextBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                }
                UpdateMacRouteHint(TargetIpTextBox.Text);
                UpdateProfileSummary();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in TargetIpTextBox_TextChanged");
            }
        }

        private void UpdateMacRouteHint(string? overrideBasicTargetIp = null)
        {

            ApplyMacRouteHint(
                overrideBasicTargetIp ?? TargetIpTextBox?.Text,
                SourceIpTextBox?.Text,
                MacRouteHintText);

            ApplyMacRouteHint(
                AdvTargetIpTextBox?.Text,
                AdvSourceIpTextBox?.Text,
                AdvMacRouteHintText);
        }

        private void ApplyMacRouteHint(string? targetIpText, string? sourceIpText, TextBlock? hint)
        {
            try
            {
                if (hint == null) return;

                if (string.IsNullOrWhiteSpace(targetIpText) ||
                    !IPAddress.TryParse(targetIpText, out var targetIp))
                {
                    hint.Visibility = Visibility.Collapsed;
                    return;
                }
                if (!IPAddress.TryParse(sourceIpText, out var sourceIp))
                {
                    hint.Visibility = Visibility.Collapsed;
                    return;
                }

                var route = TargetExpansionService.DetermineRoute(sourceIp, targetIp);

                (hint.Text, hint.Foreground) = route switch
                {
                    RouteType.OnLink =>
                        ("On-link target — Dest./Next-hop MAC refers to the destination host MAC address.",
                         new SolidColorBrush(Color.FromRgb(5, 150, 105))),

                    RouteType.ViaGateway =>
                        ("⚠ Routed target — Dest./Next-hop MAC must be the next-hop gateway MAC. " +
                         "The remote host MAC is not visible across routed hops and cannot be used as L2 destination.",
                         new SolidColorBrush(Color.FromRgb(217, 119, 6))),

                    RouteType.NoRoute =>
                        ("⛔ No route detected to this target from the selected source IP. " +
                         "Raw packet send will likely fail — check NIC selection and routing.",
                         new SolidColorBrush(Color.FromRgb(185, 28, 28))),

                    _ =>
                        ("Route unknown — if target is on a different subnet, use the next-hop gateway MAC.",
                         new SolidColorBrush(Color.FromRgb(107, 114, 128)))
                };
                hint.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error in ApplyMacRouteHint");
                if (hint != null) hint.Visibility = Visibility.Collapsed;
            }
        }

        private void TargetMacTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                var textBox = sender as TextBox;
                if (string.IsNullOrWhiteSpace(textBox.Text))
                {
                    textBox.ClearValue(TextBox.BackgroundProperty);
                    textBox.ClearValue(TextBox.ForegroundProperty);
                    textBox.ClearValue(TextBox.BorderBrushProperty);
                    return;
                }

                var macRegex = new Regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
                if (macRegex.IsMatch(textBox.Text))
                {
                    textBox.ClearValue(TextBox.BackgroundProperty);
                    textBox.ClearValue(TextBox.ForegroundProperty);
                    textBox.ClearValue(TextBox.BorderBrushProperty);

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
                    textBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                    textBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                    textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
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
            UpdateAttackTypeDescription();
            UpdateProtocolCardSelection();
        }

        private void UpdateAttackTypeDescription()
        {
            if (AttackTypeDescText == null) return;
            var item = AttackTypeComboBox?.SelectedItem as ComboBoxItem;
            string protocol = item?.Content?.ToString() ?? string.Empty;
            AttackTypeDescText.Text = protocol switch
            {
                "UDP Flood"
                    => "Randomised UDP datagrams at wire rate. Effective for bandwidth saturation tests.",
                "TCP SYN Flood"
                    => "TCP SYN packets with realistic OS fingerprints (MSS, WScale, SACK). Tests stateful session-table capacity.",
                "ICMP Flood"
                    => "ICMP Echo Request packets. Tests host and path reachability under load. Target port is ignored.",
                string s when s.StartsWith("Ethernet Unicast")
                    => "Layer-2 unicast frames injected directly onto the wire. Tests switch and NIC throughput.",
                string s when s.StartsWith("Ethernet Multicast")
                    => "Layer-2 multicast frames. Tests multicast handling in the local segment.",
                string s when s.StartsWith("Ethernet Broadcast")
                    => "Layer-2 broadcast frames. Tests broadcast domain saturation.",
                _ => string.Empty
            };
            UpdateDestinationTypeVisibility(protocol);
        }

        private void UpdateDestinationTypeVisibility(string protocol)
        {
            if (DestinationTypePanel == null) return;
            bool show = protocol is "UDP Flood" or "TCP SYN Flood" or "ICMP Flood";
            DestinationTypePanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            if (show)
            {

                if (UnicastRadio != null && UnicastRadio.IsChecked != true)
                    UnicastRadio.IsChecked = true;
                else
                    DestType_Changed(UnicastRadio!, new RoutedEventArgs());
            }
        }

        private void AdvTargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                if (sender is TextBox textBox)
                {
                    if (string.IsNullOrWhiteSpace(textBox.Text))
                    {
                        textBox.ClearValue(TextBox.BackgroundProperty);
                        textBox.ClearValue(TextBox.ForegroundProperty);
                        textBox.ClearValue(TextBox.BorderBrushProperty);
                        UpdateProfileSummary();
                        return;
                    }

                    if (IPAddress.TryParse(textBox.Text, out _))
                    {
                        textBox.ClearValue(TextBox.BackgroundProperty);
                        textBox.ClearValue(TextBox.ForegroundProperty);
                        textBox.ClearValue(TextBox.BorderBrushProperty);
                    }
                    else
                    {
                        textBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                        textBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                        textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
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
                            SpoofedMacTextBox.IsEnabled = true;

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

                            if (string.IsNullOrWhiteSpace(AdvTargetPortTextBox.Text) || AdvTargetPortTextBox.Text == "0")
                            {
                                AdvTargetPortTextBox.Text = "10110";
                            }

                            break;
                        case "NMEA 0183 (UDP Multicast)":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;

                            if (string.IsNullOrWhiteSpace(AdvTargetPortTextBox.Text) || AdvTargetPortTextBox.Text == "0")
                            {
                                AdvTargetPortTextBox.Text = "10110";
                            }
                            if (string.IsNullOrWhiteSpace(AdvTargetIpTextBox.Text))
                            {
                                AdvTargetIpTextBox.Text = "239.192.0.1";
                            }
                            break;
                        case "Modbus/TCP Flood (Read Requests)":
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;

                            if (string.IsNullOrWhiteSpace(AdvTargetPortTextBox.Text) || AdvTargetPortTextBox.Text == "0")
                            {
                                AdvTargetPortTextBox.Text = "502";
                            }
                            break;
                        default:
                            AdvTargetPortTextBox.IsEnabled = true;
                            AdvMegabitsPerSecondTextBox.IsEnabled = true;
                            AdvTargetMacTextBox.IsEnabled = false;
                            SpoofedMacTextBox.IsEnabled = false;
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
                        textBox.ClearValue(TextBox.BackgroundProperty);
                        textBox.ClearValue(TextBox.ForegroundProperty);
                        textBox.ClearValue(TextBox.BorderBrushProperty);
                        return;
                    }

                    string cleanText = new string(textBox.Text.Where(c =>
                        (c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F') ||
                        c == ':').ToArray()).ToUpper();

                    if (cleanText.Contains(':'))
                    {
                        var parts = cleanText.Split(':');
                        cleanText = string.Join("", parts);
                    }

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

                    if (result != originalText)
                    {
                        textBox.Text = result;

                        int hexDigitsBeforeCaret = originalText.Take(currentCaretIndex)
                            .Count(c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'));

                        int colonCount = hexDigitsBeforeCaret / 2;
                        if (hexDigitsBeforeCaret > 0 && hexDigitsBeforeCaret % 2 == 0 && hexDigitsBeforeCaret < 12)
                        {
                            colonCount--;
                        }

                        int newPosition = hexDigitsBeforeCaret + colonCount;
                        if (newPosition > result.Length)
                        {
                            newPosition = result.Length;
                        }

                        textBox.CaretIndex = newPosition;
                    }

                    var isComplete = new Regex("^([0-9A-F]{2}:){5}[0-9A-F]{2}$").IsMatch(result);
                    var isPartial = new Regex("^([0-9A-F]{2}:)*[0-9A-F]{0,2}$").IsMatch(result);

                    if (isComplete)
                    {
                        textBox.Background = new SolidColorBrush(Color.FromRgb(0x1A, 0x3A, 0x2A));
                        textBox.Foreground = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                        textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x2A, 0x5A, 0x3A));
                    }
                    else if (isPartial)
                    {
                        textBox.ClearValue(TextBox.BackgroundProperty);
                        textBox.ClearValue(TextBox.ForegroundProperty);
                        textBox.ClearValue(TextBox.BorderBrushProperty);
                    }
                    else
                    {
                        textBox.Background = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                        textBox.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                        textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
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

                if (!TryParseRateInput(AdvMegabitsPerSecondTextBox, _advCurrentRateUnit, out long bytesPerSecond))
                    return;

                bool isMulticast = attackType == "NMEA 0183 (UDP Multicast)";
                string actualMulticastGroupIp = targetIp;
                string destinationIpForLogging = targetIp;

                if (isMulticast)
                {
                    var ipBytes = parsedTargetIp.GetAddressBytes();
                    bool isUnicastIp = ipBytes.Length < 1 || ipBytes[0] < 224 || ipBytes[0] > 239;

                    if (isUnicastIp)
                    {

                        actualMulticastGroupIp = "239.192.0.1";
                        destinationIpForLogging = targetIp;
                        _attackLogger.LogInfo($"Using unicast IP {targetIp} as interface/config; targeting multicast group {actualMulticastGroupIp}");
                    }
                    else
                    {

                        actualMulticastGroupIp = targetIp;
                        destinationIpForLogging = targetIp;
                    }
                }

                _currentRunningAttackType = attackType;
                _totalPacketsSent         = 0;
                _attackStartTime          = DateTime.Now;
                _runStartTime             = DateTime.Now;
                _targetWireBytesPerSec    = bytesPerSecond;

                _protocolCaps             = Dorothy.Services.FloodProtocolCapabilities.None;
                TargetRateText.Text       = Dorothy.Services.RateConverter.Format(bytesPerSecond);
                _statsTimer?.Start();

                StartAdvancedAttackButton.IsEnabled = false;
                StopAdvancedAttackButton.IsEnabled = true;

                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                byte[] targetMacBytes;

                if (isMulticast)
                {

                    var multicastIpBytes = IPAddress.Parse(actualMulticastGroupIp).GetAddressBytes();
                    targetMacBytes = new byte[] { 0x01, 0x00, 0x5E, (byte)(multicastIpBytes[1] & 0x7F), multicastIpBytes[2], multicastIpBytes[3] };
                }
                else
                {

                    targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                    if (targetMacBytes.Length == 0)
                    {

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

                _attackLogger.StartNmea0183Attack(isMulticast, sourceIp, sourceMacBytes,
                    actualMulticastGroupIp, targetMacBytes, bytesPerSecond, targetPort, destinationIpForLogging);

                await _networkStorm.StartNmea0183AttackAsync(actualMulticastGroupIp, targetPort, bytesPerSecond, isMulticast);
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

                if (!TryParseRateInput(AdvMegabitsPerSecondTextBox, _advCurrentRateUnit, out long bytesPerSecond))
                    return;

                _currentRunningAttackType = "Modbus/TCP Flood (Read Requests)";
                _totalPacketsSent         = 0;
                _attackStartTime          = DateTime.Now;
                _runStartTime             = DateTime.Now;
                _targetWireBytesPerSec    = bytesPerSecond;
                _protocolCaps             = Dorothy.Services.FloodProtocolCapabilities.None;
                TargetRateText.Text       = Dorothy.Services.RateConverter.Format(bytesPerSecond);
                _statsTimer?.Start();

                StartAdvancedAttackButton.IsEnabled = false;
                StopAdvancedAttackButton.IsEnabled = true;

                var sourceMacBytes = await _mainController.GetLocalMacAddressAsync();
                byte[] targetMacBytes;

                targetMacBytes = await _mainController.GetMacAddressAsync(targetIp);
                if (targetMacBytes.Length == 0)
                {

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

                _attackLogger.StartModbusTcpAttack(sourceIp, sourceMacBytes, targetIp, targetMacBytes, bytesPerSecond, targetPort);

                await _networkStorm.StartModbusTcpAttackAsync(targetIp, targetPort, bytesPerSecond);
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
                if (!TryParseRateInput(MegabitsPerSecondTextBox, _currentRateUnit, out long bytesPerSecond))
                    return;

                _currentRunningAttackType = attackType;

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

                if (packetType == EthernetFlood.EthernetPacketType.Unicast && !useIPv6 && !ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                    _currentRunningAttackType = null;
                    return;
                }

                _totalPacketsSent      = 0;
                _attackStartTime       = DateTime.Now;
                _runStartTime          = DateTime.Now;
                _targetWireBytesPerSec = bytesPerSecond;

                _protocolCaps          = Dorothy.Services.FloodProtocolCapabilities.FullScheduler;
                TargetRateText.Text    = Dorothy.Services.RateConverter.Format(bytesPerSecond);
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

                _attackLogger.StartEthernetAttack(packetType, sourceIp, sourceMacBytes, targetIp, targetMac, bytesPerSecond, targetPort);

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, bytesPerSecond, packetType, useIPv6, targetMac);
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
                if (!TryParseRateInput(AdvMegabitsPerSecondTextBox, _advCurrentRateUnit, out long bytesPerSecond))
                    return;

                var attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();

                _currentRunningAttackType = attackType ?? $"Ethernet {packetType}";

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
                    packetType, localSourceIp, sourceMacBytes, targetIp, targetMac, bytesPerSecond, targetPort);

                await _networkStorm.StartEthernetAttackAsync(targetIp, targetPort, bytesPerSecond, packetType, false, targetMac);
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

                if (string.IsNullOrEmpty(_validationToken) || !IsValidationTokenValid(_validationToken))
                {
                    MessageBox.Show("Please validate your password first by clicking the 'Validate' button.", "Authentication Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                    AdvPasswordBox?.Focus();
                    return;
                }

                _statsTimer?.Stop();

                var attackType = _currentRunningAttackType ??
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();

                _attackLogger.LogInfo($"Stopping advanced attack. Attack type: '{attackType}', Current running type: '{_currentRunningAttackType}'");

                bool isAdvancedMode = MainTabControl.SelectedItem == AdvancedTab && _isAdvancedMode;

                if (attackType == "ARP Spoofing")
                {
                    await _mainController.StopArpSpoofingAsync(_totalPacketsSent, isAdvancedMode);
                }
                else if (attackType != null && (attackType.StartsWith("Ethernet") || attackType.StartsWith("NMEA 0183") || attackType.Contains("NMEA")))
                {

                    _attackLogger.LogInfo($"Stopping attack type: {attackType}");
                    await _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
                }
                else if (attackType != null)
                {

                    _attackLogger.LogInfo($"Stopping attack (fallback) for type: {attackType}");
                    await _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
                }
                else
                {

                    _attackLogger.LogInfo("Stopping attack (attack type was null, using fallback)");
                    await _mainController.StopAttackAsync(_totalPacketsSent, isAdvancedMode);
                }

                _currentRunningAttackType = null;
                ResetStatistics();
                ResetStatistics();

                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Error stopping advanced attack: {ex}");

                StartAdvancedAttackButton.IsEnabled = true;
                StopAdvancedAttackButton.IsEnabled = false;
            }
        }

        private async Task StartArpSpoofingAttack()
        {
            try
            {
                string sourceIp, sourceMac, targetIp, targetMac, spoofedMac;

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

                if (!ValidateCrossSubnetGateway(targetIp, sourceIp))
                {
                return;
            }

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

                _currentRunningAttackType = "ARP Spoofing";

                _totalPacketsSent      = 0;
                _attackStartTime       = DateTime.Now;
                _runStartTime          = DateTime.Now;
                _targetWireBytesPerSec = 0;
                _protocolCaps          = Dorothy.Services.FloodProtocolCapabilities.None;
                _statsTimer?.Start();

                byte[] sourceMacBytes = sourceMac.Split(':').Select(b => Convert.ToByte(b, 16)).ToArray();
                byte[] targetMacBytes = targetMac.Split(':').Select(b => Convert.ToByte(b, 16)).ToArray();

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

                var selectedInterface = NetworkInterfaceComboBox.SelectedItem as dynamic;
                if (selectedInterface?.Interface is NetworkInterface nic)
                {
                    var ipProps = nic.GetIPProperties();
                    var unicastInfo = ipProps.UnicastAddresses
                        .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (unicastInfo != null)
                    {

                        var maskBytes = unicastInfo.IPv4Mask.GetAddressBytes();
                        Array.Reverse(maskBytes);
                        var mask = BitConverter.ToUInt32(maskBytes, 0);

                        var sourceBytes = sourceIpAddress.GetAddressBytes();
                        var targetBytes = targetIpAddress.GetAddressBytes();
                        Array.Reverse(sourceBytes);
                        Array.Reverse(targetBytes);
                        var sourceInt = BitConverter.ToUInt32(sourceBytes, 0);
                        var targetInt = BitConverter.ToUInt32(targetBytes, 0);

                        var sameSubnet = (sourceInt & mask) == (targetInt & mask);
                        var currentMessage = sameSubnet ?
                            "Source and target are on the same subnet. Gateway not required." :
                            "Source and target are on different subnets. Gateway required.";

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
                            GatewayIpTextBox.ClearValue(TextBox.BackgroundProperty);
                            GatewayIpTextBox.ClearValue(TextBox.ForegroundProperty);
                            GatewayIpTextBox.ClearValue(TextBox.BorderBrushProperty);
                        }
                        else
                        {
                            GatewayIpTextBox.ClearValue(TextBox.BackgroundProperty);
                            GatewayIpTextBox.ClearValue(TextBox.ForegroundProperty);
                            GatewayIpTextBox.ClearValue(TextBox.BorderBrushProperty);

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

            if (_isHandlingTabChange)
                return;

            try
            {
                if (e.Source is TabControl)
                {
                    TabItem? currentTab = MainTabControl.SelectedItem as TabItem;

                    TabItem? previousTabFromEvent = null;
                    if (e.RemovedItems.Count > 0)
                    {
                        previousTabFromEvent = e.RemovedItems[0] as TabItem;

                        if (previousTabFromEvent != null && previousTabFromEvent != AdvancedTab)
                        {
                            _previousTab = previousTabFromEvent;
                        }
                    }

                    if (currentTab == AdvancedTab)
                    {
                        _isHandlingTabChange = true;

                        _disclaimerAcknowledged = false;

                        ShowAdvancedSettingsDisclaimer();

                        if (!_disclaimerAcknowledged)
                        {

                            TabItem? targetTab = _previousTab ?? previousTabFromEvent;

                            if (targetTab == null && MainTabControl.Items.Count > 0)
                            {
                                targetTab = MainTabControl.Items[0] as TabItem;
                            }

                            if (targetTab == AdvancedTab && MainTabControl.Items.Count > 0)
                            {

                                foreach (TabItem item in MainTabControl.Items)
                                {
                                    if (item != AdvancedTab)
                                    {
                                        targetTab = item;
                                        break;
                                    }
                                }
                            }

                            if (targetTab != null)
                            {
                                MainTabControl.SelectionChanged -= MainTabControl_SelectionChanged;
                                MainTabControl.SelectedItem = targetTab;
                                MainTabControl.SelectionChanged += MainTabControl_SelectionChanged;
                            }

                            _isHandlingTabChange = false;
                            return;
                        }

                        if (MainTabControl.SelectedItem != AdvancedTab)
                        {
                            MainTabControl.SelectionChanged -= MainTabControl_SelectionChanged;
                            MainTabControl.SelectedItem = AdvancedTab;
                            MainTabControl.SelectionChanged += MainTabControl_SelectionChanged;
                        }

                        UpdateLabModeBadge(true);

                        AdvTargetIpTextBox.Text = TargetIpTextBox.Text;
                        AdvTargetMacTextBox.Text = TargetMacTextBox.Text;
                        AdvSourceIpTextBox.Text = SourceIpTextBox.Text;
                        AdvSourceMacTextBox.Text = SourceMacTextBox.Text;
                        AdvGatewayIpTextBox.Text = GatewayIpTextBox.Text;

                        if (NetworkInterfaceComboBox.SelectedItem != null)
                        {
                            AdvNetworkInterfaceComboBox.SelectedItem = NetworkInterfaceComboBox.SelectedItem;
                        }

                        if (AdvPasswordBox != null)
                        {

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

                        _disclaimerAcknowledged = false;

                        UpdateLabModeBadge(false);

                        TargetIpTextBox.Text = AdvTargetIpTextBox.Text;
                        TargetMacTextBox.Text = AdvTargetMacTextBox.Text;
                        SourceIpTextBox.Text = AdvSourceIpTextBox.Text;
                        SourceMacTextBox.Text = AdvSourceMacTextBox.Text;
                        GatewayIpTextBox.Text = AdvGatewayIpTextBox.Text;

                        if (AdvNetworkInterfaceComboBox.SelectedItem != null)
                        {
                            NetworkInterfaceComboBox.SelectedItem = AdvNetworkInterfaceComboBox.SelectedItem;
                        }

                        ValidatePasswordAndUpdateUI();

                        _isHandlingTabChange = false;
                    }
                }

                UpdateProfileSummary();

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

            if (MainTabControl.SelectedItem == AdvancedTab)
            {

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

            if (MainTabControl.SelectedItem == AdvancedTab && AdvPasswordBox != null)
            {
                ValidatePasswordAndShowFeedback(AdvPasswordBox);
            }
        }

        private void ValidatePasswordAndShowFeedback(object sender)
        {
            var passwordBox = sender as PasswordBox;

            string password = AdvPasswordBox?.Password ?? string.Empty;
            bool passwordCorrect = !string.IsNullOrEmpty(password) && ValidatePassword(password);

            if (passwordCorrect)
            {

                _validationToken = GenerateValidationToken();

                SaveValidationToken();

                _isAdvancedMode = true;
                _attackLogger.LogInfo("🔓 Password validated - Attack controls enabled");

                ValidatePasswordAndUpdateUI();

                Application.Current.Dispatcher.Invoke(() =>
                {
                    if (StartAdvancedAttackButton != null)
                    {
                        bool tokenValid = !string.IsNullOrEmpty(_validationToken) && IsValidationTokenValid(_validationToken);
                        StartAdvancedAttackButton.IsEnabled = tokenValid;
                    }

                    if (AdvValidatePasswordButton != null)
                    {
                        AdvValidatePasswordButton.IsEnabled = false;
                    }
                }, System.Windows.Threading.DispatcherPriority.Normal);

                if (passwordBox != null)
                {
                    passwordBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                    var timer = new System.Windows.Threading.DispatcherTimer();
                    timer.Interval = TimeSpan.FromSeconds(2);
                    timer.Tick += (s, args) =>
                    {
                        passwordBox.ClearValue(System.Windows.Controls.Control.BorderBrushProperty);
                        timer.Stop();
                    };
                    timer.Start();
                }

                if (PasswordFeedbackText != null)
                {
                    PasswordFeedbackText.Visibility = Visibility.Collapsed;
                }

                _toastService?.ShowSuccess("Authentication successful. Advanced controls enabled.", 3000);
            }
            else
            {

                _validationToken = null;
                ValidatePasswordAndUpdateUI();

                if (passwordBox != null)
                {
                    passwordBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                }

                if (PasswordFeedbackText != null)
                {
                    PasswordFeedbackText.Text = "Incorrect password. Please try again.";
                    PasswordFeedbackText.Visibility = Visibility.Visible;
                }
            }
        }

        private void ValidatePasswordAndUpdateUI()
        {

            bool isValid = true;

            if (MainTabControl.SelectedItem == AdvancedTab)
            {

                isValid = !string.IsNullOrEmpty(_validationToken) && IsValidationTokenValid(_validationToken);
            }
            else
            {

                isValid = true;
            }

            if (StartButton != null)
            {
                StartButton.IsEnabled = isValid;
            }
            if (StopButton != null)
            {
                StopButton.IsEnabled = isValid && StopButton.IsEnabled;
            }
            if (StartAdvancedAttackButton != null)
            {

                bool attackRunning = StopAdvancedAttackButton?.IsEnabled == true;

                if (!isValid)
                {

                    StartAdvancedAttackButton.IsEnabled = false;
                }
                else if (attackRunning)
                {

                    StartAdvancedAttackButton.IsEnabled = false;
                }
                else
                {

                    StartAdvancedAttackButton.IsEnabled = true;
                }
            }
            if (StopAdvancedAttackButton != null)
            {

                if (!isValid)
                {
                    StopAdvancedAttackButton.IsEnabled = false;
                }

            }

            if (AdvValidatePasswordButton != null && MainTabControl.SelectedItem == AdvancedTab)
            {

                AdvValidatePasswordButton.IsEnabled = !isValid;
            }
        }

        private void NoteTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            var textBox = (TextBox)sender;
            if (textBox.Text == NOTE_PLACEHOLDER)
            {
                textBox.Text = string.Empty;
                textBox.ClearValue(TextBox.ForegroundProperty);
            }
        }

        private void NoteTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            var textBox = (TextBox)sender;
            if (string.IsNullOrWhiteSpace(textBox.Text))
            {
                textBox.Text = NOTE_PLACEHOLDER;
                textBox.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xAA));
            }
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);

            NoteTextBox.Text = NOTE_PLACEHOLDER;
            NoteTextBox.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xAA));
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
                NoteTextBox.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xAA));
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Error adding note: {ex.Message}");
                MessageBox.Show($"Error adding note: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

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

                var button = sender as Button;
                if (button != null)
                {
                    button.IsEnabled = false;
                }

                UpdateRunStatus(Dorothy.Services.FloodRunStatus.Running);
                await _traceRoute.ExecuteTraceRouteAsync(targetIp);
                UpdateRunStatus(Dorothy.Services.FloodRunStatus.Idle);

                if (button != null)
                {
                    button.IsEnabled = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error executing trace route: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                _attackLogger.LogError($"Trace route failed: {ex}");
                UpdateRunStatus(Dorothy.Services.FloodRunStatus.Error);
            }
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var progressBar = button == ScanButton ? ScanProgressBar : AdvScanProgressBar;
            var portTextBox = MainTabControl.SelectedItem == AdvancedTab ? AdvTargetPortTextBox : TargetPortTextBox;

            try
            {

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

                string attackType = MainTabControl.SelectedItem == AdvancedTab ?
                    (AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() :
                    (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content.ToString();

                if (string.IsNullOrEmpty(attackType))
                {
                    MessageBox.Show("Please select an attack type first.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                ProtocolType protocol;
                int[] portsToScan;

                if (attackType.Contains("TCP") || attackType == "TCP SYN Flood" || attackType == "TcpRoutedFlood")
                {
                    protocol = ProtocolType.Tcp;

                    portsToScan = new int[] {

                        80, 443, 8080, 8443, 8000, 8888, 9000,

                        22, 23, 2222,

                        25, 110, 143, 993, 995, 587, 465,

                        53,

                        21, 20, 2121,

                        3306, 5432, 1433, 1521, 27017, 6379,

                        3389, 5900, 5901,

                        8001, 8002, 8081, 8444, 9001,

                        139, 445,

                        135, 139, 445,

                        161, 162, 514, 636, 873, 2049, 3300, 5000, 5001, 5060, 5433, 5902, 5985, 5986, 7001, 7002, 8009, 8010, 8181, 8443, 8880, 9090, 9200, 9300, 10000
                    };
                }
                else if (attackType.Contains("UDP") || attackType == "UDP Flood")
                {
                    protocol = ProtocolType.Udp;

                    portsToScan = new int[] {

                        53,

                        67, 68,

                        69,

                        123,

                        161, 162,

                        500, 4500,

                        514,

                        520,

                        137, 138,

                        1900, 5353,

                        111, 1194, 1812, 1813, 2049, 5060, 5061, 10000
                    };
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

                    protocol = ProtocolType.Tcp;
                    portsToScan = new int[] {

                        80, 443, 8080, 8443, 8000, 8888, 9000,

                        22, 23, 2222,

                        25, 110, 143, 993, 995, 587, 465,

                        53,

                        21, 20, 2121,

                        3306, 5432, 1433, 1521, 27017, 6379,

                        3389, 5900, 5901,

                        8001, 8002, 8081, 8444, 9001,

                        139, 445,

                        135, 139, 445,

                        161, 162, 514, 636, 873, 2049, 3300, 5000, 5001, 5060, 5433, 5902, 5985, 5986, 7001, 7002, 8009, 8010, 8181, 8443, 8880, 9090, 9200, 9300, 10000
                    };
                }

                if (button != null)
                {
                    button.IsEnabled = false;
                    button.Content = "Scanning...";
                }

                if (progressBar != null)
                {
                    progressBar.Value = 0;
                    progressBar.Maximum = portsToScan.Length;
                    progressBar.IsIndeterminate = false;
                    progressBar.Visibility = Visibility.Visible;
                }

                _attackLogger.LogInfo($"🔍 Quick {protocol} port scan on {targetIp}...");
                _attackLogger.LogInfo($"Scanning {portsToScan.Length} common {protocol} ports...");

                int? foundPort = null;
                await Task.Run(async () =>
                {
                    try
                    {
                        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

                        foreach (var port in portsToScan)
                        {
                            if (cts.Token.IsCancellationRequested)
                                break;

                            try
                            {
                                bool isOpen = false;

                                if (protocol == ProtocolType.Tcp)
                                {

                                    using (var client = new TcpClient())
                                    {
                                        var connectTask = client.ConnectAsync(targetIp, port);
                                        var timeoutTask = Task.Delay(500, cts.Token);
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
                                            client.Client.ReceiveTimeout = 500;
                                            client.Client.SendTimeout = 500;
                                            await client.SendAsync(new byte[] { 0 }, 1, targetIp, port);
                                            await Task.Delay(200, cts.Token);

                                            isOpen = true;
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
                                    cts.Cancel();
                                    break;
                                }
                            }
                            catch (Exception ex)
                            {

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

                byte[] subnetMask = new byte[] { 255, 255, 255, 0 };
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

                var sourceBytes = sourceIpObj.GetAddressBytes();
                var networkBytes = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkBytes[i] = (byte)(sourceBytes[i] & subnetMask[i]);
                }
                string networkAddress = string.Join(".", networkBytes);

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

                var isAdvancedTab = MainTabControl.SelectedItem == AdvancedTab;
                var comboBox = isAdvancedTab ? AdvNetworkInterfaceComboBox : NetworkInterfaceComboBox;

                if (comboBox?.SelectedItem is { } selectedItem)
                {
                    var selectedInterface = (dynamic)selectedItem;

                    if (selectedInterface.Interface is NetworkInterface nic)
                    {

                        var ipProps = nic.GetIPProperties();
                        var unicastInfo = ipProps.UnicastAddresses
                            .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);

                        if (unicastInfo?.Address != null)
                        {
                            var ipAddress = unicastInfo.Address.ToString();
                            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
                            var macAddress = BitConverter.ToString(macBytes).Replace("-", ":");

                            byte[] subnetMask = new byte[] { 255, 255, 255, 0 };
                            if (unicastInfo.IPv4Mask != null)
                            {
                                subnetMask = unicastInfo.IPv4Mask.GetAddressBytes();
                            }

                            SourceIpTextBox.Text = ipAddress;
                            SourceMacTextBox.Text = macAddress;
                            AdvSourceIpTextBox.Text = ipAddress;
                            AdvSourceMacTextBox.Text = macAddress;

                            _networkStorm.SetSourceInfo(ipAddress, macBytes, subnetMask);

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

                            var currentIndex = comboBox.SelectedIndex;
                            PopulateNetworkInterfaces();

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

        private void ReachabilityPathAnalysisButton_Click(object sender, RoutedEventArgs e)
        {
            ReachabilityWizardWindow? wizard = null;
            try
            {

                wizard = new ReachabilityWizardWindow();
                wizard.Owner = this;
                wizard.ShowDialog();

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

        private BoundedTcpScanWindow? _boundedTcpScanWindow;

        private void BoundedTcpScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_boundedTcpScanWindow != null && _boundedTcpScanWindow.IsLoaded)
                {
                    _boundedTcpScanWindow.Activate();
                    return;
                }
                _boundedTcpScanWindow = new BoundedTcpScanWindow { Owner = this };
                _boundedTcpScanWindow.Closed += (_, _) => _boundedTcpScanWindow = null;
                _boundedTcpScanWindow.Show();
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error opening Bounded TCP Scan window");
                MessageBox.Show($"Error opening scan window: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

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

                StartSnmpWalkButton.IsEnabled = false;
                StopSnmpWalkButton.IsEnabled = true;

                _snmpWalkCancellationTokenSource = new CancellationTokenSource();
                var token = _snmpWalkCancellationTokenSource.Token;

                var progress = new Progress<(string message, int percent)>(update =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        SnmpWalkProgressBar.Value = update.percent;
                        _attackLogger.LogInfo(update.message);
                    });
                });

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

                            _snmpWalkNotVulnerable = !result.Success;
                            UpdateSecurityAssessmentStatus();

                            try
                            {
                                await _databaseService.SaveSnmpWalkResultAsync(result, null);
                            }
                            catch (Exception ex)
                            {
                                _logger.Error(ex, "Failed to save SNMP walk result");

                            }

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
                        System.Windows.Media.Color.FromRgb(5, 150, 105));
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

