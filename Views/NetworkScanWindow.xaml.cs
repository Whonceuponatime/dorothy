using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media.Animation;
using Dorothy.Models;
using Dorothy.Models.Database;
using Dorothy.Services;
using ClosedXML.Excel;
using Microsoft.Win32;

namespace Dorothy.Views
{
    public partial class NetworkScanWindow : Window
    {
        private readonly NetworkScan _networkScan;
        private readonly AttackLogger _attackLogger;
        private readonly DatabaseService? _databaseService;
        private List<NetworkAsset> _assets = new List<NetworkAsset>();
        private CancellationTokenSource? _cancellationTokenSource;
        private readonly List<NetworkAsset> _foundAssets = new List<NetworkAsset>();
        private bool _scanCompleted = false;
        private HashSet<int> _discoveredPorts = new HashSet<int>();
        private PortScanMode _currentPortScanMode = PortScanMode.None;

        private string _networkAddress = string.Empty;
        private string _subnetMask = string.Empty;

        private readonly string _hardwareId;
        private readonly string _machineName;
        private readonly string _username;

        public NetworkScanWindow(
            NetworkScan networkScan,
            AttackLogger attackLogger,
            DatabaseService? databaseService = null,
            string? hardwareId = null,
            string? machineName = null,
            string? username = null)
        {
            InitializeComponent();
            _networkScan = networkScan;
            _attackLogger = attackLogger;
            _databaseService = databaseService;
            _hardwareId = hardwareId ?? string.Empty;
            _machineName = machineName ?? Environment.MachineName;
            _username = username ?? Environment.UserName;

            if (AllPortsRadioButton != null)
                AllPortsRadioButton.Checked += PortScanMode_Changed;
            if (RangePortsRadioButton != null)
                RangePortsRadioButton.Checked += PortScanMode_Changed;
            if (SelectedPortsRadioButton != null)
                SelectedPortsRadioButton.Checked += PortScanMode_Changed;

            // 2.6.0: per-row sync flow replaced by engagement submit. Hide
            // the legacy Sync Assets button entirely; its callers have been
            // gutted alongside the SyncWindow / SupabaseSyncService deletions.
            if (SyncAssetsButton != null)
                SyncAssetsButton.Visibility = Visibility.Collapsed;
        }

        private void ScanMode_Changed(object sender, RoutedEventArgs e)
        {

            if (PortScanModePanel != null)
            {
                if (IntenseScanRadioButton?.IsChecked == true)
                {
                    PortScanModePanel.Visibility = Visibility.Visible;

                    if (AllPortsRadioButton?.IsChecked == true)
                        _currentPortScanMode = PortScanMode.All;
                    else if (RangePortsRadioButton?.IsChecked == true)
                        _currentPortScanMode = PortScanMode.Range;
                    else if (SelectedPortsRadioButton?.IsChecked == true)
                        _currentPortScanMode = PortScanMode.Selected;
                }
                else
                {
                    PortScanModePanel.Visibility = Visibility.Collapsed;
                    _currentPortScanMode = PortScanMode.None;
                }
            }

            UpdatePortDetailsVisibility();
        }

        private void PortScanMode_Changed(object sender, RoutedEventArgs e)
        {

            if (PortRangePanel != null && SelectedPortsPanel != null)
            {
                if (RangePortsRadioButton?.IsChecked == true)
                {
                    PortRangePanel.Visibility = Visibility.Visible;
                    SelectedPortsPanel.Visibility = Visibility.Collapsed;
                    _currentPortScanMode = PortScanMode.Range;

                    if (PortRangeStartTextBox != null && string.IsNullOrWhiteSpace(PortRangeStartTextBox.Text))
                    {
                        PortRangeStartTextBox.Text = "1";
                    }
                    if (PortRangeEndTextBox != null && string.IsNullOrWhiteSpace(PortRangeEndTextBox.Text))
                    {
                        PortRangeEndTextBox.Text = "65535";
                    }
                }
                else if (SelectedPortsRadioButton?.IsChecked == true)
                {
                    PortRangePanel.Visibility = Visibility.Collapsed;
                    SelectedPortsPanel.Visibility = Visibility.Visible;
                    _currentPortScanMode = PortScanMode.Selected;

                    if (PopulateFromScanButton != null)
                    {
                        PopulateFromScanButton.Visibility = _discoveredPorts.Count > 0
                            ? Visibility.Visible
                            : Visibility.Collapsed;
                    }
                }
                else if (AllPortsRadioButton?.IsChecked == true)
                {
                    PortRangePanel.Visibility = Visibility.Collapsed;
                    SelectedPortsPanel.Visibility = Visibility.Collapsed;
                    _currentPortScanMode = PortScanMode.All;
                }
            }

            UpdatePortDetailsVisibility();
        }

        private void UpdatePortDetailsVisibility()
        {

            bool shouldShowPorts = _currentPortScanMode == PortScanMode.All ||
                                   _currentPortScanMode == PortScanMode.Range ||
                                   _currentPortScanMode == PortScanMode.Selected;

            var portsDetailsBorder = this.FindName("PortsDetailsBorder") as Border;
            if (portsDetailsBorder != null)
            {
                portsDetailsBorder.Visibility = shouldShowPorts ? Visibility.Visible : Visibility.Collapsed;
            }

            if (PortsDataGrid != null)
            {
                PortsDataGrid.Visibility = shouldShowPorts ? Visibility.Visible : Visibility.Collapsed;
            }
        }

        private void PopulateFromScanButton_Click(object sender, RoutedEventArgs e)
        {

            if (SelectedPortsTextBox != null && _discoveredPorts.Count > 0)
            {
                var sortedPorts = _discoveredPorts.OrderBy(p => p).ToList();
                SelectedPortsTextBox.Text = string.Join(",", sortedPorts);
            }
        }

        private void ResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (PortsDataGrid == null) return;

            if (ResultsDataGrid.SelectedItem is NetworkAsset selectedAsset)
            {

                if (selectedAsset.OpenPorts != null && selectedAsset.OpenPorts.Count > 0)
                {
                    PortsDataGrid.ItemsSource = selectedAsset.OpenPorts.OrderBy(p => p.Port).ToList();

                    if (PortsCountText != null)
                    {
                        PortsCountText.Text = $"({selectedAsset.OpenPorts.Count} port{(selectedAsset.OpenPorts.Count == 1 ? "" : "s")} from {selectedAsset.IpAddress})";
                        PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                            System.Windows.Media.Color.FromRgb(5, 150, 105));
                    }
                }
                else
                {
                    PortsDataGrid.ItemsSource = null;
                    if (PortsCountText != null)
                    {
                        PortsCountText.Text = $"(No ports found for {selectedAsset.IpAddress})";
                        PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                            System.Windows.Media.Color.FromRgb(107, 114, 128));
                    }
                }
            }
            else
            {

                var allPorts = _foundAssets
                    .Where(a => a.OpenPorts != null && a.OpenPorts.Count > 0)
                    .SelectMany(a => a.OpenPorts)
                    .OrderBy(p => p.Port)
                    .ToList();

                if (allPorts.Count > 0)
                {
                    PortsDataGrid.ItemsSource = allPorts;
                    if (PortsCountText != null)
                    {
                        var deviceCount = _foundAssets.Count(a => a.OpenPorts != null && a.OpenPorts.Count > 0);
                        PortsCountText.Text = $"({allPorts.Count} port{(allPorts.Count == 1 ? "" : "s")} from {deviceCount} device{(deviceCount == 1 ? "" : "s")})";
                        PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                            System.Windows.Media.Color.FromRgb(5, 150, 105));
                    }
                }
                else
                {
                    PortsDataGrid.ItemsSource = null;
                    if (PortsCountText != null)
                    {
                        PortsCountText.Text = "(No ports found)";
                        PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                            System.Windows.Media.Color.FromRgb(107, 114, 128));
                    }
                }
            }
        }

        private List<int> ParseSelectedPorts(string text)
        {
            var ports = new List<int>();
            if (string.IsNullOrWhiteSpace(text))
                return ports;

            var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                if (int.TryParse(part.Trim(), out int port) && port >= 1 && port <= 65535)
                {
                    if (!ports.Contains(port))
                        ports.Add(port);
                }
            }
            return ports;
        }

        public async Task StartScanAsync(string networkAddress, string subnetMask)
        {
            _networkAddress = networkAddress;
            _subnetMask = subnetMask;

            CalculateAndSetDefaultRange(networkAddress, subnetMask);

            _networkScan.SetScanMode(false);
        }

        private void CalculateAndSetDefaultRange(string networkAddress, string subnetMask)
        {
            try
            {
                if (System.Net.IPAddress.TryParse(networkAddress, out var networkIp) &&
                    System.Net.IPAddress.TryParse(subnetMask, out var maskIp))
                {
                    var networkBytes = networkIp.GetAddressBytes();
                    var maskBytes = maskIp.GetAddressBytes();

                    var networkStart = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        networkStart[i] = (byte)(networkBytes[i] & maskBytes[i]);
                    }

                    var broadcast = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        broadcast[i] = (byte)(networkStart[i] | ~maskBytes[i]);
                    }

                    var startIp = new byte[4];
                    Array.Copy(networkStart, startIp, 4);
                    startIp[3] = (byte)(startIp[3] + 1);

                    var endIp = new byte[4];
                    Array.Copy(broadcast, endIp, 4);
                    endIp[3] = (byte)(endIp[3] - 1);

                    StartIpTextBox.Text = string.Join(".", startIp);
                    EndIpTextBox.Text = string.Join(".", endIp);
                }
            }
            catch
            {

            }
        }

        private void QuickRangeButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string tag)
            {
                switch (tag)
                {
                    case "full":

                        CalculateAndSetDefaultRange(_networkAddress, _subnetMask);
                        break;
                    case "192.168.1":
                        StartIpTextBox.Text = "192.168.1.1";
                        EndIpTextBox.Text = "192.168.1.254";
                        break;
                    case "192.168.0":
                        StartIpTextBox.Text = "192.168.0.1";
                        EndIpTextBox.Text = "192.168.0.254";
                        break;
                    case "10.0.0":
                        StartIpTextBox.Text = "10.0.0.1";
                        EndIpTextBox.Text = "10.0.0.254";
                        break;
                }
            }
        }

        private async void StartScanButton_Click(object sender, RoutedEventArgs e)
        {
            var startIp = StartIpTextBox.Text.Trim();
            var endIp = EndIpTextBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(startIp) || string.IsNullOrWhiteSpace(endIp))
            {
                MessageBox.Show("Please enter both start and end IP addresses.", "Invalid Range", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!System.Net.IPAddress.TryParse(startIp, out _) || !System.Net.IPAddress.TryParse(endIp, out _))
            {
                MessageBox.Show("Please enter valid IP addresses.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            bool intenseScan = IntenseScanRadioButton?.IsChecked == true;
            if (_networkScan != null)
            {
                _networkScan.SetScanMode(intenseScan);

                if (intenseScan)
                {
                    PortScanMode portMode = PortScanMode.All;
                    int? rangeStart = null;
                    int? rangeEnd = null;
                    List<int>? selectedPorts = null;

                    if (AllPortsRadioButton?.IsChecked == true)
                    {
                        portMode = PortScanMode.All;
                        _currentPortScanMode = PortScanMode.All;
                    }
                    else if (RangePortsRadioButton?.IsChecked == true)
                    {
                        portMode = PortScanMode.Range;
                        _currentPortScanMode = PortScanMode.Range;

                        if (PortRangeStartTextBox != null && PortRangeEndTextBox != null)
                        {
                            if (int.TryParse(PortRangeStartTextBox.Text, out int start) &&
                                int.TryParse(PortRangeEndTextBox.Text, out int end))
                            {
                                rangeStart = Math.Max(1, Math.Min(start, 65535));
                                rangeEnd = Math.Min(65535, Math.Max(start, end));
                            }
                            else
                            {

                                rangeStart = 1;
                                rangeEnd = 65535;
                            }
                        }
                        else
                        {

                            rangeStart = 1;
                            rangeEnd = 65535;
                        }
                    }
                    else if (SelectedPortsRadioButton?.IsChecked == true)
                    {
                        portMode = PortScanMode.Selected;
                        _currentPortScanMode = PortScanMode.Selected;
                        if (SelectedPortsTextBox != null)
                        {
                            selectedPorts = ParseSelectedPorts(SelectedPortsTextBox.Text);
                        }
                    }

                    _networkScan.SetPortScanMode(portMode, rangeStart, rangeEnd, selectedPorts);
                }
                else
                {
                    _networkScan.SetPortScanMode(PortScanMode.None);
                    _currentPortScanMode = PortScanMode.None;
                }

                UpdatePortDetailsVisibility();
            }

            RangeConfigPanel.Visibility = Visibility.Collapsed;
            StartScanButton.IsEnabled = false;

            var progressSection = FindName("ProgressSection") as FrameworkElement;
            if (progressSection != null)
            {
                progressSection.Visibility = Visibility.Visible;
            }

            await StartCustomRangeScanAsync(startIp, endIp);
        }

        private async Task StartCustomRangeScanAsync(string startIp, string endIp)
        {
            try
            {
                if (string.IsNullOrEmpty(startIp) || string.IsNullOrEmpty(endIp))
                {
                    MessageBox.Show("Start IP and End IP are required.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (_networkScan == null)
                {
                    MessageBox.Show("Network scan instance is not initialized.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                _cancellationTokenSource = new CancellationTokenSource();

                Dispatcher.Invoke(() =>
                {
                    try
                    {
                        if (LoadingIndicator != null)
                            LoadingIndicator.Visibility = Visibility.Visible;
                        if (CancelScanButton != null)
                            CancelScanButton.Visibility = Visibility.Visible;
                        if (BackButton != null)
                            BackButton.Visibility = Visibility.Collapsed;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = false;
                        if (ExportExcelButton != null)
                            ExportExcelButton.IsEnabled = false;

                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Visibility = Visibility.Visible;
                            StatusTextBlock.Text = "Initializing scan...";
                            StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 24, 39));
                        }
                        if (ProgressTextBlock != null)
                        {
                            ProgressTextBlock.Visibility = Visibility.Visible;
                            ProgressTextBlock.Text = "0 / 0";
                        }
                        if (ScanProgressBar != null)
                        {
                            ScanProgressBar.Visibility = Visibility.Visible;
                            ScanProgressBar.Value = 0;
                            ScanProgressBar.Maximum = 100;
                        }
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Visibility = Visibility.Visible;
                            CurrentIpTextBlock.Text = "Preparing scan...";
                            CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(156, 163, 175));
                        }
                        if (FoundCountTextBlock != null)
                        {
                            FoundCountTextBlock.Visibility = Visibility.Visible;
                            FoundCountTextBlock.Text = "0";
                        }

                        _foundAssets.Clear();
                        if (ResultsDataGrid != null)
                            ResultsDataGrid.ItemsSource = _foundAssets;
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error updating UI: {ex.Message}");
                    }
                }, System.Windows.Threading.DispatcherPriority.Send);

                await Task.Delay(150);

                _scanCompleted = false;

                var progress = new Progress<ScanProgress>(UpdateProgress);

                _assets = await _networkScan.ScanNetworkByRangeAsync(startIp, endIp, _cancellationTokenSource.Token, progress);

                _scanCompleted = true;

                await Task.Delay(100);

                foreach (var asset in _assets)
                {
                    if (asset.OpenPorts != null && asset.OpenPorts.Count > 0)
                    {
                        foreach (var openPort in asset.OpenPorts)
                        {
                            _discoveredPorts.Add(openPort.Port);
                        }
                    }
                }

                if (_databaseService != null && _assets.Count > 0)
                {
                    await SaveAssetsToDatabaseAsync();
                }

                Dispatcher.Invoke(() =>
                {
                    try
                    {

                        if (_assets != null && _assets.Count > 0)
                        {
                            _foundAssets.Clear();
                            var allPorts = new List<Models.OpenPort>();

                            foreach (var asset in _assets)
                            {
                                _foundAssets.Add(asset);

                                if (asset.OpenPorts != null && asset.OpenPorts.Count > 0)
                                {
                                    allPorts.AddRange(asset.OpenPorts);
                                }
                            }

                            if ((_currentPortScanMode == PortScanMode.All || _currentPortScanMode == PortScanMode.Range || _currentPortScanMode == PortScanMode.Selected) && PortsDataGrid != null && allPorts.Count > 0)
                            {
                                PortsDataGrid.ItemsSource = allPorts.OrderBy(p => p.Port).ToList();

                                if (PortsCountText != null)
                                {
                                    PortsCountText.Text = $"({allPorts.Count} port{(allPorts.Count == 1 ? "" : "s")} from {_assets.Count(a => a.OpenPorts != null && a.OpenPorts.Count > 0)} device{(allPorts.Count == 1 ? "" : "s")})";
                                    PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                                        System.Windows.Media.Color.FromRgb(5, 150, 105));
                                }
                            }
                            else if (PortsDataGrid != null)
                            {
                                PortsDataGrid.ItemsSource = null;
                                if (PortsCountText != null)
                                {
                                    PortsCountText.Text = "(No ports found)";
                                    PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                                        System.Windows.Media.Color.FromRgb(107, 114, 128));
                                }
                            }

                            UpdatePortDetailsVisibility();

                            var firstAssetWithPorts = _foundAssets.FirstOrDefault(a => a.OpenPorts != null && a.OpenPorts.Count > 0);
                            if (firstAssetWithPorts != null && ResultsDataGrid != null)
                            {
                                ResultsDataGrid.SelectedItem = firstAssetWithPorts;
                                ResultsDataGrid.ScrollIntoView(firstAssetWithPorts);
                            }
                        }

                        if (PopulateFromScanButton != null && SelectedPortsRadioButton?.IsChecked == true)
                        {
                            PopulateFromScanButton.Visibility = _discoveredPorts.Count > 0
                                ? Visibility.Visible
                                : Visibility.Collapsed;
                        }

                        if (ResultsDataGrid != null)
                        {
                            ResultsDataGrid.ItemsSource = null;
                            ResultsDataGrid.ItemsSource = _foundAssets;
                            ResultsDataGrid.Items.Refresh();
                        }

                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Text = $"✅ Scan Complete! Found {(_assets?.Count ?? 0)} active device(s).";
                            StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(5, 150, 105));
                        }
                        if (ProgressTextBlock != null)
                            ProgressTextBlock.Text = "Done";
                        if (ScanProgressBar != null)
                            ScanProgressBar.Value = ScanProgressBar.Maximum;
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Text = "Scan finished successfully.";
                            CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(5, 150, 105));
                        }

                        if (FoundCountTextBlock != null)
                        {
                            FoundCountTextBlock.Text = (_assets?.Count ?? 0).ToString();
                        }

                        if (ExportExcelButton != null)
                            ExportExcelButton.IsEnabled = _assets != null && _assets.Count > 0;

                        if (LoadingIndicator != null)
                            LoadingIndicator.Visibility = Visibility.Collapsed;
                        if (CancelScanButton != null)
                            CancelScanButton.Visibility = Visibility.Collapsed;
                        if (BackButton != null)
                            BackButton.Visibility = Visibility.Visible;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = true;

                        // 2.6.0: per-row sync flow removed.
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error in final UI update: {ex.Message}");
                    }
                }, System.Windows.Threading.DispatcherPriority.Send);
            }
            catch (OperationCanceledException)
            {
                _scanCompleted = true;
                await Task.Delay(100);
                Dispatcher.Invoke(() =>
                {
                    try
                    {
                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Text = "⚠️ Scan Cancelled";
                            StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 158, 11));
                        }
                        if (ProgressTextBlock != null)
                            ProgressTextBlock.Text = "Cancelled";
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Text = "Scan was cancelled by user.";
                            CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(107, 114, 128));
                        }
                        if (LoadingIndicator != null)
                            LoadingIndicator.Visibility = Visibility.Collapsed;
                        if (CancelScanButton != null)
                            CancelScanButton.Visibility = Visibility.Collapsed;
                        if (BackButton != null)
                            BackButton.Visibility = Visibility.Visible;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = true;
                    }
                    catch (Exception uiEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error updating UI on cancel: {uiEx.Message}");
                    }
                }, System.Windows.Threading.DispatcherPriority.Send);
            }
            catch (Exception ex)
            {
                _scanCompleted = true;
                await Task.Delay(100);
                Dispatcher.Invoke(() =>
                {
                    try
                    {
                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Text = $"❌ Scan Failed: {ex.Message}";
                            StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xF8, 0x71, 0x71));
                        }
                        if (ProgressTextBlock != null)
                            ProgressTextBlock.Text = "Failed";
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Text = $"Error: {ex.Message}";
                            CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xF8, 0x71, 0x71));
                        }
                        if (LoadingIndicator != null)
                            LoadingIndicator.Visibility = Visibility.Collapsed;
                        if (CancelScanButton != null)
                            CancelScanButton.Visibility = Visibility.Collapsed;
                        if (BackButton != null)
                            BackButton.Visibility = Visibility.Visible;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = true;
                        MessageBox.Show($"Network scan failed: {ex.Message}\n\nStack trace: {ex.StackTrace}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                    catch (Exception uiEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error updating UI on error: {uiEx.Message}");
                        MessageBox.Show($"Network scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }, System.Windows.Threading.DispatcherPriority.Send);
            }
        }

        private void UpdateProgress(ScanProgress progress)
        {
            try
            {
                if (progress == null)
                    return;

                if (_scanCompleted)
                    return;

                Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {

                        if (_scanCompleted)
                            return;

                        if (progress.IsPortScanning && !string.IsNullOrEmpty(progress.PortScanIp))
                        {

                            if (LoadingIndicator != null)
                            {
                                LoadingIndicator.Visibility = Visibility.Visible;
                            }

                            if (StatusTextBlock != null)
                            {
                                StatusTextBlock.Text = $"Scanning ports on {progress.PortScanIp}...";
                                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(37, 99, 235));
                            }

                            if (CurrentIpTextBlock != null)
                            {
                                if (progress.TotalPorts > 0)
                                {
                                    CurrentIpTextBlock.Text = $"Port scanning: {progress.PortScanIp} ({progress.PortsScanned} / {progress.TotalPorts} ports)";
                                }
                                else
                                {
                                    CurrentIpTextBlock.Text = $"Port scanning: {progress.PortScanIp}...";
                                }
                                CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(37, 99, 235));
                            }

                            if (ScanProgressBar != null && progress.TotalPorts > 0)
                            {
                                ScanProgressBar.Maximum = progress.TotalPorts;
                                ScanProgressBar.Value = progress.PortsScanned;
                            }

                            if (progress.NewPort != null)
                            {

                                var asset = _foundAssets.FirstOrDefault(a => a.IpAddress == progress.PortScanIp);
                                if (asset != null)
                                {

                                    if (asset.OpenPorts == null)
                                        asset.OpenPorts = new List<Models.OpenPort>();

                                    if (!asset.OpenPorts.Any(p => p.Port == progress.NewPort.Port && p.Protocol == progress.NewPort.Protocol))
                                    {
                                        asset.OpenPorts.Add(progress.NewPort);
                                        asset.OpenPorts = asset.OpenPorts.OrderBy(p => p.Port).ToList();

                                        _discoveredPorts.Add(progress.NewPort.Port);

                                        ResultsDataGrid.Items.Refresh();

                                        if (PortsDataGrid != null &&
                                            (_currentPortScanMode == PortScanMode.Common ||
                                             _currentPortScanMode == PortScanMode.All ||
                                             _currentPortScanMode == PortScanMode.Range ||
                                             _currentPortScanMode == PortScanMode.Selected))
                                        {

                                            var allPorts = _foundAssets
                                                .Where(a => a.OpenPorts != null && a.OpenPorts.Count > 0)
                                                .SelectMany(a => a.OpenPorts)
                                                .OrderBy(p => p.Port)
                                                .ToList();

                                            PortsDataGrid.ItemsSource = allPorts;
                                            PortsDataGrid.Items.Refresh();

                                            if (PortsCountText != null)
                                            {
                                                var deviceCount = _foundAssets.Count(a => a.OpenPorts != null && a.OpenPorts.Count > 0);
                                                PortsCountText.Text = $"({allPorts.Count} port{(allPorts.Count == 1 ? "" : "s")} from {deviceCount} device{(deviceCount == 1 ? "" : "s")})";
                                                PortsCountText.Foreground = new System.Windows.Media.SolidColorBrush(
                                                    System.Windows.Media.Color.FromRgb(5, 150, 105));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {

                            if (StatusTextBlock != null)
                            {
                                StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 24, 39));
                                StatusTextBlock.Text = $"Scanning network...";
                            }

                            if (CurrentIpTextBlock != null)
                            {
                                CurrentIpTextBlock.Text = $"Scanning: {progress.CurrentIp ?? "..."}";
                                CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(156, 163, 175));
                            }

                            if (ProgressTextBlock != null)
                                ProgressTextBlock.Text = $"{progress.Scanned} / {progress.Total}";

                            if (ScanProgressBar != null && progress.Total > 0)
                            {
                                ScanProgressBar.Maximum = progress.Total;
                                ScanProgressBar.Value = progress.Scanned;
                            }

                            if (FoundCountTextBlock != null)
                                FoundCountTextBlock.Text = progress.Found.ToString();

                            if (progress.NewAsset != null && ResultsDataGrid != null)
                            {
                                _foundAssets.Add(progress.NewAsset);

                                if (progress.NewAsset.OpenPorts != null && progress.NewAsset.OpenPorts.Count > 0)
                                {
                                    foreach (var openPort in progress.NewAsset.OpenPorts)
                                    {
                                        _discoveredPorts.Add(openPort.Port);
                                    }
                                }

                                ResultsDataGrid.Items.Refresh();

                                if (ResultsDataGrid.Items.Count > 0)
                                {
                                    ResultsDataGrid.ScrollIntoView(ResultsDataGrid.Items[ResultsDataGrid.Items.Count - 1]);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error in UpdateProgress UI update: {ex.Message}");
                    }
                }), System.Windows.Threading.DispatcherPriority.Normal);
            }
            catch
            {

            }
        }

        private void CancelScanButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            CancelScanButton.IsEnabled = false;
            CancelScanButton.Content = "Cancelling...";
        }

        private async Task SaveAssetsToDatabaseAsync()
        {
            if (_databaseService == null) return;

            try
            {
                foreach (var asset in _assets)
                {

                    string portsDisplay = null;
                    if (asset.OpenPorts != null && asset.OpenPorts.Count > 0)
                    {
                        portsDisplay = string.Join(", ", asset.OpenPorts.Select(p =>
                            string.IsNullOrEmpty(p.Banner)
                                ? $"{p.Port}/{p.Protocol}"
                                : $"{p.Port}/{p.Protocol} [{p.Banner}]"));
                    }

                    var assetEntry = new Models.Database.AssetEntry
                    {
                        HostIp = asset.IpAddress,

                        HostName = string.IsNullOrEmpty(asset.Name) ? null : (asset.Name == "Unknown" ? "Unknown" : asset.Name),
                        MacAddress = string.IsNullOrEmpty(asset.MacAddress) ? null : (asset.MacAddress == "Unknown" ? "Unknown" : asset.MacAddress),
                        Vendor = string.IsNullOrEmpty(asset.Vendor) ? null : (asset.Vendor == "Unknown" ? "Unknown" : asset.Vendor),
                        IsOnline = asset.IsReachable,
                        PingTime = asset.RoundTripTime.HasValue ? (int)asset.RoundTripTime.Value : null,
                        ScanTime = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Ports = portsDisplay,

                        HardwareId = _hardwareId,
                        MachineName = _machineName,
                        Username = _username,
                        UserId = null
                    };

                    // Unsubmitted-bucket insert. EngagementId stays null until
                    // the user submits, at which point AssignEngagementIdToUnsubmittedAsync
                    // flips it for every still-null row.
                    var assetId = await _databaseService.SaveAssetAsync(assetEntry);
                    Services.EngagementContext.NotifyActivityChanged();

                    if (asset.OpenPorts != null && asset.OpenPorts.Count > 0)
                    {
                        foreach (var openPort in asset.OpenPorts)
                        {
                            var portEntry = new Models.Database.PortEntry
                            {
                                AssetId = assetId,
                                HostIp = asset.IpAddress,
                                Port = openPort.Port,
                                Protocol = openPort.Protocol ?? "TCP",
                                Service = string.IsNullOrWhiteSpace(openPort.Service) ? null : openPort.Service.Trim(),
                                Banner = string.IsNullOrWhiteSpace(openPort.Banner) ? null : openPort.Banner.Trim(),
                                ScanTime = DateTime.UtcNow,
                                CreatedAt = DateTime.UtcNow,

                                HardwareId = _hardwareId,
                                MachineName = _machineName,
                                Username = _username,
                                UserId = null
                            };

                            try
                            {
                                await _databaseService.SavePortAsync(portEntry);
                            }
                            catch (Exception portEx)
                            {
                                _attackLogger.LogError($"Failed to save port {openPort.Port} for {asset.IpAddress}: {portEx.Message}");

                            }
                        }

                        _attackLogger.LogInfo($"Saved/updated {asset.OpenPorts.Count} port(s) for {asset.IpAddress} to database. Asset marked as unsynced for cloud sync.");
                    }
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Failed to save assets to database: {ex.Message}");
            }
        }

        // Removed in 2.6.0: per-row sync flow replaced by engagement submit.
        private async void SyncAssetsButton_Click(object sender, RoutedEventArgs e)
        {
            await Task.CompletedTask;
            _attackLogger.LogInfo("Asset upload now happens at engagement submit time (MainWindow toolbar).");
        }

        private void ExportExcelButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Filter = "Excel Files (*.xlsx)|*.xlsx|All Files (*.*)|*.*",
                    FileName = $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx",
                    DefaultExt = "xlsx"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    ExportToExcel(saveDialog.FileName);
                    MessageBox.Show($"Network scan results exported to:\n{saveDialog.FileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export to Excel: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportToExcel(string filePath)
        {
            using var workbook = new XLWorkbook();
            var worksheet = workbook.Worksheets.Add("Network Assets");

            worksheet.Cell(1, 1).Value = "IP Address";
            worksheet.Cell(1, 2).Value = "MAC Address";
            worksheet.Cell(1, 3).Value = "Name";
            worksheet.Cell(1, 4).Value = "Vendor";
            worksheet.Cell(1, 5).Value = "Status";
            worksheet.Cell(1, 6).Value = "Round Trip Time (ms)";
            worksheet.Cell(1, 7).Value = "Open Ports";
            worksheet.Cell(1, 8).Value = "Port Details";

            var headerRange = worksheet.Range(1, 1, 1, 8);
            headerRange.Style.Font.Bold = true;
            headerRange.Style.Fill.BackgroundColor = XLColor.LightGray;
            headerRange.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;

            int row = 2;
            foreach (var asset in _assets)
            {
                worksheet.Cell(row, 1).Value = asset.IpAddress;
                worksheet.Cell(row, 2).Value = asset.MacAddress;
                worksheet.Cell(row, 3).Value = asset.Name;
                worksheet.Cell(row, 4).Value = asset.Vendor;
                worksheet.Cell(row, 5).Value = asset.Status;
                worksheet.Cell(row, 6).Value = asset.RoundTripTime?.ToString() ?? "N/A";
                worksheet.Cell(row, 7).Value = asset.OpenPorts.Count > 0 ? asset.OpenPorts.Count.ToString() : "0";

                var portDetails = new System.Text.StringBuilder();
                foreach (var port in asset.OpenPorts)
                {
                    if (portDetails.Length > 0) portDetails.AppendLine();
                    portDetails.Append($"{port.Port}/{port.Protocol} - {port.Service}");
                    if (!string.IsNullOrEmpty(port.Banner))
                    {
                        portDetails.Append($" ({port.Banner})");
                    }
                }
                worksheet.Cell(row, 8).Value = portDetails.Length > 0 ? portDetails.ToString() : "None";
                row++;
            }

            worksheet.Columns().AdjustToContents();

            var summarySheet = workbook.Worksheets.Add("Summary");
            summarySheet.Cell(1, 1).Value = "Network Scan Summary";
            summarySheet.Cell(1, 1).Style.Font.Bold = true;
            summarySheet.Cell(1, 1).Style.Font.FontSize = 14;

            summarySheet.Cell(3, 1).Value = "Total Devices Found:";
            summarySheet.Cell(3, 2).Value = _assets.Count;
            summarySheet.Cell(4, 1).Value = "Scan Date:";
            summarySheet.Cell(4, 2).Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            summarySheet.Columns().AdjustToContents();

            workbook.SaveAs(filePath);
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();

            Dispatcher.Invoke(() =>
            {
                try
                {

                    if (RangeConfigPanel != null)
                        RangeConfigPanel.Visibility = Visibility.Visible;

                    if (StartScanButton != null)
                        StartScanButton.IsEnabled = true;

                    if (BackButton != null)
                        BackButton.Visibility = Visibility.Collapsed;

                    if (StatusTextBlock != null)
                    {
                        StatusTextBlock.Text = "Ready to scan";
                        StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 24, 39));
                    }
                    if (ProgressTextBlock != null)
                        ProgressTextBlock.Text = "0 / 0";
                    if (ScanProgressBar != null)
                    {
                        ScanProgressBar.Value = 0;
                        ScanProgressBar.Maximum = 100;
                    }
                    if (CurrentIpTextBlock != null)
                        CurrentIpTextBlock.Text = "";
                    if (FoundCountTextBlock != null)
                        FoundCountTextBlock.Text = "0";
                    if (LoadingIndicator != null)
                        LoadingIndicator.Visibility = Visibility.Collapsed;
                    if (CancelScanButton != null)
                        CancelScanButton.Visibility = Visibility.Collapsed;

                    _foundAssets.Clear();
                    if (ResultsDataGrid != null)
                    {
                        ResultsDataGrid.ItemsSource = null;
                        ResultsDataGrid.ItemsSource = _foundAssets;
                    }

                    if (PortsDataGrid != null)
                    {
                        PortsDataGrid.ItemsSource = null;
                    }

                    if (ExportExcelButton != null)
                        ExportExcelButton.IsEnabled = false;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error in BackButton_Click: {ex.Message}");
                }
            });
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            base.OnClosing(e);
        }
    }

    public class NullableLongConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            var nullableLong = value as long?;
            if (nullableLong.HasValue)
            {
                return nullableLong.Value.ToString();
            }
            return "N/A";
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }

    public class EmptyBannerConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
            {
                return "(No banner - port may not respond to probes)";
            }
            return value.ToString();
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}

