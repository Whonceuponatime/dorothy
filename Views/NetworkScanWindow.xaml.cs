using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;
using Dorothy.Models;
using Dorothy.Models.Database;
using Dorothy.Services;
using ClosedXML.Excel;

namespace Dorothy.Views
{
    public partial class NetworkScanWindow : Window
    {
        // FindControl properties for XAML-named controls
        private RadioButton? AllPortsRadioButton => this.FindControl<RadioButton>("AllPortsRadioButton");
        private RadioButton? RangePortsRadioButton => this.FindControl<RadioButton>("RangePortsRadioButton");
        private RadioButton? SelectedPortsRadioButton => this.FindControl<RadioButton>("SelectedPortsRadioButton");
        private Button? SyncAssetsButton => this.FindControl<Button>("SyncAssetsButton");
        private Panel? PortScanModePanel => this.FindControl<Panel>("PortScanModePanel");
        private RadioButton? IntenseScanRadioButton => this.FindControl<RadioButton>("IntenseScanRadioButton");
        private Panel? PortRangePanel => this.FindControl<Panel>("PortRangePanel");
        private Panel? SelectedPortsPanel => this.FindControl<Panel>("SelectedPortsPanel");
        private TextBox? PortRangeStartTextBox => this.FindControl<TextBox>("PortRangeStartTextBox");
        private TextBox? PortRangeEndTextBox => this.FindControl<TextBox>("PortRangeEndTextBox");
        private Button? PopulateFromScanButton => this.FindControl<Button>("PopulateFromScanButton");
        private DataGrid? PortsDataGrid => this.FindControl<DataGrid>("PortsDataGrid");
        private TextBox? SelectedPortsTextBox => this.FindControl<TextBox>("SelectedPortsTextBox");
        private TextBox? StartIpTextBox => this.FindControl<TextBox>("StartIpTextBox");
        private TextBox? EndIpTextBox => this.FindControl<TextBox>("EndIpTextBox");
        private Panel? RangeConfigPanel => this.FindControl<Panel>("RangeConfigPanel");
        private Button? StartScanButton => this.FindControl<Button>("StartScanButton");
        private Control? LoadingIndicator => this.FindControl<Control>("LoadingIndicator");
        private Button? CancelScanButton => this.FindControl<Button>("CancelScanButton");
        private Button? BackButton => this.FindControl<Button>("BackButton");
        private Button? CloseButton => this.FindControl<Button>("CloseButton");
        private Button? ExportExcelButton => this.FindControl<Button>("ExportExcelButton");
        private TextBlock? StatusTextBlock => this.FindControl<TextBlock>("StatusTextBlock");
        private TextBlock? ProgressTextBlock => this.FindControl<TextBlock>("ProgressTextBlock");
        private ProgressBar? ScanProgressBar => this.FindControl<ProgressBar>("ScanProgressBar");
        private TextBlock? CurrentIpTextBlock => this.FindControl<TextBlock>("CurrentIpTextBlock");
        private TextBlock? FoundCountTextBlock => this.FindControl<TextBlock>("FoundCountTextBlock");
        private DataGrid? ResultsDataGrid => this.FindControl<DataGrid>("ResultsDataGrid");
        private TextBlock? PortsCountText => this.FindControl<TextBlock>("PortsCountText");
        private Border? AssetsSyncBadge => this.FindControl<Border>("AssetsSyncBadge");
        private TextBlock? AssetsSyncBadgeText => this.FindControl<TextBlock>("AssetsSyncBadgeText");

        private readonly NetworkScan _networkScan;
        private readonly AttackLogger _attackLogger;
        private readonly DatabaseService? _databaseService;
        private readonly SupabaseSyncService? _supabaseSyncService;
        private List<NetworkAsset> _assets = new List<NetworkAsset>();
        private CancellationTokenSource? _cancellationTokenSource;
        private readonly List<NetworkAsset> _foundAssets = new List<NetworkAsset>();
        private bool _scanCompleted = false;
        private HashSet<int> _discoveredPorts = new HashSet<int>(); // Track ports discovered in previous scans
        private PortScanMode _currentPortScanMode = PortScanMode.None; // Track current port scan mode for UI visibility

        private string _networkAddress = string.Empty;
        private string _subnetMask = string.Empty;

        // Metadata for asset tracking
        private readonly string _hardwareId;
        private readonly string _machineName;
        private readonly string _username;

        public NetworkScanWindow(
            NetworkScan networkScan, 
            AttackLogger attackLogger, 
            DatabaseService? databaseService = null, 
            SupabaseSyncService? supabaseSyncService = null,
            string? hardwareId = null,
            string? machineName = null,
            string? username = null)
        {
            AvaloniaXamlLoader.Load(this);
            _networkScan = networkScan;
            _attackLogger = attackLogger;
            _databaseService = databaseService;
            _supabaseSyncService = supabaseSyncService;
            _hardwareId = hardwareId ?? string.Empty;
            _machineName = machineName ?? Environment.MachineName;
            _username = username ?? Environment.UserName;
            
            // Wire up port scan mode radio button events (check for null in case XAML hasn't loaded yet)
            if (AllPortsRadioButton != null)
                AllPortsRadioButton.Checked += PortScanMode_Changed;
            if (RangePortsRadioButton != null)
                RangePortsRadioButton.Checked += PortScanMode_Changed;
            if (SelectedPortsRadioButton != null)
                SelectedPortsRadioButton.Checked += PortScanMode_Changed;
            
            // Show/hide sync button based on availability
            if (_databaseService == null || _supabaseSyncService == null)
            {
                SyncAssetsButton.IsVisible = false;
            }
            else
            {
                _ = Task.Run(async () => await UpdateAssetsSyncStatus());
            }
        }
        
        private void ScanMode_Changed(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            // Show/hide port scan mode panel based on scan mode
            if (PortScanModePanel != null)
            {
                if (IntenseScanRadioButton?.IsChecked == true)
                {
                    PortScanModePanel.IsVisible = true;
                    // Determine current port scan mode from radio buttons
                    if (AllPortsRadioButton?.IsChecked == true)
                        _currentPortScanMode = PortScanMode.All;
                    else if (RangePortsRadioButton?.IsChecked == true)
                        _currentPortScanMode = PortScanMode.Range;
                    else if (SelectedPortsRadioButton?.IsChecked == true)
                        _currentPortScanMode = PortScanMode.Selected;
                }
                else
                {
                    PortScanModePanel.IsVisible = false;
                    _currentPortScanMode = PortScanMode.None; // Simple scan - no ports
                }
            }
            
            // Update port details UI visibility
            UpdatePortDetailsVisibility();
        }
        
        private void PortScanMode_Changed(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            // Show/hide port range and selected ports panels based on selection
            if (PortRangePanel != null && SelectedPortsPanel != null)
            {
                if (RangePortsRadioButton?.IsChecked == true)
                {
                    PortRangePanel.IsVisible = true;
                    SelectedPortsPanel.IsVisible = false;
                    _currentPortScanMode = PortScanMode.Range;
                    
                    // Set default range to 1-65535 if text boxes are empty
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
                    PortRangePanel.IsVisible = false;
                    SelectedPortsPanel.IsVisible = true;
                    _currentPortScanMode = PortScanMode.Selected;
                    
                    // Show "Use Discovered Ports" button if we have discovered ports
                    if (PopulateFromScanButton != null)
                    {
                        PopulateFromScanButton.IsVisible = _discoveredPorts.Count > 0;
                    }
                }
                else if (AllPortsRadioButton?.IsChecked == true)
                {
                    PortRangePanel.IsVisible = false;
                    SelectedPortsPanel.IsVisible = false;
                    _currentPortScanMode = PortScanMode.All;
                }
            }
            
            // Update port details UI visibility
            UpdatePortDetailsVisibility();
        }
        
        private void UpdatePortDetailsVisibility()
        {
            // Show port details UI for All, Range, and Banner Grabbing modes
            // Hide for: Simple scan (None) only
            bool shouldShowPorts = _currentPortScanMode == PortScanMode.All || 
                                   _currentPortScanMode == PortScanMode.Range ||
                                   _currentPortScanMode == PortScanMode.Selected;
            
            // Hide/show the entire Port Details section (Border containing the DataGrid)
            var portsDetailsBorder = this.FindControl<Border>("PortsDetailsBorder");
            if (portsDetailsBorder != null)
            {
                portsDetailsBorder.Visibility = shouldShowPorts ? Visibility.Visible : Visibility.Collapsed;
            }
            
            // Also hide the DataGrid itself if needed
            if (PortsDataGrid != null)
            {
                PortsDataGrid.Visibility = shouldShowPorts ? Visibility.Visible : Visibility.Collapsed;
            }
        }
        
        private void PopulateFromScanButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            // Populate SelectedPortsTextBox with discovered ports from previous scans
            if (SelectedPortsTextBox != null && _discoveredPorts.Count > 0)
            {
                var sortedPorts = _discoveredPorts.OrderBy(p => p).ToList();
                SelectedPortsTextBox.Text = string.Join(",", sortedPorts);
            }
        }

        private void ResultsDataGrid_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (PortsDataGrid == null) return;

            if (ResultsDataGrid.SelectedItem is NetworkAsset selectedAsset)
            {
                // Populate ports DataGrid with ports from selected asset
                if (selectedAsset.OpenPorts != null && selectedAsset.OpenPorts.Count > 0)
                {
                    PortsDataGrid.ItemsSource = selectedAsset.OpenPorts.OrderBy(p => p.Port).ToList();
                    
                    // Update ports count text
                    if (PortsCountText != null)
                    {
                        PortsCountText.Text = $"({selectedAsset.OpenPorts.Count} port{(selectedAsset.OpenPorts.Count == 1 ? "" : "s")} from {selectedAsset.IpAddress})";
                        PortsCountText.Foreground = new SolidColorBrush(
                            Color.FromRgb(5, 150, 105)); // Green color
                    }
                }
                else
                {
                    PortsDataGrid.ItemsSource = null;
                    if (PortsCountText != null)
                    {
                        PortsCountText.Text = $"(No ports found for {selectedAsset.IpAddress})";
                        PortsCountText.Foreground = new SolidColorBrush(
                            Color.FromRgb(107, 114, 128)); // Gray color
                    }
                }
            }
            else
            {
                // When no asset is selected, show all ports from all assets
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
                        PortsCountText.Foreground = new SolidColorBrush(
                            Color.FromRgb(5, 150, 105)); // Green color
                    }
                }
                else
                {
                    PortsDataGrid.ItemsSource = null;
                    if (PortsCountText != null)
                    {
                        PortsCountText.Text = "(No ports found)";
                        PortsCountText.Foreground = new SolidColorBrush(
                            Color.FromRgb(107, 114, 128)); // Gray color
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
            
            // Pre-fill the range based on network and subnet mask
            CalculateAndSetDefaultRange(networkAddress, subnetMask);
            
            // Set default scan mode (simple)
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
                    
                    // Calculate network start
                    var networkStart = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        networkStart[i] = (byte)(networkBytes[i] & maskBytes[i]);
                    }
                    
                    // Calculate broadcast (end)
                    var broadcast = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        broadcast[i] = (byte)(networkStart[i] | ~maskBytes[i]);
                    }
                    
                    // Start IP (network + 1)
                    var startIp = new byte[4];
                    Array.Copy(networkStart, startIp, 4);
                    startIp[3] = (byte)(startIp[3] + 1);
                    
                    // End IP (broadcast - 1)
                    var endIp = new byte[4];
                    Array.Copy(broadcast, endIp, 4);
                    endIp[3] = (byte)(endIp[3] - 1);
                    
                    StartIpTextBox.Text = string.Join(".", startIp);
                    EndIpTextBox.Text = string.Join(".", endIp);
                }
            }
            catch
            {
                // If calculation fails, leave empty
            }
        }

        private void QuickRangeButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (sender is Button button && button.Tag is string tag)
            {
                switch (tag)
                {
                    case "full":
                        // Use the calculated default range
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

        private async void StartScanButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var startIp = StartIpTextBox.Text.Trim();
            var endIp = EndIpTextBox.Text.Trim();
            
            if (string.IsNullOrWhiteSpace(startIp) || string.IsNullOrWhiteSpace(endIp))
            {
                _ = ShowMessageAsync("Invalid Range", "Please enter both start and end IP addresses.");
                return;
            }
            
            if (!System.Net.IPAddress.TryParse(startIp, out _) || !System.Net.IPAddress.TryParse(endIp, out _))
            {
                _ = ShowMessageAsync("Invalid IP", "Please enter valid IP addresses.");
                return;
            }
            
            // Set scan mode
            bool intenseScan = IntenseScanRadioButton?.IsChecked == true;
            if (_networkScan != null)
            {
                _networkScan.SetScanMode(intenseScan);
                
                // Set port scan mode if intense scan is enabled
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
                        // Default to full range (1-65535) if not specified
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
                                // Default to full range if text boxes are empty or invalid
                                rangeStart = 1;
                                rangeEnd = 65535;
                            }
                        }
                        else
                        {
                            // Default to full range if text boxes don't exist
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
                
                // Update port details UI visibility based on scan mode
                UpdatePortDetailsVisibility();
            }
            
            // Hide range config panel and show progress section
            RangeConfigPanel.IsVisible = false;
            StartScanButton.IsEnabled = false;
            
            // Ensure progress section is visible
            var progressSection = this.FindControl<Control>("ProgressSection");
            if (progressSection != null)
            {
                progressSection.IsVisible = true;
            }
            
            await StartCustomRangeScanAsync(startIp, endIp);
        }

        private async Task StartCustomRangeScanAsync(string startIp, string endIp)
        {
            try
            {
                if (string.IsNullOrEmpty(startIp) || string.IsNullOrEmpty(endIp))
                {
                    _ = ShowMessageAsync("Invalid Input", "Start IP and End IP are required.");
                    return;
                }
                
                if (_networkScan == null)
                {
                    _ = ShowMessageAsync("Error", "Network scan instance is not initialized.");
                    return;
                }
                
                _cancellationTokenSource = new CancellationTokenSource();
                
                // Show loading UI immediately and ensure visibility
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        if (LoadingIndicator != null)
                            LoadingIndicator.IsVisible = true;
                        if (CancelScanButton != null)
                            CancelScanButton.IsVisible = true;
                        if (BackButton != null)
                            BackButton.IsVisible = false;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = false;
                        if (ExportExcelButton != null)
                            ExportExcelButton.IsEnabled = false;
                        
                        // Ensure progress section is visible
                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.IsVisible = true;
                            StatusTextBlock.Text = "Initializing scan...";
                            StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39));
                        }
                        if (ProgressTextBlock != null)
                        {
                            ProgressTextBlock.IsVisible = true;
                            ProgressTextBlock.Text = "0 / 0";
                        }
                        if (ScanProgressBar != null)
                        {
                            ScanProgressBar.IsVisible = true;
                            ScanProgressBar.Value = 0;
                            ScanProgressBar.Maximum = 100;
                        }
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.IsVisible = true;
                            CurrentIpTextBlock.Text = "Preparing scan...";
                            CurrentIpTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(156, 163, 175));
                        }
                        if (FoundCountTextBlock != null)
                        {
                            FoundCountTextBlock.IsVisible = true;
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
                });
                
                // Small delay to ensure UI is updated before starting scan
                await Task.Delay(150);
                
                // Reset scan completed flag
                _scanCompleted = false;
                
                // Create progress reporter that updates the DataGrid in real-time
                var progress = new Progress<ScanProgress>(UpdateProgress);
                
                _assets = await _networkScan.ScanNetworkByRangeAsync(startIp, endIp, _cancellationTokenSource.Token, progress);
                
                // Mark scan as completed before updating UI
                _scanCompleted = true;
                
                // Wait a moment to ensure all pending progress updates are processed
                await Task.Delay(100);
                
                // Collect all discovered ports from all assets for Banner Grabbing mode auto-population
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
                
                // Save assets to database
                if (_databaseService != null && _assets.Count > 0)
                {
                    await SaveAssetsToDatabaseAsync();
                }
                
                // Final refresh to ensure all items are displayed
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        // Copy all assets to _foundAssets for display
                        if (_assets != null && _assets.Count > 0)
                        {
                            _foundAssets.Clear();
                            var allPorts = new List<Models.OpenPort>();
                            
                            foreach (var asset in _assets)
                            {
                                _foundAssets.Add(asset);
                                
                                // Collect all ports from all assets for auto-display
                                if (asset.OpenPorts != null && asset.OpenPorts.Count > 0)
                                {
                                    allPorts.AddRange(asset.OpenPorts);
                                }
                            }
                            
                            // Auto-display all ports from all assets in the ports table
                            // Show ports if we're in All, Range, or Banner Grabbing mode
                            if ((_currentPortScanMode == PortScanMode.All || _currentPortScanMode == PortScanMode.Range || _currentPortScanMode == PortScanMode.Selected) && PortsDataGrid != null && allPorts.Count > 0)
                            {
                                PortsDataGrid.ItemsSource = allPorts.OrderBy(p => p.Port).ToList();
                                
                                // Update ports count text
                                if (PortsCountText != null)
                                {
                                    PortsCountText.Text = $"({allPorts.Count} port{(allPorts.Count == 1 ? "" : "s")} from {_assets.Count(a => a.OpenPorts != null && a.OpenPorts.Count > 0)} device{(allPorts.Count == 1 ? "" : "s")})";
                                    PortsCountText.Foreground = new SolidColorBrush(
                                        Color.FromRgb(5, 150, 105)); // Green color
                                }
                            }
                            else if (PortsDataGrid != null)
                            {
                                PortsDataGrid.ItemsSource = null;
                                if (PortsCountText != null)
                                {
                                    PortsCountText.Text = "(No ports found)";
                                    PortsCountText.Foreground = new SolidColorBrush(
                                        Color.FromRgb(107, 114, 128)); // Gray color
                                }
                            }
                            
                            // Update port details UI visibility after scan completes
                            UpdatePortDetailsVisibility();
                            
                            // Auto-select first asset with ports
                            var firstAssetWithPorts = _foundAssets.FirstOrDefault(a => a.OpenPorts != null && a.OpenPorts.Count > 0);
                            if (firstAssetWithPorts != null && ResultsDataGrid != null)
                            {
                                ResultsDataGrid.SelectedItem = firstAssetWithPorts;
                                ResultsDataGrid.ScrollIntoView(firstAssetWithPorts);
                            }
                        }
                        
                        // Update the "Use Discovered Ports" button visibility if Banner Grabbing mode is active
                        if (PopulateFromScanButton != null && SelectedPortsRadioButton?.IsChecked == true)
                        {
                            PopulateFromScanButton.IsVisible = _discoveredPorts.Count > 0;
                        }
                        
                        // Update the DataGrid items source to ensure it's bound correctly
                        if (ResultsDataGrid != null)
                        {
                            ResultsDataGrid.ItemsSource = null; // Clear first
                            ResultsDataGrid.ItemsSource = _foundAssets; // Rebind
                            ResultsDataGrid.ItemsSource = null;
                            ResultsDataGrid.ItemsSource = _foundAssets;
                        }
                        
                        // Clear progress indicators and show completion message
                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Text = $"✅ Scan Complete! Found {(_assets?.Count ?? 0)} active device(s).";
                            StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(5, 150, 105));
                        }
                        if (ProgressTextBlock != null)
                            ProgressTextBlock.Text = "Done";
                        if (ScanProgressBar != null)
                            ScanProgressBar.Value = ScanProgressBar.Maximum;
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Text = "Scan finished successfully.";
                            CurrentIpTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(5, 150, 105));
                        }
                        
                        // Update found count display
                        if (FoundCountTextBlock != null)
                        {
                            FoundCountTextBlock.Text = (_assets?.Count ?? 0).ToString();
                        }
                        
                        if (ExportExcelButton != null)
                            ExportExcelButton.IsEnabled = _assets != null && _assets.Count > 0;
                        
                        // Hide loading UI and show back button
                        if (LoadingIndicator != null)
                            LoadingIndicator.IsVisible = false;
                        if (CancelScanButton != null)
                            CancelScanButton.IsVisible = false;
                        if (BackButton != null)
                            BackButton.IsVisible = true;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = true;
                        
                        // Update sync status
                        if (_supabaseSyncService != null)
                        {
                            _ = Task.Run(async () => await UpdateAssetsSyncStatus());
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error in final UI update: {ex.Message}");
                    }
                });
            }
            catch (OperationCanceledException)
            {
                _scanCompleted = true;
                await Task.Delay(100); // Wait for pending progress updates
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Text = "⚠️ Scan Cancelled";
                            StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11));
                        }
                        if (ProgressTextBlock != null)
                            ProgressTextBlock.Text = "Cancelled";
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Text = "Scan was cancelled by user.";
                            CurrentIpTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(107, 114, 128));
                        }
                        if (LoadingIndicator != null)
                            LoadingIndicator.IsVisible = false;
                        if (CancelScanButton != null)
                            CancelScanButton.IsVisible = false;
                        if (BackButton != null)
                            BackButton.IsVisible = true;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = true;
                    }
                    catch (Exception uiEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error updating UI on cancel: {uiEx.Message}");
                    }
                });
            }
            catch (Exception ex)
            {
                _scanCompleted = true;
                await Task.Delay(100); // Wait for pending progress updates
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        if (StatusTextBlock != null)
                        {
                            StatusTextBlock.Text = $"❌ Scan Failed: {ex.Message}";
                            StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                        }
                        if (ProgressTextBlock != null)
                            ProgressTextBlock.Text = "Failed";
                        if (CurrentIpTextBlock != null)
                        {
                            CurrentIpTextBlock.Text = $"Error: {ex.Message}";
                            CurrentIpTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                        }
                        if (LoadingIndicator != null)
                            LoadingIndicator.IsVisible = false;
                        if (CancelScanButton != null)
                            CancelScanButton.IsVisible = false;
                        if (BackButton != null)
                            BackButton.IsVisible = true;
                        if (CloseButton != null)
                            CloseButton.IsEnabled = true;
                        _ = ShowMessageAsync("Error", $"Network scan failed: {ex.Message}\n\nStack trace: {ex.StackTrace}");
                    }
                    catch (Exception uiEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error updating UI on error: {uiEx.Message}");
                        _ = ShowMessageAsync("Error", $"Network scan failed: {ex.Message}");
                    }
                });
            }
        }

        private void UpdateProgress(ScanProgress progress)
        {
            try
            {
                if (progress == null)
                    return;
                    
                // Don't update if scan is already completed
                if (_scanCompleted)
                    return;

                // Use InvokeAsync for better performance and responsiveness
                _ = Dispatcher.UIThread.InvokeAsync(() =>
                {
                    try
                    {
                        // Don't update if scan completed while this was queued
                        if (_scanCompleted)
                            return;

                        // Handle port scanning progress first (takes priority)
                        if (progress.IsPortScanning && !string.IsNullOrEmpty(progress.PortScanIp))
                        {
                            // Show port scanning indicator
                            if (LoadingIndicator != null)
                            {
                                LoadingIndicator.IsVisible = true;
                            }
                            
                            // Update status to show port scanning
                            if (StatusTextBlock != null)
                            {
                                StatusTextBlock.Text = $"Scanning ports on {progress.PortScanIp}...";
                                StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(37, 99, 235)); // Blue
                            }
                            
                            // Update current IP text to show port scanning progress
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
                                CurrentIpTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(37, 99, 235)); // Blue
                            }
                            
                            // Update progress bar for port scanning
                            if (ScanProgressBar != null && progress.TotalPorts > 0)
                            {
                                ScanProgressBar.Maximum = progress.TotalPorts;
                                ScanProgressBar.Value = progress.PortsScanned;
                            }
                            
                            // Add newly found port to DataGrid in real-time
                            if (progress.NewPort != null)
                            {
                                // Find the asset for this IP and add the port
                                var asset = _foundAssets.FirstOrDefault(a => a.IpAddress == progress.PortScanIp);
                                if (asset != null)
                                {
                                    // Add port to asset if not already present
                                    if (asset.OpenPorts == null)
                                        asset.OpenPorts = new List<Models.OpenPort>();
                                    
                                    if (!asset.OpenPorts.Any(p => p.Port == progress.NewPort.Port && p.Protocol == progress.NewPort.Protocol))
                                    {
                                        asset.OpenPorts.Add(progress.NewPort);
                                        asset.OpenPorts = asset.OpenPorts.OrderBy(p => p.Port).ToList();
                                        
                                        // Track discovered ports for Banner Grabbing mode auto-population
                                        _discoveredPorts.Add(progress.NewPort.Port);
                                        
                                        // Update the asset in the list
                                        ResultsDataGrid.ItemsSource = null;
                            ResultsDataGrid.ItemsSource = _foundAssets;
                                        
                                        // Update ports DataGrid if this asset is selected or if we're showing all ports
                                        if (PortsDataGrid != null && 
                                            (_currentPortScanMode == PortScanMode.Common || 
                                             _currentPortScanMode == PortScanMode.All || 
                                             _currentPortScanMode == PortScanMode.Range || 
                                             _currentPortScanMode == PortScanMode.Selected))
                                        {
                                            // Refresh ports DataGrid with all ports from all assets
                                            var allPorts = _foundAssets
                                                .Where(a => a.OpenPorts != null && a.OpenPorts.Count > 0)
                                                .SelectMany(a => a.OpenPorts)
                                                .OrderBy(p => p.Port)
                                                .ToList();
                                            
                                            PortsDataGrid.ItemsSource = allPorts;
                                            PortsDataGrid.ItemsSource = null;
                                            PortsDataGrid.ItemsSource = allPorts;
                                            
                                            // Update ports count text
                                            if (PortsCountText != null)
                                            {
                                                var deviceCount = _foundAssets.Count(a => a.OpenPorts != null && a.OpenPorts.Count > 0);
                                                PortsCountText.Text = $"({allPorts.Count} port{(allPorts.Count == 1 ? "" : "s")} from {deviceCount} device{(deviceCount == 1 ? "" : "s")})";
                                                PortsCountText.Foreground = new SolidColorBrush(
                                                    Color.FromRgb(5, 150, 105)); // Green color
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            // Normal host scanning (not port scanning)
                            // Reset status text color to default during scanning
                            if (StatusTextBlock != null)
                            {
                                StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39)); // Default dark gray
                                StatusTextBlock.Text = $"Scanning network...";
                            }
                            
                            if (CurrentIpTextBlock != null)
                            {
                                CurrentIpTextBlock.Text = $"Scanning: {progress.CurrentIp ?? "..."}";
                                CurrentIpTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(156, 163, 175)); // Default light gray
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
                            
                            // Add newly found asset to DataGrid in real-time
                            if (progress.NewAsset != null && ResultsDataGrid != null)
                            {
                                _foundAssets.Add(progress.NewAsset);
                                
                                // Track discovered ports for Selected mode auto-population
                                if (progress.NewAsset.OpenPorts != null && progress.NewAsset.OpenPorts.Count > 0)
                                {
                                    foreach (var openPort in progress.NewAsset.OpenPorts)
                                    {
                                        _discoveredPorts.Add(openPort.Port);
                                    }
                                }
                                
                                ResultsDataGrid.ItemsSource = null;
                            ResultsDataGrid.ItemsSource = _foundAssets;
                                
                                // Auto-scroll to the newest item
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
                });
            }
            catch
            {
                // Ignore UI update errors
            }
        }

        private void CancelScanButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
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
                    // Generate ports display string from OpenPorts
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
                        // Keep "Unknown" as string for display purposes (don't convert to null)
                        HostName = string.IsNullOrEmpty(asset.Name) ? null : (asset.Name == "Unknown" ? "Unknown" : asset.Name),
                        MacAddress = string.IsNullOrEmpty(asset.MacAddress) ? null : (asset.MacAddress == "Unknown" ? "Unknown" : asset.MacAddress),
                        Vendor = string.IsNullOrEmpty(asset.Vendor) ? null : (asset.Vendor == "Unknown" ? "Unknown" : asset.Vendor),
                        IsOnline = asset.IsReachable,
                        PingTime = asset.RoundTripTime.HasValue ? (int)asset.RoundTripTime.Value : null,
                        ScanTime = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Synced = false,
                        Ports = portsDisplay, // Store ports display string in assets table
                        // Metadata for audit tracking
                        HardwareId = _hardwareId,
                        MachineName = _machineName,
                        Username = _username,
                        UserId = null // Can be set if user authentication is implemented
                    };

                    var assetId = await _databaseService.SaveAssetAsync(assetEntry);

                    // Save ports separately - ensure ALL port data is saved including banners
                    // When ports are added/updated, the asset is automatically marked as unsynced
                    if (asset.OpenPorts != null && asset.OpenPorts.Count > 0)
                    {
                        foreach (var openPort in asset.OpenPorts)
                        {
                            var portEntry = new Models.Database.PortEntry
                            {
                                AssetId = assetId,
                                HostIp = asset.IpAddress,
                                Port = openPort.Port,
                                Protocol = openPort.Protocol ?? "TCP", // Default to TCP if null
                                Service = string.IsNullOrWhiteSpace(openPort.Service) ? null : openPort.Service.Trim(),
                                Banner = string.IsNullOrWhiteSpace(openPort.Banner) ? null : openPort.Banner.Trim(), // Save banner if it exists
                                ScanTime = DateTime.UtcNow,
                                CreatedAt = DateTime.UtcNow,
                                Synced = false,
                                // Metadata for audit tracking
                                HardwareId = _hardwareId,
                                MachineName = _machineName,
                                Username = _username,
                                UserId = null
                            };

                            try
                            {
                                // SavePortAsync will automatically mark the asset as unsynced when ports are added/updated
                                await _databaseService.SavePortAsync(portEntry, markAssetUnsynced: true);
                            }
                            catch (Exception portEx)
                            {
                                _attackLogger.LogError($"Failed to save port {openPort.Port} for {asset.IpAddress}: {portEx.Message}");
                                // Continue saving other ports even if one fails
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

        private async Task UpdateAssetsSyncStatus()
        {
            if (_supabaseSyncService == null) return;

            try
            {
                var pendingCount = await _supabaseSyncService.GetPendingAssetsCountAsync();
                
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (pendingCount > 0)
                    {
                        AssetsSyncBadge.IsVisible = true;
                        AssetsSyncBadgeText.Text = pendingCount > 99 ? "99+" : pendingCount.ToString();
                        SyncAssetsButton.ToolTip = $"{pendingCount} asset(s) pending sync - Click to sync";
                    }
                    else
                    {
                        AssetsSyncBadge.IsVisible = false;
                        SyncAssetsButton.ToolTip = "Sync assets to cloud";
                    }
                });
            }
            catch (Exception ex)
            {
                // Ignore errors
            }
        }

        private async void SyncAssetsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (_databaseService == null || _supabaseSyncService == null)
            {
                await ShowMessageAsync("Error", "Database services are not available.");
                return;
            }

            try
            {
                if (!_supabaseSyncService.IsConfigured)
                {
                    await ShowMessageAsync("Not Configured", "Supabase is not configured. Please configure it in Settings first.");
                    return;
                }

                var unsyncedAssets = await _databaseService.GetUnsyncedAssetsAsync();
                if (unsyncedAssets == null || unsyncedAssets.Count == 0)
                {
                    await ShowMessageAsync("No Pending Assets", "No pending assets to sync.");
                    return;
                }

                // Create sync window for assets
                var syncWindow = new AssetSyncWindow(unsyncedAssets)
                {
                    Owner = this
                };

                var dialogResult = await syncWindow.ShowDialog<bool?>(this);
                if (dialogResult == true && syncWindow.ShouldSync)
                {
                    // Delete selected assets if any
                    if (syncWindow.DeletedIds.Count > 0)
                    {
                        await _databaseService.DeleteAssetsAsync(syncWindow.DeletedIds);
                        _attackLogger.LogInfo($"Deleted {syncWindow.DeletedIds.Count} asset(s).");
                    }

                    // Sync selected assets
                    if (syncWindow.SelectedIds.Count > 0)
                    {
                        SyncAssetsButton.IsEnabled = false;
                        var originalTooltip = SyncAssetsButton.ToolTip;

                        var result = await _supabaseSyncService.SyncAssetsAsync(syncWindow.ProjectName, syncWindow.SelectedIds);

                        if (result.Success)
                        {
                            _attackLogger.LogSuccess(result.Message);
                            if (result.SyncedCount > 0)
                            {
                                await ShowMessageAsync("Sync Successful", $"Sync complete – {result.SyncedCount} asset(s) synced successfully.");
                                _ = Task.Run(async () => await UpdateAssetsSyncStatus());
                            }
                        }
                        else
                        {
                            _attackLogger.LogWarning(result.Message);
                            await ShowMessageAsync("Sync Warning", result.Message);
                        }

                        SyncAssetsButton.IsEnabled = true;
                        SyncAssetsButton.ToolTip = originalTooltip;
                    }

                    // Update sync status
                    _ = Task.Run(async () => await UpdateAssetsSyncStatus());
                }
            }
            catch (Exception ex)
            {
                _attackLogger.LogError($"Asset sync failed: {ex.Message}");
                await ShowMessageAsync("Error", $"Asset sync failed: {ex.Message}");
            }
        }

        private async Task ShowMessageAsync(string title, string message)
        {
            var msgBox = new Window
            {
                Title = title,
                Content = new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                Width = 400,
                Height = 200,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            };
            await msgBox.ShowDialog(this);
        }

        private async void ExportExcelButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                var fileName = await FileDialogHelper.ShowSaveFileDialogAsync(
                    this,
                    "Export Network Scan Results",
                    $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx",
                    "xlsx",
                    new[] { ("Excel Files", new[] { "*.xlsx" }), ("All Files", new[] { "*.*" }) });

                if (!string.IsNullOrEmpty(fileName))
                {
                    ExportToExcel(fileName);
                    var msgBox = new Window
                    {
                        Title = "Export Successful",
                        Content = new TextBlock { Text = $"Network scan results exported to:\n{fileName}" },
                        Width = 500,
                        Height = 200,
                        WindowStartupLocation = WindowStartupLocation.CenterOwner
                    };
                    await msgBox.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                var msgBox = new Window
                {
                    Title = "Export Error",
                    Content = new TextBlock { Text = $"Failed to export to Excel: {ex.Message}" },
                    Width = 400,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
            }
        }

        private void ExportToExcel(string filePath)
        {
            using var workbook = new XLWorkbook();
            var worksheet = workbook.Worksheets.Add("Network Assets");

            // Add headers
            worksheet.Cell(1, 1).Value = "IP Address";
            worksheet.Cell(1, 2).Value = "MAC Address";
            worksheet.Cell(1, 3).Value = "Name";
            worksheet.Cell(1, 4).Value = "Vendor";
            worksheet.Cell(1, 5).Value = "Status";
            worksheet.Cell(1, 6).Value = "Round Trip Time (ms)";
            worksheet.Cell(1, 7).Value = "Open Ports";
            worksheet.Cell(1, 8).Value = "Port Details";

            // Style headers
            var headerRange = worksheet.Range(1, 1, 1, 8);
            headerRange.Style.Font.Bold = true;
            headerRange.Style.Fill.BackgroundColor = XLColor.LightGray;
            headerRange.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;

            // Add data
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
                
                // Port details (one port per line)
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

            // Auto-fit columns
            worksheet.Columns().AdjustToContents();

            // Add summary sheet
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

        private async void BackButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            
            // Restore the initial state - show configuration panel, hide results
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                try
                {
                    // Show the scan configuration panel
                    if (RangeConfigPanel != null)
                        RangeConfigPanel.IsVisible = true;
                    
                    // Re-enable the start scan button
                    if (StartScanButton != null)
                        StartScanButton.IsEnabled = true;
                    
                    // Hide the back button (only show after scan completes)
                    if (BackButton != null)
                        BackButton.IsVisible = false;
                    
                    // Reset progress indicators
                    if (StatusTextBlock != null)
                    {
                        StatusTextBlock.Text = "Ready to scan";
                        StatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39));
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
                        LoadingIndicator.IsVisible = false;
                    if (CancelScanButton != null)
                        CancelScanButton.IsVisible = false;
                    
                    // Clear the results
                    _foundAssets.Clear();
                    if (ResultsDataGrid != null)
                    {
                        ResultsDataGrid.ItemsSource = null;
                        ResultsDataGrid.ItemsSource = _foundAssets;
                    }
                    
                    // Clear ports DataGrid
                    if (PortsDataGrid != null)
                    {
                        PortsDataGrid.ItemsSource = null;
                    }
                    
                    // Disable export button
                    if (ExportExcelButton != null)
                        ExportExcelButton.IsEnabled = false;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error in BackButton_Click: {ex.Message}");
                }
            });
        }

        private void CloseButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }

        protected override void OnClosing(WindowClosingEventArgs e)
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


