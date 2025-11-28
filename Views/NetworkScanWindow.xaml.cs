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
        private readonly SupabaseSyncService? _supabaseSyncService;
        private List<NetworkAsset> _assets = new List<NetworkAsset>();
        private CancellationTokenSource? _cancellationTokenSource;
        private readonly List<NetworkAsset> _foundAssets = new List<NetworkAsset>();

        private string _networkAddress = string.Empty;
        private string _subnetMask = string.Empty;

        public NetworkScanWindow(NetworkScan networkScan, AttackLogger attackLogger, DatabaseService? databaseService = null, SupabaseSyncService? supabaseSyncService = null)
        {
            InitializeComponent();
            _networkScan = networkScan;
            _attackLogger = attackLogger;
            _databaseService = databaseService;
            _supabaseSyncService = supabaseSyncService;
            
            // Show/hide sync button based on availability
            if (_databaseService == null || _supabaseSyncService == null)
            {
                SyncAssetsButton.Visibility = Visibility.Collapsed;
            }
            else
            {
                _ = Task.Run(async () => await UpdateAssetsSyncStatus());
            }
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

        private void QuickRangeButton_Click(object sender, RoutedEventArgs e)
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
            
            // Set scan mode
            bool intenseScan = IntenseScanRadioButton.IsChecked == true;
            _networkScan.SetScanMode(intenseScan);
            
            // Hide range config panel and show progress section
            RangeConfigPanel.Visibility = Visibility.Collapsed;
            StartScanButton.IsEnabled = false;
            
            // Ensure progress section is visible
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
                _cancellationTokenSource = new CancellationTokenSource();
                
                // Show loading UI immediately and ensure visibility
                Dispatcher.Invoke(() =>
                {
                    LoadingIndicator.Visibility = Visibility.Visible;
                    CancelScanButton.Visibility = Visibility.Visible;
                    CloseButton.IsEnabled = false;
                    ExportExcelButton.IsEnabled = false;
                    
                    // Ensure progress section is visible
                    StatusTextBlock.Visibility = Visibility.Visible;
                    ProgressTextBlock.Visibility = Visibility.Visible;
                    ScanProgressBar.Visibility = Visibility.Visible;
                    CurrentIpTextBlock.Visibility = Visibility.Visible;
                    FoundCountTextBlock.Visibility = Visibility.Visible;
                    
                    StatusTextBlock.Text = "Initializing scan...";
                    StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 24, 39)); // Default dark gray
                    ScanProgressBar.Value = 0;
                    ScanProgressBar.Maximum = 100;
                    CurrentIpTextBlock.Text = "Preparing scan...";
                    CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(156, 163, 175)); // Default light gray
                    FoundCountTextBlock.Text = "0";
                    ProgressTextBlock.Text = "0 / 0";
                    
                    _foundAssets.Clear();
                    ResultsDataGrid.ItemsSource = _foundAssets;
                }, System.Windows.Threading.DispatcherPriority.Send);
                
                // Small delay to ensure UI is updated before starting scan
                await Task.Delay(150);
                
                // Create progress reporter that updates the DataGrid in real-time
                var progress = new Progress<ScanProgress>(UpdateProgress);
                
                _assets = await _networkScan.ScanNetworkByRangeAsync(startIp, endIp, _cancellationTokenSource.Token, progress);
                
                // Save assets to database
                if (_databaseService != null && _assets.Count > 0)
                {
                    await SaveAssetsToDatabaseAsync();
                }
                
                // Final refresh to ensure all items are displayed
                Dispatcher.Invoke(() =>
                {
                    ResultsDataGrid.Items.Refresh();
                    
                    // Clear progress indicators and show completion message
                    StatusTextBlock.Text = $"✅ Scan Complete! Found {_assets.Count} active device(s).";
                    StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(5, 150, 105)); // Green color
                    ProgressTextBlock.Text = "Done";
                    ScanProgressBar.Value = ScanProgressBar.Maximum; // Fill progress bar to 100%
                    CurrentIpTextBlock.Text = "Scan finished successfully.";
                    CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(5, 150, 105));
                    
                    ExportExcelButton.IsEnabled = _assets.Count > 0;
                    
                    // Hide loading UI
                    LoadingIndicator.Visibility = Visibility.Collapsed;
                    CancelScanButton.Visibility = Visibility.Collapsed;
                    CloseButton.IsEnabled = true;
                    
                    // Update sync status
                    if (_supabaseSyncService != null)
                    {
                        _ = Task.Run(async () => await UpdateAssetsSyncStatus());
                    }
                });
            }
            catch (OperationCanceledException)
            {
                Dispatcher.Invoke(() =>
                {
                    StatusTextBlock.Text = "⚠️ Scan Cancelled";
                    StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 158, 11)); // Orange color
                    ProgressTextBlock.Text = "Cancelled";
                    CurrentIpTextBlock.Text = "Scan was cancelled by user.";
                    CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(107, 114, 128)); // Gray color
                    LoadingIndicator.Visibility = Visibility.Collapsed;
                    CancelScanButton.Visibility = Visibility.Collapsed;
                    CloseButton.IsEnabled = true;
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    StatusTextBlock.Text = $"❌ Scan Failed: {ex.Message}";
                    StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 68, 68)); // Red color
                    ProgressTextBlock.Text = "Failed";
                    CurrentIpTextBlock.Text = $"Error: {ex.Message}";
                    CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 68, 68));
                    LoadingIndicator.Visibility = Visibility.Collapsed;
                    CancelScanButton.Visibility = Visibility.Collapsed;
                    CloseButton.IsEnabled = true;
                    MessageBox.Show($"Network scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                });
            }
        }

        private void UpdateProgress(ScanProgress progress)
        {
            try
            {
                // Use BeginInvoke for better performance and responsiveness
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    // Reset status text color to default during scanning
                    StatusTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(17, 24, 39)); // Default dark gray
                    CurrentIpTextBlock.Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(156, 163, 175)); // Default light gray
                    
                    StatusTextBlock.Text = $"Scanning network...";
                    ProgressTextBlock.Text = $"{progress.Scanned} / {progress.Total}";
                    
                    if (progress.Total > 0)
                    {
                        ScanProgressBar.Maximum = progress.Total;
                        ScanProgressBar.Value = progress.Scanned;
                    }
                    
                    CurrentIpTextBlock.Text = $"Scanning: {progress.CurrentIp}";
                    FoundCountTextBlock.Text = progress.Found.ToString();
                    
                    // Add newly found asset to DataGrid in real-time
                    if (progress.NewAsset != null)
                    {
                        _foundAssets.Add(progress.NewAsset);
                        ResultsDataGrid.Items.Refresh();
                        
                        // Auto-scroll to the newest item
                        if (ResultsDataGrid.Items.Count > 0)
                        {
                            ResultsDataGrid.ScrollIntoView(ResultsDataGrid.Items[ResultsDataGrid.Items.Count - 1]);
                        }
                    }
                }), System.Windows.Threading.DispatcherPriority.Normal);
            }
            catch
            {
                // Ignore UI update errors
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
                    var assetEntry = new Models.Database.AssetEntry
                    {
                        HostIp = asset.IpAddress,
                        HostName = string.IsNullOrEmpty(asset.Hostname) || asset.Hostname == "Unknown" ? null : asset.Hostname,
                        MacAddress = string.IsNullOrEmpty(asset.MacAddress) || asset.MacAddress == "Unknown" ? null : asset.MacAddress,
                        Vendor = string.IsNullOrEmpty(asset.Vendor) || asset.Vendor == "Unknown" ? null : asset.Vendor,
                        IsOnline = asset.IsReachable,
                        PingTime = asset.RoundTripTime.HasValue ? (int)asset.RoundTripTime.Value : null,
                        ScanTime = DateTime.UtcNow,
                        CreatedAt = DateTime.UtcNow,
                        Synced = false
                    };

                    await _databaseService.SaveAssetAsync(assetEntry);
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
                
                Dispatcher.Invoke(() =>
                {
                    if (pendingCount > 0)
                    {
                        AssetsSyncBadge.Visibility = Visibility.Visible;
                        AssetsSyncBadgeText.Text = pendingCount > 99 ? "99+" : pendingCount.ToString();
                        SyncAssetsButton.ToolTip = $"{pendingCount} asset(s) pending sync - Click to sync";
                    }
                    else
                    {
                        AssetsSyncBadge.Visibility = Visibility.Collapsed;
                        SyncAssetsButton.ToolTip = "Sync assets to cloud";
                    }
                });
            }
            catch (Exception ex)
            {
                // Ignore errors
            }
        }

        private async void SyncAssetsButton_Click(object sender, RoutedEventArgs e)
        {
            if (_databaseService == null || _supabaseSyncService == null)
            {
                MessageBox.Show("Database services are not available.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                if (!_supabaseSyncService.IsConfigured)
                {
                    MessageBox.Show("Supabase is not configured. Please configure it in Settings first.", "Not Configured", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var unsyncedAssets = await _databaseService.GetUnsyncedAssetsAsync();
                if (unsyncedAssets == null || unsyncedAssets.Count == 0)
                {
                    MessageBox.Show("No pending assets to sync.", "No Pending Assets", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                // Create sync window for assets
                var syncWindow = new AssetSyncWindow(unsyncedAssets)
                {
                    Owner = this
                };

                if (syncWindow.ShowDialog() == true && syncWindow.ShouldSync)
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
                                MessageBox.Show($"Sync complete – {result.SyncedCount} asset(s) synced successfully.", "Sync Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                                _ = Task.Run(async () => await UpdateAssetsSyncStatus());
                            }
                        }
                        else
                        {
                            _attackLogger.LogWarning(result.Message);
                            MessageBox.Show(result.Message, "Sync Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                MessageBox.Show($"Asset sync failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
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

            // Add headers
            worksheet.Cell(1, 1).Value = "IP Address";
            worksheet.Cell(1, 2).Value = "MAC Address";
            worksheet.Cell(1, 3).Value = "Hostname";
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
                worksheet.Cell(row, 3).Value = asset.Hostname;
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
}

