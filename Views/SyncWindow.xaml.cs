using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Dorothy.Models.Database;

namespace Dorothy.Views
{
    public partial class SyncWindow : Window
    {
        // FindControl properties for XAML-named controls
        private DataGrid? LogsDataGrid => this.FindControl<DataGrid>("LogsDataGrid");
        private DataGrid? AssetsDataGrid => this.FindControl<DataGrid>("AssetsDataGrid");
        private DataGrid? ReachabilityTestsDataGrid => this.FindControl<DataGrid>("ReachabilityTestsDataGrid");
        private DataGrid? SnmpWalkTestsDataGrid => this.FindControl<DataGrid>("SnmpWalkTestsDataGrid");
        private TextBlock? LogsCountText => this.FindControl<TextBlock>("LogsCountText");
        private TextBlock? AssetsCountText => this.FindControl<TextBlock>("AssetsCountText");
        private TextBlock? ReachabilityTestsCountText => this.FindControl<TextBlock>("ReachabilityTestsCountText");
        private TextBlock? SnmpWalkTestsCountText => this.FindControl<TextBlock>("SnmpWalkTestsCountText");
        private TabItem? LogsTab => this.FindControl<TabItem>("LogsTab");
        private TabItem? AssetsTab => this.FindControl<TabItem>("AssetsTab");
        private TabItem? ReachabilityTestsTab => this.FindControl<TabItem>("ReachabilityTestsTab");
        private TabItem? SnmpWalkTestsTab => this.FindControl<TabItem>("SnmpWalkTestsTab");
        private TabControl? SyncTabControl => this.FindControl<TabControl>("SyncTabControl");
        private CheckBox? EnhanceDataCheckBox => this.FindControl<CheckBox>("EnhanceDataCheckBox");

        public string? ProjectName { get; private set; }
        public List<long> SelectedLogIds { get; private set; } = new();
        public List<long> SelectedAssetIds { get; private set; } = new();
        public List<long> SelectedTestIds { get; private set; } = new();
        public List<long> SelectedSnmpWalkIds { get; private set; } = new();
        public List<long> DeletedLogIds { get; private set; } = new();
        public List<long> DeletedAssetIds { get; private set; } = new();
        public List<long> DeletedTestIds { get; private set; } = new();
        public List<long> DeletedSnmpWalkIds { get; private set; } = new();
        public bool ShouldSync { get; private set; }
        public bool EnhanceData { get; private set; }

        private List<LogItem> _logItems = new();
        private List<AssetItem> _assetItems = new();
        private List<TestItem> _testItems = new();
        private List<TestItem> _snmpWalkItems = new();

        public SyncWindow(List<AttackLogEntry> logs, List<AssetEntry> assets, List<ReachabilityTestEntry> tests)
        {
            AvaloniaXamlLoader.Load(this);
            
            // Convert logs to LogItem for binding
            _logItems = logs.Select(log => new LogItem
            {
                Id = log.Id,
                AttackType = log.AttackType,
                Protocol = log.Protocol,
                TargetIp = log.TargetIp,
                PacketsSent = log.PacketsSent,
                StartTime = log.StartTime,
                ProjectName = log.ProjectName ?? "None",
                IsSelected = true // Default to selected
            }).ToList();

            // Convert assets to AssetItem for binding
            _assetItems = assets.Select(asset => new AssetItem
            {
                Id = asset.Id,
                HostIp = asset.HostIp,
                HostName = string.IsNullOrWhiteSpace(asset.HostName) ? "Unknown" : asset.HostName,
                MacAddress = string.IsNullOrWhiteSpace(asset.MacAddress) ? "Unknown" : asset.MacAddress,
                Vendor = string.IsNullOrWhiteSpace(asset.Vendor) ? "Unknown" : asset.Vendor,
                IsOnline = asset.IsOnline,
                ScanTime = asset.ScanTime,
                OpenPortsDisplay = string.IsNullOrWhiteSpace(asset.Ports) ? "N/A" : asset.Ports, // Use Ports column from database
                IsSelected = true // Default to selected
            }).ToList();

            // Separate SNMP walk tests from regular reachability tests
            var snmpWalkTests = tests.Where(t => t.VantagePointName == "SNMP Walk").ToList();
            var regularTests = tests.Where(t => t.VantagePointName != "SNMP Walk").ToList();

            // Convert regular tests to TestItem for binding
            _testItems = regularTests.Select(test => new TestItem
            {
                Id = test.Id,
                AnalysisMode = test.AnalysisMode,
                VantagePointName = test.VantagePointName,
                SourceIp = test.SourceIp,
                TargetNetworkName = test.TargetNetworkName ?? "N/A",
                TargetCidr = test.TargetCidr ?? "N/A",
                BoundaryGatewayIp = test.BoundaryGatewayIp ?? "N/A",
                CreatedAt = test.CreatedAt,
                ProjectName = test.ProjectName ?? "None",
                IsSelected = true // Default to selected
            }).ToList();

            // Convert SNMP walk tests to TestItem for binding
            _snmpWalkItems = snmpWalkTests.Select(test => new TestItem
            {
                Id = test.Id,
                AnalysisMode = test.AnalysisMode,
                VantagePointName = test.VantagePointName,
                SourceIp = test.SourceIp ?? "N/A",
                TargetNetworkName = test.TargetNetworkName ?? "N/A",
                TargetCidr = test.TargetCidr ?? "N/A",
                BoundaryGatewayIp = test.BoundaryGatewayIp ?? "N/A",
                CreatedAt = test.CreatedAt,
                ProjectName = test.ProjectName ?? "None",
                IsSelected = true // Default to selected
            }).ToList();

            if (LogsDataGrid != null) LogsDataGrid.ItemsSource = _logItems;
            if (AssetsDataGrid != null) AssetsDataGrid.ItemsSource = _assetItems;
            if (ReachabilityTestsDataGrid != null) ReachabilityTestsDataGrid.ItemsSource = _testItems;
            if (SnmpWalkTestsDataGrid != null) SnmpWalkTestsDataGrid.ItemsSource = _snmpWalkItems;
            
            if (LogsCountText != null) LogsCountText.Text = $"{logs.Count} pending log(s)";
            if (AssetsCountText != null) AssetsCountText.Text = $"{assets.Count} pending asset(s)";
            if (ReachabilityTestsCountText != null) ReachabilityTestsCountText.Text = $"{regularTests.Count} pending test(s)";
            if (SnmpWalkTestsCountText != null) SnmpWalkTestsCountText.Text = $"{snmpWalkTests.Count} pending SNMP walk(s)";
            
            UpdateSelectedCounts();
            
            // Always show all tabs (even if empty) for consistency
            LogsTab.IsVisible = true;
            AssetsTab.IsVisible = true;
            ReachabilityTestsTab.IsVisible = true;
            SnmpWalkTestsTab.IsVisible = true;
            
            // Select the tab with data, or logs tab by default
            if (snmpWalkTests.Count > 0 && regularTests.Count == 0 && logs.Count == 0 && assets.Count == 0)
            {
                SyncTabControl.SelectedItem = SnmpWalkTestsTab;
            }
            else if (regularTests.Count > 0 && logs.Count == 0 && assets.Count == 0)
            {
                SyncTabControl.SelectedItem = ReachabilityTestsTab;
            }
            else if (assets.Count > 0 && logs.Count == 0)
            {
                SyncTabControl.SelectedItem = AssetsTab;
            }
            else
            {
                SyncTabControl.SelectedItem = LogsTab;
            }

            // Handle window closing to persist deletions
            this.Closing += SyncWindow_Closing;
        }

        // FindControl properties for XAML-named controls
        private Avalonia.Controls.DataGrid? LogsDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("LogsDataGrid");
        private Avalonia.Controls.DataGrid? AssetsDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("AssetsDataGrid");
        private Avalonia.Controls.DataGrid? ReachabilityTestsDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("ReachabilityTestsDataGrid");
        private Avalonia.Controls.DataGrid? SnmpWalkTestsDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("SnmpWalkTestsDataGrid");
        private TextBlock? LogsCountText => this.FindControl<TextBlock>("LogsCountText");
        private TextBlock? AssetsCountText => this.FindControl<TextBlock>("AssetsCountText");
        private TextBlock? ReachabilityTestsCountText => this.FindControl<TextBlock>("ReachabilityTestsCountText");
        private TextBlock? SnmpWalkTestsCountText => this.FindControl<TextBlock>("SnmpWalkTestsCountText");
        private TabItem? LogsTab => this.FindControl<TabItem>("LogsTab");
        private TabItem? AssetsTab => this.FindControl<TabItem>("AssetsTab");
        private TabItem? ReachabilityTestsTab => this.FindControl<TabItem>("ReachabilityTestsTab");
        private TabItem? SnmpWalkTestsTab => this.FindControl<TabItem>("SnmpWalkTestsTab");
        private TabControl? SyncTabControl => this.FindControl<TabControl>("SyncTabControl");
        private TextBox? ProjectNameTextBox => this.FindControl<TextBox>("ProjectNameTextBox");
        private TextBlock? TotalSelectedText => this.FindControl<TextBlock>("TotalSelectedText");
        private TextBlock? SelectedLogsCountText => this.FindControl<TextBlock>("SelectedLogsCountText");
        private TextBlock? SelectedAssetsCountText => this.FindControl<TextBlock>("SelectedAssetsCountText");
        private TextBlock? SelectedTestsCountText => this.FindControl<TextBlock>("SelectedTestsCountText");

        private void SyncWindow_Closing(object? sender, WindowClosingEventArgs e)
        {
            // If user closes window (X button) and there are deletions, persist them
            // Note: In Avalonia, we handle this in the Close() method
        }

        private void ProjectNameTextBox_TextChanged(object? sender, Avalonia.Controls.TextChangedEventArgs e)
        {
            if (ProjectNameTextBox != null)
            {
                ProjectName = ProjectNameTextBox.Text?.Trim();
            }
        }

        private void SelectAllLogsCheckBox_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _logItems)
            {
                item.IsSelected = true;
            }
            if (LogsDataGrid != null)
            {
                LogsDataGrid.ItemsSource = null;
                LogsDataGrid.ItemsSource = _logItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllLogsCheckBox_Unchecked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _logItems)
            {
                item.IsSelected = false;
            }
            if (LogsDataGrid != null)
            {
                LogsDataGrid.ItemsSource = null;
                LogsDataGrid.ItemsSource = _logItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllAssetsCheckBox_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _assetItems)
            {
                item.IsSelected = true;
            }
            if (AssetsDataGrid != null)
            {
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllAssetsCheckBox_Unchecked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _assetItems)
            {
                item.IsSelected = false;
            }
            if (AssetsDataGrid != null)
            {
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
            }
            UpdateSelectedCounts();
        }

        private void UpdateSelectedCounts()
        {
            var selectedLogsCount = _logItems.Count(item => item.IsSelected);
            var selectedAssetsCount = _assetItems.Count(item => item.IsSelected);
            var selectedTestsCount = _testItems.Count(item => item.IsSelected);
            
            if (SelectedLogsCountText != null)
            {
                SelectedLogsCountText.Text = $"{selectedLogsCount} of {_logItems.Count} selected";
            }
            if (SelectedAssetsCountText != null)
            {
                SelectedAssetsCountText.Text = $"{selectedAssetsCount} of {_assetItems.Count} selected";
            }
            if (SelectedTestsCountText != null)
            {
                SelectedTestsCountText.Text = $"{selectedTestsCount} of {_testItems.Count} selected";
            }
            
            if (TotalSelectedText != null)
            {
                TotalSelectedText.Text = $"{selectedLogsCount} log(s), {selectedAssetsCount} asset(s), {selectedTestsCount} test(s) selected";
            }
        }

        private async void DeleteSelectedLogsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _logItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No logs selected for deletion." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            // Delete directly for now - in production, add confirmation dialog
            foreach (var item in selectedItems)
            {
                DeletedLogIds.Add(item.Id);
                _logItems.Remove(item);
            }
            if (LogsDataGrid != null)
            {
                LogsDataGrid.ItemsSource = null;
                LogsDataGrid.ItemsSource = _logItems;
            }
            if (LogsCountText != null)
            {
                LogsCountText.Text = $"{_logItems.Count} pending log(s)";
            }
            UpdateSelectedCounts();
        }

        private async void SkipSelectedLogsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _logItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No logs selected to skip." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            foreach (var item in selectedItems)
            {
                item.IsSelected = false;
            }
            if (LogsDataGrid != null)
            {
                LogsDataGrid.ItemsSource = null;
                LogsDataGrid.ItemsSource = _logItems;
            }
            UpdateSelectedCounts();
        }

        private async void DeleteSelectedAssetsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _assetItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No assets selected for deletion." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            // Delete directly
            foreach (var item in selectedItems)
            {
                DeletedAssetIds.Add(item.Id);
                _assetItems.Remove(item);
            }
            if (AssetsDataGrid != null)
            {
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
            }
            if (AssetsCountText != null)
            {
                AssetsCountText.Text = $"{_assetItems.Count} pending asset(s)";
            }
            UpdateSelectedCounts();
        }

        private async void SkipSelectedAssetsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _assetItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No assets selected to skip." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            foreach (var item in selectedItems)
            {
                item.IsSelected = false;
            }
            if (AssetsDataGrid != null)
            {
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllTestsCheckBox_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _testItems)
            {
                item.IsSelected = true;
            }
            if (ReachabilityTestsDataGrid != null)
            {
                ReachabilityTestsDataGrid.ItemsSource = null;
                ReachabilityTestsDataGrid.ItemsSource = _testItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllTestsCheckBox_Unchecked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _testItems)
            {
                item.IsSelected = false;
            }
            if (ReachabilityTestsDataGrid != null)
            {
                ReachabilityTestsDataGrid.ItemsSource = null;
                ReachabilityTestsDataGrid.ItemsSource = _testItems;
            }
            UpdateSelectedCounts();
        }

        private async void DeleteSelectedTestsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _testItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No tests selected for deletion." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            // Delete directly
            foreach (var item in selectedItems)
            {
                DeletedTestIds.Add(item.Id);
                _testItems.Remove(item);
            }
            if (ReachabilityTestsDataGrid != null)
            {
                ReachabilityTestsDataGrid.ItemsSource = null;
                ReachabilityTestsDataGrid.ItemsSource = _testItems;
            }
            if (ReachabilityTestsCountText != null)
            {
                ReachabilityTestsCountText.Text = $"{_testItems.Count} pending test(s)";
            }
            UpdateSelectedCounts();
        }

        private async void SkipSelectedTestsButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _testItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No tests selected to skip." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            foreach (var item in selectedItems)
            {
                item.IsSelected = false;
            }
            if (ReachabilityTestsDataGrid != null)
            {
                ReachabilityTestsDataGrid.ItemsSource = null;
                ReachabilityTestsDataGrid.ItemsSource = _testItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllSnmpWalkCheckBox_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _snmpWalkItems)
            {
                item.IsSelected = true;
            }
            if (SnmpWalkTestsDataGrid != null)
            {
                SnmpWalkTestsDataGrid.ItemsSource = null;
                SnmpWalkTestsDataGrid.ItemsSource = _snmpWalkItems;
            }
            UpdateSelectedCounts();
        }

        private void SelectAllSnmpWalkCheckBox_Unchecked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            foreach (var item in _snmpWalkItems)
            {
                item.IsSelected = false;
            }
            if (SnmpWalkTestsDataGrid != null)
            {
                SnmpWalkTestsDataGrid.ItemsSource = null;
                SnmpWalkTestsDataGrid.ItemsSource = _snmpWalkItems;
            }
            UpdateSelectedCounts();
        }

        private async void DeleteSelectedSnmpWalkButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _snmpWalkItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No SNMP walks selected for deletion." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            // Delete directly
            foreach (var item in selectedItems)
            {
                DeletedSnmpWalkIds.Add(item.Id);
                _snmpWalkItems.Remove(item);
            }
            if (SnmpWalkTestsDataGrid != null)
            {
                SnmpWalkTestsDataGrid.ItemsSource = null;
                SnmpWalkTestsDataGrid.ItemsSource = _snmpWalkItems;
            }
            SnmpWalkTestsCountText.Text = $"{_snmpWalkItems.Count} pending SNMP walk(s)";
            UpdateSelectedCounts();
        }

        private async void SkipSelectedSnmpWalkButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedItems = _snmpWalkItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "No SNMP walks selected to skip." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            foreach (var item in selectedItems)
            {
                item.IsSelected = false;
            }
            if (SnmpWalkTestsDataGrid != null)
            {
                SnmpWalkTestsDataGrid.ItemsSource = null;
                SnmpWalkTestsDataGrid.ItemsSource = _snmpWalkItems;
            }
            UpdateSelectedCounts();
        }

        private async void SyncButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            SelectedLogIds = _logItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            SelectedAssetIds = _assetItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            SelectedTestIds = _testItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            SelectedSnmpWalkIds = _snmpWalkItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            
            if (SelectedLogIds.Count == 0 && SelectedAssetIds.Count == 0 && SelectedTestIds.Count == 0 && SelectedSnmpWalkIds.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "Please select at least one log, asset, test, or SNMP walk to sync." },
                    Width = 400,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            EnhanceData = EnhanceDataCheckBox?.IsChecked ?? true;
            ShouldSync = true;
            Close(true);
        }

        private void CancelButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            // Even if canceling, we should persist deletions
            ShouldSync = false;
            // Return true so deletions are processed
            Close(true);
        }
    }

    public class LogItem : INotifyPropertyChanged
    {
        private bool _isSelected;

        public long Id { get; set; }
        public string AttackType { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public string TargetIp { get; set; } = string.Empty;
        public long PacketsSent { get; set; }
        public DateTime StartTime { get; set; }
        public string ProjectName { get; set; } = string.Empty;

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class TestItem : INotifyPropertyChanged
    {
        private bool _isSelected;

        public long Id { get; set; }
        public string AnalysisMode { get; set; } = string.Empty;
        public string VantagePointName { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public string TargetNetworkName { get; set; } = string.Empty;
        public string TargetCidr { get; set; } = string.Empty;
        public string BoundaryGatewayIp { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public string ProjectName { get; set; } = string.Empty;

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                _isSelected = value;
                OnPropertyChanged(nameof(IsSelected));
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

}

