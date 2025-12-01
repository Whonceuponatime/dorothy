using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Models.Database;

namespace Dorothy.Views
{
    public partial class SyncWindow : Window
    {
        public string? ProjectName { get; private set; }
        public List<long> SelectedLogIds { get; private set; } = new();
        public List<long> SelectedAssetIds { get; private set; } = new();
        public List<long> DeletedLogIds { get; private set; } = new();
        public List<long> DeletedAssetIds { get; private set; } = new();
        public bool ShouldSync { get; private set; }
        public bool EnhanceData { get; private set; }

        private List<LogItem> _logItems = new();
        private List<AssetItem> _assetItems = new();

        public SyncWindow(List<AttackLogEntry> logs, List<AssetEntry> assets)
        {
            InitializeComponent();
            
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
                HostName = asset.HostName ?? "Unknown",
                MacAddress = asset.MacAddress ?? "Unknown",
                Vendor = asset.Vendor ?? "Unknown",
                IsOnline = asset.IsOnline,
                ScanTime = asset.ScanTime,
                IsSelected = true // Default to selected
            }).ToList();

            LogsDataGrid.ItemsSource = _logItems;
            AssetsDataGrid.ItemsSource = _assetItems;
            
            LogsCountText.Text = $"{logs.Count} pending log(s)";
            AssetsCountText.Text = $"{assets.Count} pending asset(s)";
            
            UpdateSelectedCounts();
            
            // Always show both tabs (even if empty) for consistency
            LogsTab.Visibility = Visibility.Visible;
            AssetsTab.Visibility = Visibility.Visible;
            
            // Select the tab with data, or logs tab by default
            if (assets.Count > 0 && logs.Count == 0)
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

        private void SyncWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            // If user closes window (X button) and there are deletions, persist them
            // Set DialogResult to true so MainWindow processes deletions
            if (DeletedLogIds.Count > 0 || DeletedAssetIds.Count > 0)
            {
                DialogResult = true;
            }
        }

        private void ProjectNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ProjectName = ProjectNameTextBox.Text.Trim();
        }

        private void SelectAllLogsCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _logItems)
            {
                item.IsSelected = true;
            }
            LogsDataGrid.Items.Refresh();
            UpdateSelectedCounts();
        }

        private void SelectAllLogsCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _logItems)
            {
                item.IsSelected = false;
            }
            LogsDataGrid.Items.Refresh();
            UpdateSelectedCounts();
        }

        private void SelectAllAssetsCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _assetItems)
            {
                item.IsSelected = true;
            }
            AssetsDataGrid.Items.Refresh();
            UpdateSelectedCounts();
        }

        private void SelectAllAssetsCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _assetItems)
            {
                item.IsSelected = false;
            }
            AssetsDataGrid.Items.Refresh();
            UpdateSelectedCounts();
        }

        private void UpdateSelectedCounts()
        {
            var selectedLogsCount = _logItems.Count(item => item.IsSelected);
            var selectedAssetsCount = _assetItems.Count(item => item.IsSelected);
            
            SelectedLogsCountText.Text = $"{selectedLogsCount} of {_logItems.Count} selected";
            SelectedAssetsCountText.Text = $"{selectedAssetsCount} of {_assetItems.Count} selected";
            
            TotalSelectedText.Text = $"{selectedLogsCount} log(s), {selectedAssetsCount} asset(s) selected";
        }

        private void DeleteSelectedLogsButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _logItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("No logs selected for deletion.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Are you sure you want to delete {selectedItems.Count} log(s)? This action cannot be undone.",
                "Confirm Deletion",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                foreach (var item in selectedItems)
                {
                    DeletedLogIds.Add(item.Id);
                    _logItems.Remove(item);
                }
                LogsDataGrid.ItemsSource = null;
                LogsDataGrid.ItemsSource = _logItems;
                LogsCountText.Text = $"{_logItems.Count} pending log(s)";
                UpdateSelectedCounts();
            }
        }

        private void SkipSelectedLogsButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _logItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("No logs selected to skip.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var item in selectedItems)
            {
                item.IsSelected = false;
            }
            LogsDataGrid.Items.Refresh();
            UpdateSelectedCounts();
        }

        private void DeleteSelectedAssetsButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _assetItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("No assets selected for deletion.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Are you sure you want to delete {selectedItems.Count} asset(s)? This action cannot be undone.",
                "Confirm Deletion",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                foreach (var item in selectedItems)
                {
                    DeletedAssetIds.Add(item.Id);
                    _assetItems.Remove(item);
                }
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
                AssetsCountText.Text = $"{_assetItems.Count} pending asset(s)";
                UpdateSelectedCounts();
            }
        }

        private void SkipSelectedAssetsButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _assetItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("No assets selected to skip.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var item in selectedItems)
            {
                item.IsSelected = false;
            }
            AssetsDataGrid.Items.Refresh();
            UpdateSelectedCounts();
        }

        private void SyncButton_Click(object sender, RoutedEventArgs e)
        {
            SelectedLogIds = _logItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            SelectedAssetIds = _assetItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            
            if (SelectedLogIds.Count == 0 && SelectedAssetIds.Count == 0)
            {
                MessageBox.Show("Please select at least one log or asset to sync.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            EnhanceData = EnhanceDataCheckBox?.IsChecked ?? true;
            ShouldSync = true;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            // Even if canceling, we should persist deletions
            ShouldSync = false;
            DialogResult = true; // Changed to true so deletions are processed
            Close();
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

}

