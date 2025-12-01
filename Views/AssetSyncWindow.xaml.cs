using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Models.Database;

namespace Dorothy.Views
{
    public partial class AssetSyncWindow : Window
    {
        public string? ProjectName { get; private set; }
        public List<long> SelectedIds { get; private set; } = new();
        public List<long> DeletedIds { get; private set; } = new();
        public bool ShouldSync { get; private set; }

        private List<AssetItem> _assetItems = new();

        public AssetSyncWindow(List<AssetEntry> assets)
        {
            InitializeComponent();
            
            // Convert to AssetItem for binding
            _assetItems = assets.Select(asset => new AssetItem
            {
                Id = asset.Id,
                HostIp = asset.HostIp,
                HostName = string.IsNullOrWhiteSpace(asset.HostName) ? "Unknown" : asset.HostName,
                MacAddress = string.IsNullOrWhiteSpace(asset.MacAddress) ? "Unknown" : asset.MacAddress,
                Vendor = string.IsNullOrWhiteSpace(asset.Vendor) ? "Unknown" : asset.Vendor,
                IsOnline = asset.IsOnline,
                PingTime = asset.PingTime,
                ScanTime = asset.ScanTime,
                ProjectName = asset.ProjectName ?? "None",
                IsSelected = true // Default to selected
            }).ToList();

            AssetsDataGrid.ItemsSource = _assetItems;
            UpdateSelectedCount();
        }

        private void ProjectNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ProjectName = ProjectNameTextBox.Text.Trim();
        }

        private void SelectAllCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _assetItems)
            {
                item.IsSelected = true;
            }
            AssetsDataGrid.Items.Refresh();
            UpdateSelectedCount();
        }

        private void SelectAllCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _assetItems)
            {
                item.IsSelected = false;
            }
            AssetsDataGrid.Items.Refresh();
            UpdateSelectedCount();
        }

        private void UpdateSelectedCount()
        {
            var selectedCount = _assetItems.Count(item => item.IsSelected);
            SelectedCountText.Text = $"{selectedCount} of {_assetItems.Count} selected";
        }

        private void DeleteSelectedButton_Click(object sender, RoutedEventArgs e)
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
                    DeletedIds.Add(item.Id);
                    _assetItems.Remove(item);
                }
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
                UpdateSelectedCount();
            }
        }

        private void SkipSelectedButton_Click(object sender, RoutedEventArgs e)
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
            UpdateSelectedCount();
        }

        private void SyncButton_Click(object sender, RoutedEventArgs e)
        {
            SelectedIds = _assetItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            
            if (SelectedIds.Count == 0)
            {
                MessageBox.Show("Please select at least one asset to sync.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            ShouldSync = true;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            ShouldSync = false;
            DialogResult = false;
            Close();
        }
    }

    public class AssetItem : INotifyPropertyChanged
    {
        private bool _isSelected;

        public long Id { get; set; }
        public string HostIp { get; set; } = string.Empty;
        public string HostName { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string Vendor { get; set; } = string.Empty;
        public bool IsOnline { get; set; }
        public int? PingTime { get; set; }
        public DateTime ScanTime { get; set; }
        public string ProjectName { get; set; } = string.Empty;
        public string OpenPortsDisplay { get; set; } = "N/A"; // Ports not stored in database

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

    public class BoolToStatusConverter : System.Windows.Data.IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value is bool isOnline)
            {
                return isOnline ? "Online" : "Offline";
            }
            return "Unknown";
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}

