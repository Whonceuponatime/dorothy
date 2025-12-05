using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Markup.Xaml;
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
            AvaloniaXamlLoader.Load(this);
            
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
                OpenPortsDisplay = string.IsNullOrWhiteSpace(asset.Ports) ? "N/A" : asset.Ports, // Use Ports column from database
                IsSelected = true // Default to selected
            }).ToList();

            var assetsDataGrid = this.FindControl<Avalonia.Controls.DataGrid>("AssetsDataGrid");
            if (assetsDataGrid != null)
            {
                assetsDataGrid.ItemsSource = _assetItems;
            }
            UpdateSelectedCount();
        }

        private Avalonia.Controls.DataGrid? AssetsDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("AssetsDataGrid");
        private TextBox? ProjectNameTextBox => this.FindControl<TextBox>("ProjectNameTextBox");

        private void ProjectNameTextBox_TextChanged(object? sender, Avalonia.Controls.TextChangedEventArgs e)
        {
            if (ProjectNameTextBox != null)
            {
                ProjectName = ProjectNameTextBox.Text?.Trim();
            }
        }

        private TextBlock? SelectedCountText => this.FindControl<TextBlock>("SelectedCountText");

        private void SelectAllCheckBox_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
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
            UpdateSelectedCount();
        }

        private void SelectAllCheckBox_Unchecked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
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
            UpdateSelectedCount();
        }

        private void UpdateSelectedCount()
        {
            var selectedCount = _assetItems.Count(item => item.IsSelected);
            if (SelectedCountText != null)
            {
                SelectedCountText.Text = $"{selectedCount} of {_assetItems.Count} selected";
            }
        }

        private async void DeleteSelectedButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
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

            // Simple confirmation - delete directly for now
            // In production, you'd want a proper dialog with Yes/No buttons
            foreach (var item in selectedItems)
            {
                DeletedIds.Add(item.Id);
                _assetItems.Remove(item);
            }
            if (AssetsDataGrid != null)
            {
                AssetsDataGrid.ItemsSource = null;
                AssetsDataGrid.ItemsSource = _assetItems;
            }
            UpdateSelectedCount();
        }

        private async void SkipSelectedButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
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
            UpdateSelectedCount();
        }

        private async void SyncButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            SelectedIds = _assetItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            
            if (SelectedIds.Count == 0)
            {
                var msgBox = new Window
                {
                    Title = "No Selection",
                    Content = new TextBlock { Text = "Please select at least one asset to sync." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }

            ShouldSync = true;
            Close(true);
        }

        private void CancelButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            ShouldSync = false;
            Close(false);
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

    public class BoolToStatusConverter : IValueConverter
    {
        public object? Convert(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture)
        {
            if (value is bool isOnline)
            {
                return isOnline ? "Online" : "Offline";
            }
            return "Unknown";
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}

