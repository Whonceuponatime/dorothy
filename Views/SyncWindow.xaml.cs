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
        public List<long> SelectedIds { get; private set; } = new();
        public List<long> DeletedIds { get; private set; } = new();
        public List<long> SkippedIds { get; private set; } = new();
        public bool ShouldSync { get; private set; }

        private List<LogItem> _logItems = new();

        public SyncWindow(List<AttackLogEntry> logs)
        {
            InitializeComponent();
            
            // Convert to LogItem for binding
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

            LogsDataGrid.ItemsSource = _logItems;
            UpdateSelectedCount();
        }

        private void ProjectNameTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ProjectName = ProjectNameTextBox.Text.Trim();
        }

        private void SelectAllCheckBox_Checked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _logItems)
            {
                item.IsSelected = true;
            }
            LogsDataGrid.Items.Refresh();
            UpdateSelectedCount();
        }

        private void SelectAllCheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            foreach (var item in _logItems)
            {
                item.IsSelected = false;
            }
            LogsDataGrid.Items.Refresh();
            UpdateSelectedCount();
        }

        private void UpdateSelectedCount()
        {
            var selectedCount = _logItems.Count(item => item.IsSelected);
            SelectedCountText.Text = $"{selectedCount} of {_logItems.Count} selected";
        }

        private void DeleteSelectedButton_Click(object sender, RoutedEventArgs e)
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
                    DeletedIds.Add(item.Id);
                    _logItems.Remove(item);
                }
                LogsDataGrid.ItemsSource = null;
                LogsDataGrid.ItemsSource = _logItems;
                UpdateSelectedCount();
            }
        }

        private void SkipSelectedButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedItems = _logItems.Where(item => item.IsSelected).ToList();
            if (selectedItems.Count == 0)
            {
                MessageBox.Show("No logs selected to skip.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            foreach (var item in selectedItems)
            {
                SkippedIds.Add(item.Id);
                item.IsSelected = false;
            }
            LogsDataGrid.Items.Refresh();
            UpdateSelectedCount();
        }

        private void SyncButton_Click(object sender, RoutedEventArgs e)
        {
            SelectedIds = _logItems.Where(item => item.IsSelected).Select(item => item.Id).ToList();
            
            if (SelectedIds.Count == 0)
            {
                MessageBox.Show("Please select at least one log to sync.", "No Selection", MessageBoxButton.OK, MessageBoxImage.Information);
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

