using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Dorothy.Models;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class ReachabilityHistoryWindow : Window
    {
        private readonly DatabaseService _database;
        private List<RunRow> _rows;

        public ReachabilityRun? SelectedRun { get; private set; }

        public ReachabilityHistoryWindow(List<ReachabilityRun> runs, DatabaseService database)
        {
            InitializeComponent();
            _database = database;
            _rows = runs.Select(r => new RunRow(r)).ToList();
            RunsListView.ItemsSource = _rows;
        }

        private void LoadButton_Click(object sender, RoutedEventArgs e)
        {
            if (RunsListView.SelectedItem is RunRow row)
            {
                SelectedRun = row.Run;
                DialogResult = true;
                Close();
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void RunsListView_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            LoadButton_Click(sender, e);
        }

        private async void DeleteButton_Click(object sender, RoutedEventArgs e)
        {
            if (RunsListView.SelectedItem is not RunRow row) return;
            var confirm = MessageBox.Show(
                $"Delete run '{row.Label}' from {row.StartedDisplay}?",
                "Confirm Delete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;
            try
            {
                await _database.DeleteReachabilityRunAsync(row.Run.Id);
                _rows.Remove(row);
                RunsListView.ItemsSource = null;
                RunsListView.ItemsSource = _rows;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to delete run: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private class RunRow
        {
            public ReachabilityRun Run { get; }
            public string StartedDisplay => Run.StartedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            public string? Label => Run.Label;
            public string? TargetRaw => Run.TargetRaw;
            public int HostsTested => Run.HostsTested;
            public int HostsReachable => Run.HostsReachable;
            public int HostsPartial => Run.HostsPartial;
            public int HostsUnreachable => Run.HostsUnreachable;

            public RunRow(ReachabilityRun run) { Run = run; }
        }
    }
}
