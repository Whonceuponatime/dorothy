using System.Collections.ObjectModel;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Dorothy.Models;

namespace Dorothy.Views
{
    /// <summary>
    /// Interaction logic for ReachabilityResultsWindow.xaml
    /// </summary>
    public partial class ReachabilityResultsWindow : Window
    {
        private readonly ObservableCollection<FirewallDiscoveryHostReachabilityResult> _reachabilityResults;
        private readonly ObservableCollection<InferredFirewallRule> _inferredRules;

        // FindControl properties for XAML-named controls
        private Avalonia.Controls.DataGrid? ReachabilityResultsDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("ReachabilityResultsDataGrid");
        private Avalonia.Controls.DataGrid? InferredRulesDataGrid => this.FindControl<Avalonia.Controls.DataGrid>("InferredRulesDataGrid");
        private TextBlock? SummaryTextBlock => this.FindControl<TextBlock>("SummaryTextBlock");

        public ReachabilityResultsWindow(
            FirewallDiscoveryResult result)
        {
            AvaloniaXamlLoader.Load(this);

            _reachabilityResults = new ObservableCollection<FirewallDiscoveryHostReachabilityResult>(result.ReachabilityResults);
            _inferredRules = new ObservableCollection<InferredFirewallRule>(result.InferredRules);

            if (ReachabilityResultsDataGrid != null)
            {
                ReachabilityResultsDataGrid.ItemsSource = _reachabilityResults;
            }
            if (InferredRulesDataGrid != null)
            {
                InferredRulesDataGrid.ItemsSource = _inferredRules;
            }

            UpdateSummary();
        }

        private void UpdateSummary()
        {
            int totalHosts = _reachabilityResults.Count;
            int reachableHosts = _reachabilityResults.Count(r => 
                r.State == ReachabilityState.ReachableIcmp || 
                r.State == ReachabilityState.ReachableTcpOnly);
            int unreachableHosts = _reachabilityResults.Count(r => r.State == ReachabilityState.Unreachable);
            int totalRules = _inferredRules.Count;

            if (SummaryTextBlock != null)
            {
                SummaryTextBlock.Text = $"Total hosts tested: {totalHosts} | " +
                                       $"Reachable: {reachableHosts} | " +
                                       $"Unreachable: {unreachableHosts} | " +
                                       $"Inferred rules: {totalRules}";
            }
        }

        private void ReachabilityResultsDataGrid_SelectionChanged(object? sender, Avalonia.Controls.SelectionChangedEventArgs e)
        {
            // Filter inferred rules by selected host
            if (ReachabilityResultsDataGrid != null && ReachabilityResultsDataGrid.SelectedItem is FirewallDiscoveryHostReachabilityResult selectedResult)
            {
                var filteredRules = _inferredRules
                    .Where(r => r.Host.HostIp.ToString() == selectedResult.Host.HostIp.ToString())
                    .ToList();

                if (InferredRulesDataGrid != null)
                {
                    InferredRulesDataGrid.ItemsSource = filteredRules;
                }
            }
            else
            {
                // Show all rules if no host is selected
                if (InferredRulesDataGrid != null)
                {
                    InferredRulesDataGrid.ItemsSource = _inferredRules;
                }
            }
        }

        private void CloseButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close();
        }
    }
}

