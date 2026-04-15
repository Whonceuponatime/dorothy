using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Models;

namespace Dorothy.Views
{

    public partial class ReachabilityResultsWindow : Window
    {
        private readonly ObservableCollection<FirewallDiscoveryHostReachabilityResult> _reachabilityResults;
        private readonly ObservableCollection<InferredFirewallRule> _inferredRules;

        public ReachabilityResultsWindow(
            FirewallDiscoveryResult result)
        {
            InitializeComponent();

            _reachabilityResults = new ObservableCollection<FirewallDiscoveryHostReachabilityResult>(result.ReachabilityResults);
            _inferredRules = new ObservableCollection<InferredFirewallRule>(result.InferredRules);

            ReachabilityResultsDataGrid.ItemsSource = _reachabilityResults;
            InferredRulesDataGrid.ItemsSource = _inferredRules;

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

            SummaryTextBlock.Text = $"Total hosts tested: {totalHosts} | " +
                                   $"Reachable: {reachableHosts} | " +
                                   $"Unreachable: {unreachableHosts} | " +
                                   $"Inferred rules: {totalRules}";
        }

        private void ReachabilityResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

            if (ReachabilityResultsDataGrid.SelectedItem is FirewallDiscoveryHostReachabilityResult selectedResult)
            {
                var filteredRules = _inferredRules
                    .Where(r => r.Host.HostIp.ToString() == selectedResult.Host.HostIp.ToString())
                    .ToList();

                InferredRulesDataGrid.ItemsSource = filteredRules;
            }
            else
            {

                InferredRulesDataGrid.ItemsSource = _inferredRules;
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}

