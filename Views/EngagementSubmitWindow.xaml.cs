using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Dorothy.Models;
using Dorothy.Services;
using NLog;

namespace Dorothy.Views
{
    public partial class EngagementSubmitWindow : Window
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private enum Phase { Metadata, Confirm }

        private readonly EngagementSubmitService _submitService;
        private readonly DiscoveryOrchestrator? _orchestrator;
        private readonly DatabaseService _db;
        private readonly int _hostCount;
        private readonly int _attackCount;
        private readonly DateTime _sessionStartedAt;
        private CancellationTokenSource? _cts;
        private Phase _phase = Phase.Metadata;

        /// <summary>
        /// Set when the user ticked "Clear local scan data after successful
        /// upload" AND the submit succeeded. MainWindow uses this to clear the
        /// in-memory topology graph so the canvas reflects the on-disk state.
        /// </summary>
        public bool ClearedLocalData { get; private set; }

        public EngagementSubmitWindow(
            int hostCount,
            int attackCount,
            EngagementSubmitService submitService,
            DiscoveryOrchestrator? orchestrator,
            DatabaseService db,
            DateTime sessionStartedAt)
        {
            InitializeComponent();
            _submitService = submitService;
            _orchestrator = orchestrator;
            _db = db;
            _hostCount = hostCount;
            _attackCount = attackCount;
            _sessionStartedAt = sessionStartedAt;

            SessionStatsText.Text =
                $"This session: {hostCount} host(s) probed in detail, {attackCount} attack run(s).";
            NameTextBox.Focus();
        }

        private async void PrimaryButton_Click(object sender, RoutedEventArgs e)
        {
            if (_phase == Phase.Metadata)
            {
                if (string.IsNullOrWhiteSpace(NameTextBox.Text))
                {
                    MessageBox.Show("Engagement name is required.",
                        "Missing name", MessageBoxButton.OK, MessageBoxImage.Warning);
                    NameTextBox.Focus();
                    return;
                }

                ConfirmNameText.Text = NameTextBox.Text.Trim();
                ConfirmClientText.Text = string.IsNullOrWhiteSpace(ClientTextBox.Text)
                    ? "—" : ClientTextBox.Text.Trim();

                // Pull richer counts from DB so the surveyor sees ALL activity,
                // not just probes + attacks. Network-scan-discovered hosts
                // (topology nodes of type Host/RemoteHost) get their own row.
                int hostsDiscovered = 0;
                int subnetsDiscovered = 0;
                try
                {
                    hostsDiscovered = await _db.CountUnsubmittedTopologyHostNodesAsync();
                    subnetsDiscovered = await _db.CountUnsubmittedTopologySubnetsAsync();
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "[ENGAGEMENT-SUBMIT] Failed to fetch topology counts");
                }

                HostsDiscoveredText.Text = hostsDiscovered.ToString();
                HostsProbedText.Text = _hostCount.ToString();
                AttackRunsText.Text = _attackCount.ToString();

                if (subnetsDiscovered > 0)
                {
                    SubnetsLabel.Visibility = Visibility.Visible;
                    SubnetsText.Visibility = Visibility.Visible;
                    SubnetsText.Text = subnetsDiscovered.ToString();
                }
                else
                {
                    SubnetsLabel.Visibility = Visibility.Collapsed;
                    SubnetsText.Visibility = Visibility.Collapsed;
                }

                MetadataPanel.Visibility = Visibility.Collapsed;
                ConfirmPanel.Visibility = Visibility.Visible;
                BackButton.Visibility = Visibility.Visible;
                PrimaryButton.Content = "Submit";
                _phase = Phase.Confirm;
                return;
            }

            // Phase.Confirm → actually submit
            await SubmitAsync();
        }

        private async Task SubmitAsync()
        {
            PrimaryButton.IsEnabled = false;
            BackButton.IsEnabled = false;
            CancelButton.Content = "Close";
            StatusPanel.Visibility = Visibility.Visible;
            StatusText.Text = "Submitting…";
            StatusText.Foreground = (System.Windows.Media.Brush)FindResource("TextPrimary");

            var progress = new Progress<string>(msg => Dispatcher.Invoke(() => StatusText.Text = msg));
            _cts = new CancellationTokenSource();
            try
            {
                TopologyGraph? topology = _orchestrator?.Graph;

                bool clearAfterSubmit = ClearLocalDataCheckbox.IsChecked == true;

                var result = await _submitService.SubmitAsync(
                    name: NameTextBox.Text.Trim(),
                    clientName: string.IsNullOrWhiteSpace(ClientTextBox.Text) ? null : ClientTextBox.Text.Trim(),
                    scope: string.IsNullOrWhiteSpace(ScopeTextBox.Text) ? null : ScopeTextBox.Text.Trim(),
                    notes: string.IsNullOrWhiteSpace(NotesTextBox.Text) ? null : NotesTextBox.Text,
                    surveyorEmail: null,
                    sessionStartedAt: _sessionStartedAt,
                    clearAfterSubmit: clearAfterSubmit,
                    topology: topology,
                    progress: progress,
                    ct: _cts.Token);

                if (result.Success)
                {
                    ClearedLocalData = clearAfterSubmit;
                    StatusText.Text = "Submitted successfully.";
                    StatusText.Foreground = (System.Windows.Media.Brush)FindResource("SuccessGreen");
                    await Task.Delay(700);
                    DialogResult = true;
                    Close();
                }
                else
                {
                    // Failure: keep metadata so the user can edit and retry without
                    // re-typing. Allow Back to go to the form, and Submit (renamed
                    // Retry) on the confirmation panel.
                    PrimaryButton.IsEnabled = true;
                    BackButton.IsEnabled = true;
                    PrimaryButton.Content = "Retry";
                    StatusText.Text = result.ErrorMessage ?? "Submit failed.";
                    StatusText.Foreground = (System.Windows.Media.Brush)FindResource("ErrorRed");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "[ENGAGEMENT-SUBMIT] Submit threw");
                PrimaryButton.IsEnabled = true;
                BackButton.IsEnabled = true;
                PrimaryButton.Content = "Retry";
                StatusText.Text = $"Error: {ex.Message}";
                StatusText.Foreground = (System.Windows.Media.Brush)FindResource("ErrorRed");
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
            }
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            ConfirmPanel.Visibility = Visibility.Collapsed;
            StatusPanel.Visibility = Visibility.Collapsed;
            MetadataPanel.Visibility = Visibility.Visible;
            BackButton.Visibility = Visibility.Collapsed;
            PrimaryButton.Content = "Continue";
            PrimaryButton.IsEnabled = true;
            _phase = Phase.Metadata;
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            try { _cts?.Cancel(); } catch { }
            DialogResult = false;
            Close();
        }
    }
}
