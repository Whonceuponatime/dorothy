using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Services.Reachability;

namespace Dorothy.Views
{

    internal sealed class HostScanViewModel : INotifyPropertyChanged
    {
        private string _statusDisplay = "Pending";
        private string _icmpStatus    = "—";
        private string _openPorts     = string.Empty;
        private int    _closedCount;
        private int    _timedOutCount;
        private int    _errorCount;

        public string IpAddress { get; init; } = string.Empty;

        public string StatusDisplay
        {
            get => _statusDisplay;
            set { _statusDisplay = value; OnPropertyChanged(); }
        }
        public string IcmpStatus
        {
            get => _icmpStatus;
            set { _icmpStatus = value; OnPropertyChanged(); }
        }
        public string OpenPorts
        {
            get => _openPorts;
            set { _openPorts = value; OnPropertyChanged(); }
        }
        public int ClosedCount
        {
            get => _closedCount;
            set { _closedCount = value; OnPropertyChanged(); }
        }
        public int TimedOutCount
        {
            get => _timedOutCount;
            set { _timedOutCount = value; OnPropertyChanged(); }
        }
        public int ErrorCount
        {
            get => _errorCount;
            set { _errorCount = value; OnPropertyChanged(); }
        }

        public void UpdateFrom(HostScanResult r)
        {
            StatusDisplay = r.Status switch
            {
                HostScanStatus.Pending        => "Pending",
                HostScanStatus.Scanning       => "Scanning…",
                HostScanStatus.Done           => "Done",
                HostScanStatus.Unreachable    => "Unreachable",
                HostScanStatus.UnresolvedName => "Unresolved",
                HostScanStatus.Error          => "Error",
                _                             => "?"
            };

            if (r.IcmpResult != null)
                IcmpStatus = r.IcmpResult.ReplyStatus switch
                {
                    IcmpReplyStatus.Reply   => "Reply",
                    IcmpReplyStatus.NoReply => "No reply",
                    IcmpReplyStatus.Error   => "Error",
                    _                       => "—"
                };

            OpenPorts     = string.Join(", ", r.OpenPorts.Select(p => p.Port));
            ClosedCount   = r.ClosedPorts.Count();
            TimedOutCount = r.TimedOutPorts.Count();
            ErrorCount    = r.ErrorPorts.Count();
        }

        public static HostScanViewModel ForUnresolved(UnresolvedTarget u)
        {
            var vm = new HostScanViewModel { IpAddress = u.Input };
            vm.StatusDisplay = "Unresolved";
            return vm;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    public partial class BoundedTcpScanWindow : Window
    {
        private readonly TargetExpansionService    _expander   = new();
        private readonly TcpConnectScanService     _scanner    = new();
        private readonly ReachabilityResultAggregator _aggregator = new();

        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<HostScanViewModel> _viewModels = new();

        private IReadOnlyList<IPAddress>? _lastHosts;
        private IReadOnlyList<int>?       _lastPorts;
        private string                    _targetDescription = string.Empty;

        public BoundedTcpScanWindow()
        {
            InitializeComponent();
            ResultsDataGrid.ItemsSource = _viewModels;

            PortPresetComboBox.SelectedIndex = 0;
            IcmpDiscoveryCheckBox.IsChecked  = true;

            LoadSourceIps();
        }

        private void LoadSourceIps()
        {
            SourceIpComboBox.Items.Clear();
            SourceIpComboBox.Items.Add(new ComboBoxItem
            {
                Content = "Auto (OS routing)",
                Tag     = null,
                ToolTip = "Let the OS choose the outgoing interface based on its routing table."
            });

            foreach (var (addr, label) in TargetExpansionService.GetLocalIpAddresses())
                SourceIpComboBox.Items.Add(new ComboBoxItem { Content = label, Tag = addr });

            SourceIpComboBox.SelectedIndex = 0;
        }

        private IPAddress? GetSelectedSourceIp() =>
            (SourceIpComboBox.SelectedItem as ComboBoxItem)?.Tag as IPAddress;

        private string GetSelectedNicDisplay() =>
            (SourceIpComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Auto";

        private void PortPresetComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CustomPortsTextBox == null) return;
            var tag = (PortPresetComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "common";
            bool isCustom = tag == "custom";
            CustomPortsTextBox.IsEnabled = isCustom;
            if (!isCustom)
                CustomPortsTextBox.Text = tag switch
                {
                    "web"      => TargetExpansionService.WebPortsPreset,
                    "remote"   => TargetExpansionService.RemoteAccessPreset,
                    "database" => TargetExpansionService.DatabasePortsPreset,
                    _          => TargetExpansionService.CommonPortsPreset
                };
        }

        private void TargetInputTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TargetEstimateText == null) return;
            long hosts = _expander.EstimateHostCount(TargetInputTextBox.Text);
            int  ports = GetSelectedPorts().Count;
            TargetEstimateText.Text = hosts > 0
                ? $"Estimated: {hosts:N0} host(s) × {ports} port(s) = {hosts * ports:N0} probe(s)"
                : string.Empty;
        }

        private void EstimateButton_Click(object sender, RoutedEventArgs e)
        {
            var ports  = GetSelectedPorts();
            long hosts = _expander.EstimateHostCount(TargetInputTextBox.Text);
            var est    = _expander.EstimateWorkload(hosts, ports.Count, BuildOptions());

            string msg = est.Summary;
            if (!string.IsNullOrEmpty(est.Warning))
                msg += "\n\n" + est.Warning;

            MessageBox.Show(msg, "Workload Estimate", MessageBoxButton.OK,
                est.RequiresConfirmation ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }

        private async void StartScanButton_Click(object sender, RoutedEventArgs e)
        {
            var input = TargetInputTextBox.Text.Trim();
            if (string.IsNullOrEmpty(input))
            {
                MessageBox.Show("Please enter at least one target.", "No Target",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var ports = GetSelectedPorts();
            if (ports.Count == 0)
            {
                MessageBox.Show("No valid ports specified.", "No Ports",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var options  = BuildOptions();

            long estHosts = _expander.EstimateHostCount(input);
            var  est      = _expander.EstimateWorkload(estHosts, ports.Count, options);

            if (est.IsVeryLarge)
            {
                if (MessageBox.Show(
                    $"{est.Warning}\n\nThis is a very large scan job. Are you sure?\n\n" +
                    "Only run this on networks you are explicitly authorized to test.",
                    "Very Large Scan — Confirm", MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
                    return;
            }
            else if (est.RequiresConfirmation)
            {
                if (MessageBox.Show($"{est.Warning}\n\nProceed?",
                    "Large Scan — Confirm", MessageBoxButton.YesNo,
                    MessageBoxImage.Information) != MessageBoxResult.Yes)
                    return;
            }

            SetScanningState(true, "Expanding targets…");
            TargetExpansionResult expansion;
            try
            {
                expansion = await _expander.ExpandHostsAsync(input);
            }
            catch (Exception ex)
            {
                SetScanningState(false, string.Empty);
                MessageBox.Show($"Target expansion failed: {ex.Message}", "Error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _viewModels.Clear();
            foreach (var h in expansion.ResolvedHosts)
                _viewModels.Add(new HostScanViewModel { IpAddress = h.ToString() });
            foreach (var u in expansion.Unresolved)
                _viewModels.Add(HostScanViewModel.ForUnresolved(u));

            if (expansion.ResolvedHosts.Count == 0 && expansion.Unresolved.Count > 0)
            {
                SetScanningState(false,
                    $"All {expansion.Unresolved.Count} name(s) failed DNS resolution. " +
                    "Use IP addresses for offline environments.");
                return;
            }

            if (expansion.Unresolved.Count > 0)
            {
                ScanStatusText.Text = $"Warning: {expansion.Unresolved.Count} name(s) unresolved " +
                                      "— shown in results. Continuing with resolved IPs…";
            }

            if (expansion.ResolvedHosts.Count == 0)
            {
                SetScanningState(false, "No valid IP addresses found in target input.");
                return;
            }

            _lastHosts         = expansion.ResolvedHosts;
            _lastPorts         = ports;
            _targetDescription = BuildTargetDescription(input, expansion);

            SummaryTextBox.Text = string.Empty;

            var routeInfo = RouteType.Unknown;
            var sourceIp  = options.SourceIp;
            if (sourceIp != null && expansion.ResolvedHosts.Count > 0)
                routeInfo = TargetExpansionService.DetermineRoute(sourceIp, expansion.ResolvedHosts[0]);

            _cts = new CancellationTokenSource();
            SetScanningState(true,
                $"Scanning {expansion.ResolvedHosts.Count} host(s) on {ports.Count} port(s)…");

            List<HostScanResult> results;
            try
            {
                var progress = new Progress<ScanProgress>(p =>
                    Dispatcher.Invoke(() =>
                    {
                        ScanProgressBar.Value = expansion.ResolvedHosts.Count > 0
                            ? p.CompletedHosts * 100.0 / expansion.ResolvedHosts.Count : 0;
                        int openCount = _viewModels.Sum(v =>
                            v.OpenPorts.Split(',').Count(s => s.Trim().Length > 0));
                        ScanCounterText.Text =
                            $"{p.CompletedHosts}/{expansion.ResolvedHosts.Count} hosts  |  " +
                            $"{openCount} open port(s)";
                    }));

                results = await _scanner.ScanAsync(
                    expansion.ResolvedHosts, ports, options,
                    result => Dispatcher.Invoke(() =>
                    {
                        var vm = _viewModels.FirstOrDefault(
                            v => v.IpAddress == result.Target.ToString());
                        vm?.UpdateFrom(result);
                    }),
                    progress, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                SetScanningState(false, "Scan cancelled.");
                return;
            }
            catch (Exception ex)
            {
                SetScanningState(false, $"Scan error: {ex.Message}");
                return;
            }
            finally
            {
                _cts?.Dispose();
                _cts = null;
            }

            var ctx = new ReportContext
            {
                NicDisplayName   = GetSelectedNicDisplay(),
                SourceIp         = sourceIp,
                Route            = routeInfo,
                BoundaryGateway  = GetDefaultGateway(sourceIp)?.ToString(),
                TargetResolution = BuildResolutionLabel(input, expansion)
            };

            var allResults = new List<HostScanResult>(results);
            foreach (var u in expansion.Unresolved)
            {
                allResults.Add(new HostScanResult
                {
                    Target       = IPAddress.None,
                    Hostname     = u.Input,
                    Status       = HostScanStatus.UnresolvedName,
                    ErrorMessage = u.Reason
                });
            }

            string summary = _aggregator.GenerateScanSummary(
                allResults, _targetDescription, ports, options, ctx);
            SummaryTextBox.Text = summary;

            int openCount2 = results.Sum(r => r.OpenPorts.Count());
            SetScanningState(false,
                $"Complete — {results.Count} host(s) scanned, {openCount2} open port(s) found." +
                (expansion.Unresolved.Count > 0
                    ? $"  {expansion.Unresolved.Count} name(s) unresolved."
                    : string.Empty));
        }

        private void StopScanButton_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            ScanStatusText.Text = "Stopping…";
        }

        private void CopySummaryButton_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(SummaryTextBox.Text))
                Clipboard.SetText(SummaryTextBox.Text);
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            _cts?.Cancel();
            base.OnClosing(e);
        }

        private IReadOnlyList<int> GetSelectedPorts() =>
            TargetExpansionService.ParsePorts(CustomPortsTextBox.Text);

        private ScanOptions BuildOptions()
        {
            int.TryParse(ConcurrencyTextBox.Text, out int conc);
            int.TryParse(TimeoutMsTextBox.Text,   out int timeout);
            return new ScanOptions
            {
                UseIcmpDiscovery  = IcmpDiscoveryCheckBox.IsChecked == true,
                MaxConcurrency    = Math.Max(1, Math.Min(conc > 0 ? conc : 10, 50)),
                PerProbeTimeoutMs = Math.Max(500, timeout > 0 ? timeout : 3000),
                IcmpTimeoutMs     = 2000,
                IcmpPingCount     = 2,
                SourceIp          = GetSelectedSourceIp()
            };
        }

        private static string BuildTargetDescription(
            string input, TargetExpansionResult ex)
        {
            string first = input.Split('\n')[0].Trim();
            string desc  = first.Length > 50 ? first[..47] + "…" : first;
            string suffix = $" ({ex.ResolvedHosts.Count} host(s)" +
                (ex.Unresolved.Count > 0 ? $", {ex.Unresolved.Count} unresolved" : "") + ")";
            return desc + suffix;
        }

        private static string BuildResolutionLabel(string input, TargetExpansionResult ex)
        {
            if (ex.Unresolved.Count > 0 && ex.ResolvedHosts.Count == 0)
                return "Unresolved";
            string t = input.Trim().Split('\n')[0].Trim();
            if (t.Contains('/'))   return "CIDR";
            if (t.Contains('-'))   return "Range";
            if (IPAddress.TryParse(t, out _)) return "IP";
            if (ex.ResolvedHosts.Count > 0)
                return $"Hostname→{ex.ResolvedHosts[0]}";
            return "IP-list";
        }

        private static IPAddress? GetDefaultGateway(IPAddress? sourceIp)
        {
            if (sourceIp == null) return null;
            try
            {
                var nic = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(n => n.GetIPProperties().UnicastAddresses
                        .Any(u => u.Address.Equals(sourceIp)));
                return nic?.GetIPProperties().GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            }
            catch { return null; }
        }

        private void SetScanningState(bool isScanning, string statusMessage)
        {
            StartScanButton.IsEnabled    = !isScanning;
            StopScanButton.IsEnabled     =  isScanning;
            EstimateButton.IsEnabled     = !isScanning;
            TargetInputTextBox.IsEnabled = !isScanning;
            SourceIpComboBox.IsEnabled   = !isScanning;

            ScanProgressBar.Visibility   = isScanning ? Visibility.Visible : Visibility.Collapsed;
            if (!isScanning) ScanProgressBar.Value = 0;

            ScanStatusText.Text = statusMessage;
            if (!isScanning) ScanCounterText.Text = string.Empty;
        }
    }
}
