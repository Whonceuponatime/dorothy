using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using Dorothy.Models;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class ReachabilityWizardWindow : Window
    {
        private int _currentStep = 1;
        private AnalysisContext? _context;
        private ReachabilityWizardService? _service;
        private CancellationTokenSource? _cancellationTokenSource;
        private DatabaseService? _databaseService;
        private PathAnalysisResult? _pathResult;

        // Observable collections for data binding
        private ObservableCollection<InsideAssetDefinition> _insideAssets = new ObservableCollection<InsideAssetDefinition>();
        private ObservableCollection<IcmpReachabilityResult> _icmpResults = new ObservableCollection<IcmpReachabilityResult>();
        private ObservableCollection<TcpReachabilityResult> _tcpResults = new ObservableCollection<TcpReachabilityResult>();
        private ObservableCollection<PathHop> _pathHops = new ObservableCollection<PathHop>();
        private ObservableCollection<DeeperScanResult> _deeperScanResults = new ObservableCollection<DeeperScanResult>();

        // Step completion tracking
        private bool _step2Completed = false;
        private bool _step3Completed = false;
        private bool _step4Completed = false;
        private bool _step5Completed = false;

        public ReachabilityWizardWindow()
        {
            try
            {
                System.Diagnostics.Debug.WriteLine("ReachabilityWizardWindow: Starting InitializeComponent...");
                AvaloniaXamlLoader.Load(this);
                System.Diagnostics.Debug.WriteLine("ReachabilityWizardWindow: InitializeComponent completed");
                
                System.Diagnostics.Debug.WriteLine("ReachabilityWizardWindow: Creating service...");
                _service = new ReachabilityWizardService();
                _databaseService = new DatabaseService();
                System.Diagnostics.Debug.WriteLine("ReachabilityWizardWindow: Service created");
                
                System.Diagnostics.Debug.WriteLine("ReachabilityWizardWindow: Subscribing to Loaded event...");
                this.Loaded += ReachabilityWizardWindow_Loaded;
                System.Diagnostics.Debug.WriteLine("ReachabilityWizardWindow: Constructor completed successfully");
            }
            catch (Exception ex)
            {
                string errorDetails = $"Error in ReachabilityWizardWindow constructor:\nType: {ex.GetType().Name}\nMessage: {ex.Message}";
                if (ex.InnerException != null)
                {
                    errorDetails += $"\nInner: {ex.InnerException.Message}";
                }
                errorDetails += $"\nStack trace:\n{ex.StackTrace}";
                System.Diagnostics.Debug.WriteLine(errorDetails);
                throw; // Re-throw to be caught by caller
            }
        }

        private async void ReachabilityWizardWindow_Loaded(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            // Use Dispatcher to ensure UI is fully ready
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                try
                {
                    InitializeStep1();
                }
                catch (Exception ex)
                {
                    // Log to debug output
                    System.Diagnostics.Debug.WriteLine($"Error in Loaded event: {ex.Message}\n{ex.StackTrace}");
                    
                    // Try to show error, but don't fail if window isn't ready
                    try
                    {
                        _ = ShowMessageAsync("Initialization Error", $"Error initializing wizard: {ex.Message}\n\n{ex.StackTrace}");
                    }
                    catch
                    {
                        // If MessageBox fails, just log it
                        System.Diagnostics.Debug.WriteLine("Could not show error message box");
                    }
                }
            });
        }

        private void InitializeStep1()
        {
            // Check critical UI elements first - throw detailed exception if missing
            if (SourceNicComboBox == null)
            {
                throw new InvalidOperationException("SourceNicComboBox is not initialized. XAML may not have loaded correctly.");
            }

            if (ModeARadioButton == null)
            {
                throw new InvalidOperationException("ModeARadioButton is not initialized. XAML may not have loaded correctly.");
            }

            if (_service == null)
            {
                throw new InvalidOperationException("ReachabilityWizardService is not initialized.");
            }

            try
            {
                // Populate NIC combo box
                PopulateNetworkInterfaces();

                // Bind DataGrids (check for null to avoid exceptions)
                if (InsideIpsDataGrid != null)
                    InsideIpsDataGrid.ItemsSource = _insideAssets;
                if (IcmpResultsDataGrid != null)
                    IcmpResultsDataGrid.ItemsSource = _icmpResults;
                if (TcpResultsDataGrid != null)
                    TcpResultsDataGrid.ItemsSource = _tcpResults;
                if (PathHopsDataGrid != null)
                    PathHopsDataGrid.ItemsSource = _pathHops;
                if (DeeperScanResultsDataGrid != null)
                    DeeperScanResultsDataGrid.ItemsSource = _deeperScanResults;

                // Set default mode
                if (ModeARadioButton != null)
                {
                    ModeARadioButton.IsChecked = true;
                    UpdateModeUI();
                }
            }
            catch (Exception ex)
            {
                string errorMsg = $"Error initializing wizard: {ex.Message}";
                if (ex.InnerException != null)
                {
                    errorMsg += $"\n\nInner exception: {ex.InnerException.Message}";
                }
                errorMsg += $"\n\nStack trace: {ex.StackTrace}";
                
                System.Diagnostics.Debug.WriteLine(errorMsg);
                
                // Re-throw to be caught by Loaded event handler
                throw;
            }
        }

        private void ModeRadioButton_Checked(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            UpdateModeUI();
        }

        private void UpdateModeUI()
        {
            try
            {
                if (ModeARadioButton == null)
                    return;

                bool isModeA = ModeARadioButton.IsChecked == true;
                
                // Show/hide cards based on mode (check for null)
                if (TargetNetworkCard != null)
                    TargetNetworkCard.IsVisible = isModeA;
                if (KnownInsideIpsCard != null)
                    KnownInsideIpsCard.IsVisible = isModeA;
                if (ExternalTestIpCard != null)
                    ExternalTestIpCard.IsVisible = !isModeA;
            }
            catch (Exception ex)
            {
                // Silently handle - UI might not be fully loaded
                System.Diagnostics.Debug.WriteLine($"UpdateModeUI error: {ex.Message}");
            }
        }

        private void SourceNicComboBox_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            DiscoverBoundaryDevice();
        }

        private void DiscoverBoundaryDevice()
        {
            try
            {
                if (SourceNicComboBox?.SelectedItem == null || _service == null)
                {
                    if (BoundaryPreviewBorder != null)
                        BoundaryPreviewBorder.IsVisible = false;
                    return;
                }

                var selectedNic = SourceNicComboBox.SelectedItem as dynamic;
                var nicId = selectedNic?.Id as string;

                if (string.IsNullOrEmpty(nicId))
                {
                    if (BoundaryPreviewBorder != null)
                        BoundaryPreviewBorder.IsVisible = false;
                    return;
                }

                var gatewayIp = _service.GetBoundaryGatewayForNic(nicId);
                
                if (BoundaryInfoTextBlock == null || BoundaryPreviewBorder == null)
                    return;

                if (gatewayIp != null)
                {
                    var vendor = _service.GetBoundaryVendor(gatewayIp);
                    var vendorText = !string.IsNullOrEmpty(vendor) ? $" (Vendor: {vendor})" : "";
                    BoundaryInfoTextBlock.Text = $"Boundary device: {gatewayIp}{vendorText}";
                    BoundaryPreviewBorder.IsVisible = true;
                }
                else
                {
                    BoundaryInfoTextBlock.Text = "No default gateway detected for this NIC.";
                    BoundaryPreviewBorder.IsVisible = true;
                }
            }
            catch (Exception ex)
            {
                if (BoundaryInfoTextBlock != null && BoundaryPreviewBorder != null)
                {
                    BoundaryInfoTextBlock.Text = $"Error discovering boundary: {ex.Message}";
                    BoundaryPreviewBorder.IsVisible = true;
                }
            }
        }

        private void PopulateNetworkInterfaces()
        {
            try
            {
                if (SourceNicComboBox == null)
                {
                    System.Diagnostics.Debug.WriteLine("SourceNicComboBox is null in PopulateNetworkInterfaces");
                    return;
                }

                SourceNicComboBox.Items.Clear();
                var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .Select(n =>
                    {
                        try
                        {
                            var ipProps = n.GetIPProperties();
                            var ipv4Address = ipProps?.UnicastAddresses
                                ?.FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                            string displayName = $"{n.Name}";
                            if (ipv4Address != null)
                            {
                                displayName += $" ({ipv4Address.Address})";
                            }

                            return new
                            {
                                DisplayName = displayName,
                                Id = n.Id,
                                Interface = n,
                                IpAddress = ipv4Address?.Address
                            };
                        }
                        catch
                        {
                            // Skip interfaces that cause errors
                            return null;
                        }
                    })
                    .Where(n => n != null)
                    .OrderBy(n => n.DisplayName)
                    .ToList();

                foreach (var nic in interfaces)
                {
                    SourceNicComboBox.Items.Add(nic);
                }

                if (SourceNicComboBox.Items.Count > 0)
                {
                    SourceNicComboBox.SelectedIndex = 0;
                }
            }
            catch (Exception ex)
            {
                _ = ShowMessageAsync("Error", $"Error populating network interfaces: {ex.Message}");
            }
        }

        private async void AddInsideIpButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(InsideIpTextBox.Text))
                {
                    await ShowMessageAsync("Invalid Input", "Please enter an IP address.");
                    return;
                }

                if (!IPAddress.TryParse(InsideIpTextBox.Text, out IPAddress? ip))
                {
                    await ShowMessageAsync("Invalid Input", "Invalid IP address format.");
                    return;
                }

                var asset = new InsideAssetDefinition
                {
                    AssetIp = ip,
                    Label = InsideIpLabelTextBox.Text?.Trim() ?? string.Empty
                };

                _insideAssets.Add(asset);
                InsideIpTextBox.Clear();
                InsideIpLabelTextBox.Clear();
            }
            catch (Exception ex)
            {
                await ShowMessageAsync("Error", $"Error adding inside IP: {ex.Message}");
            }
        }

        private async void RemoveInsideIpButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (sender is Button button && button.Tag is InsideAssetDefinition asset)
                {
                    _insideAssets.Remove(asset);
                }
            }
            catch (Exception ex)
            {
                await ShowMessageAsync("Error", $"Error removing inside IP: {ex.Message}");
            }
        }

        private void BackButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (_currentStep > 1)
            {
                _currentStep--;
                UpdateUI();
            }
        }

        private async void NextButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                // Validate current step
                if (_currentStep == 1)
                {
                    if (!await ValidateStep1())
                        return;

                    // Build context
                    BuildContext();
                }

                // Move to next step
                if (_currentStep < 5)
                {
                    _currentStep++;
                    UpdateUI();

                    // Auto-run step 2, 3, 4 when entering
                    if (_currentStep == 2 && !_step2Completed)
                    {
                        await RunStep2Async();
                    }
                    else if (_currentStep == 3 && !_step3Completed)
                    {
                        await RunStep3Async();
                    }
                    else if (_currentStep == 4 && !_step4Completed)
                    {
                        try
                        {
                            NextButton.IsEnabled = false;
                            NextButton.Content = "Running...";
                            PathProgressBar.IsVisible = true;
                            PathProgressBar.Value = 0;
                            await RunStep4Async();
                        }
                        finally
                        {
                            NextButton.IsEnabled = true;
                            NextButton.Content = "Next";
                            PathProgressBar.IsVisible = false;
                            PathProgressBar.Value = 0;
                        }
                    }
                }
                else if (_currentStep == 5)
                {
                    // Generate summary
                    GenerateSummary();
                    NextButton.Content = "Finish";
                    NextButton.Click -= NextButton_Click;
                    NextButton.Click += FinishButton_Click;
                }
            }
            catch (Exception ex)
            {
                await ShowMessageAsync("Error", $"Error: {ex.Message}");
            }
        }

        private async void FinishButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (_context == null)
                {
                    await ShowMessageAsync("Error", "No test data to save.");
                    Close();
                    return;
                }

                // Disable button during save
                var finishButton = sender as Button;
                if (finishButton != null)
                {
                    finishButton.IsEnabled = false;
                    finishButton.Content = "Saving...";
                }

                // Build ReachabilityWizardResult from collected data
                var wizardResult = new ReachabilityWizardResult
                {
                    Context = _context,
                    IcmpResults = _icmpResults.ToList(),
                    TcpResults = _tcpResults.ToList(),
                    PathResult = _pathResult,
                    DeeperScanResults = _deeperScanResults.ToList(),
                    BoundaryGatewayIp = _context.BoundaryGatewayIp,
                    BoundaryVendor = _context.BoundaryVendor
                };

                // Calculate boundary reachability from results
                if (_context.BoundaryGatewayIp != null)
                {
                    var boundaryIcmp = _icmpResults.FirstOrDefault(r => r.Role == "Boundary device");
                    wizardResult.BoundaryIcmpReachable = boundaryIcmp?.Reachable ?? false;
                    wizardResult.BoundaryAnyTcpReachable = _tcpResults.Any(r => r.TargetIp.Equals(_context.BoundaryGatewayIp) && r.State == Models.TcpState.Open);
                }

                // Save to database
                if (_databaseService != null)
                {
                    await _databaseService.SaveReachabilityTestAsync(wizardResult, null);
                    await ShowMessageAsync("Success", "Reachability test results saved successfully.");
                }
                else
                {
                    await ShowMessageAsync("Warning", "Database service not available. Results were not saved.");
                }

                Close();
            }
            catch (Exception ex)
            {
                await ShowMessageAsync("Error", $"Error saving results: {ex.Message}");
                var finishButton = sender as Button;
                if (finishButton != null)
                {
                    finishButton.IsEnabled = true;
                    finishButton.Content = "Finish";
                }
            }
        }

        private void CancelButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }

        private async Task<bool> ValidateStep1()
        {
            if (SourceNicComboBox.SelectedItem == null)
            {
                await ShowMessageAsync("Validation Error", "Please select a source NIC.");
                return false;
            }

            bool isModeA = ModeARadioButton.IsChecked == true;

            if (isModeA)
            {
                // Mode A: Validate CIDR
                if (string.IsNullOrWhiteSpace(TargetCidrTextBox.Text))
                {
                    await ShowMessageAsync("Validation Error", "Please enter a target CIDR.");
                    return false;
                }

                // Validate CIDR format
                var cidrParts = TargetCidrTextBox.Text.Trim().Split('/');
                if (cidrParts.Length != 2)
                {
                    await ShowMessageAsync("Validation Error", "Invalid CIDR format. Expected format: X.Y.Z.W/N");
                    return false;
                }

                if (!IPAddress.TryParse(cidrParts[0], out _))
                {
                    await ShowMessageAsync("Validation Error", "Invalid IP address in CIDR.");
                    return false;
                }

                if (!int.TryParse(cidrParts[1], out int prefixLength) || prefixLength < 0 || prefixLength > 32)
                {
                    await ShowMessageAsync("Validation Error", "Invalid prefix length in CIDR. Must be between 0 and 32.");
                    return false;
                }
            }
            else
            {
                // Mode B: Validate external test IP (optional, but if provided must be valid)
                if (!string.IsNullOrWhiteSpace(ExternalTestIpTextBox.Text))
                {
                    if (!IPAddress.TryParse(ExternalTestIpTextBox.Text.Trim(), out _))
                    {
                        await ShowMessageAsync("Validation Error", "Invalid external test IP address.");
                        return false;
                    }
                }
            }

            return true;
        }

        private void BuildContext()
        {
            var selectedNic = SourceNicComboBox.SelectedItem as dynamic;
            var ipAddress = selectedNic?.IpAddress as IPAddress;
            var nicId = selectedNic?.Id ?? string.Empty;

            bool isModeA = ModeARadioButton.IsChecked == true;

            // Discover boundary device
            IPAddress? boundaryIp = null;
            string? boundaryVendor = null;
            if (_service != null && !string.IsNullOrEmpty(nicId))
            {
                boundaryIp = _service.GetBoundaryGatewayForNic(nicId);
                if (boundaryIp != null)
                {
                    boundaryVendor = _service.GetBoundaryVendor(boundaryIp);
                }
            }

            // Parse external test IP for Mode B
            IPAddress? externalTestIp = null;
            if (!isModeA && !string.IsNullOrWhiteSpace(ExternalTestIpTextBox.Text))
            {
                if (IPAddress.TryParse(ExternalTestIpTextBox.Text.Trim(), out IPAddress? parsedIp))
                {
                    externalTestIp = parsedIp;
                }
            }
            else if (!isModeA)
            {
                // Default to 8.8.8.8 if not specified
                externalTestIp = IPAddress.Parse("8.8.8.8");
            }

            _context = new AnalysisContext
            {
                Mode = isModeA ? AnalysisMode.RemoteNetworkKnown : AnalysisMode.BoundaryOnly,
                VantagePointName = VantagePointNameTextBox.Text.Trim(),
                SourceNicId = nicId,
                SourceIp = ipAddress ?? IPAddress.None,
                TargetNetworkName = isModeA ? TargetNetworkNameTextBox.Text.Trim() : string.Empty,
                TargetCidr = isModeA ? TargetCidrTextBox.Text.Trim() : string.Empty,
                InsideAssets = isModeA ? _insideAssets.ToList() : new List<InsideAssetDefinition>(),
                BoundaryGatewayIp = boundaryIp,
                BoundaryVendor = boundaryVendor,
                ExternalTestIp = externalTestIp
            };
        }

        private void UpdateUI()
        {
            // Update step panels visibility
            Step1Panel.IsVisible = _currentStep == 1;
            Step2Panel.IsVisible = _currentStep == 2;
            Step3Panel.IsVisible = _currentStep == 3;
            Step4Panel.IsVisible = _currentStep == 4;
            Step5Panel.IsVisible = _currentStep == 5;

            // Update title and description
            UpdateStepHeader();

            // Update navigation buttons
            BackButton.IsEnabled = _currentStep > 1;
            
            if (_currentStep == 5)
            {
                NextButton.Content = "Finish";
            }
            else
            {
                NextButton.Content = "Next";
            }

            // Update status label
            StatusLabel.Text = $"Step {_currentStep} of 5";
        }

        private void UpdateStepHeader()
        {
            switch (_currentStep)
            {
                case 1:
                    StepTitleTextBlock.Text = "Step 1: Define Vantage Point & Target Network";
                    StepDescriptionTextBlock.Text = "Configure your vantage point and select analysis mode. The boundary device (default gateway) will be automatically discovered.";
                    break;
                case 2:
                    StepTitleTextBlock.Text = "Step 2: ICMP Reachability";
                    if (_context?.Mode == AnalysisMode.RemoteNetworkKnown)
                    {
                        StepDescriptionTextBlock.Text = "We send ICMP echo (ping) to the boundary device, target network gateway candidates, and any known inside IPs to see if they respond.";
                    }
                    else
                    {
                        StepDescriptionTextBlock.Text = "We send ICMP echo (ping) to the boundary device and external test target to check basic connectivity.";
                    }
                    break;
                case 3:
                    StepTitleTextBlock.Text = "Step 3: TCP Reachability";
                    StepDescriptionTextBlock.Text = "We check basic TCP connectivity to common service ports. This detects reachability even if ICMP is blocked. Boundary device is tested first.";
                    break;
                case 4:
                    StepTitleTextBlock.Text = "Step 4: Path Analysis";
                    if (_context?.Mode == AnalysisMode.RemoteNetworkKnown)
                    {
                        StepDescriptionTextBlock.Text = "We trace the path towards the target network to identify where traffic stops. Even if targets don't respond, we'll show where the path ends.";
                    }
                    else
                    {
                        StepDescriptionTextBlock.Text = "We trace the path to the external test target to see if traffic can pass through the boundary device.";
                    }
                    break;
                case 5:
                    StepTitleTextBlock.Text = "Step 5: Optional Deeper Scan & Summary";
                    StepDescriptionTextBlock.Text = "Perform deeper port scanning on reachable hosts and view the complete analysis summary including boundary device status.";
                    break;
            }
        }

        private async Task RunStep2Async()
        {
            if (_context == null || _service == null)
                return;

            try
            {
                RunIcmpChecksButton.IsEnabled = false;
                _cancellationTokenSource = new CancellationTokenSource();
                var token = _cancellationTokenSource.Token;

                var progress = new Progress<(string message, int percent)>(update =>
                {
                    _ = Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        IcmpStatusTextBlock.Text = update.message;
                        IcmpProgressBar.Value = update.percent;
                    });
                });

                var results = await _service.RunIcmpChecksAsync(_context, progress, token);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    _icmpResults.Clear();
                    
                    // Add boundary device first, then others
                    var boundaryResult = results.FirstOrDefault(r => r.Role == "Boundary device");
                    if (boundaryResult != null)
                    {
                        _icmpResults.Add(boundaryResult);
                    }
                    
                    foreach (var result in results.Where(r => r.Role != "Boundary device"))
                    {
                        _icmpResults.Add(result);
                    }

                    // Update status
                    var reachableCount = results.Count(r => r.Reachable);
                    var boundaryReachable = boundaryResult?.Reachable == true;
                    
                    string statusText = $"Boundary: {(boundaryReachable ? "reachable" : "not reachable")}";
                    
                    if (_context?.Mode == AnalysisMode.RemoteNetworkKnown)
                    {
                        var gatewayReachable = results.Count(r => r.Role == "Gateway candidate" && r.Reachable);
                        var assetReachable = results.Count(r => r.Role == "Known asset" && r.Reachable);
                        var remoteReachable = results.Count(r => r.Role != "Boundary device" && r.Reachable);
                        statusText += $". Remote targets: {remoteReachable}/{results.Count(r => r.Role != "Boundary device")} reachable";
                    }
                    else
                    {
                        var externalReachable = results.Count(r => r.Role == "External test target" && r.Reachable);
                        if (results.Any(r => r.Role == "External test target"))
                        {
                            statusText += $". External test: {(externalReachable > 0 ? "reachable" : "not reachable")}";
                        }
                    }
                    
                    IcmpStatusTextBlock.Text = statusText;

                    _step2Completed = true;
                });
            }
            catch (OperationCanceledException)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    IcmpStatusTextBlock.Text = "ICMP checks canceled.";
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    await ShowMessageAsync("Error", $"Error running ICMP checks: {ex.Message}");
                });
            }
        }

        private async void RunIcmpChecksButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                RunIcmpChecksButton.IsEnabled = false;
                RunIcmpChecksButton.Content = "Running...";
                IcmpProgressBar.IsVisible = true;
                IcmpProgressBar.Value = 0;
                await RunStep2Async();
            }
            finally
            {
                RunIcmpChecksButton.IsEnabled = true;
                RunIcmpChecksButton.Content = "Run ICMP Checks";
                IcmpProgressBar.IsVisible = false;
                IcmpProgressBar.Value = 0;
            }
        }

        private async Task RunStep3Async()
        {
            if (_context == null || _service == null)
                return;

            try
            {
                // Button state is managed by RunTcpChecksButton_Click wrapper

                // Parse probe ports
                var portStrings = TcpProbePortsTextBox.Text.Split(',', StringSplitOptions.RemoveEmptyEntries);
                var ports = new List<int>();
                foreach (var portStr in portStrings)
                {
                    if (int.TryParse(portStr.Trim(), out int port) && port > 0 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }

                if (ports.Count == 0)
                {
                    await ShowMessageAsync("Invalid Input", "Please enter valid probe ports (e.g., 22,80,443).");
                    return;
                }

                _cancellationTokenSource = new CancellationTokenSource();
                var token = _cancellationTokenSource.Token;

                var progress = new Progress<(string message, int percent)>(update =>
                {
                    _ = Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        TcpProgressBar.Value = update.percent;
                        // Could update a status label here if needed
                    });
                });

                var results = await _service.RunTcpChecksAsync(_context, _icmpResults, ports, progress, token);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    _tcpResults.Clear();
                    
                    // Add boundary device results first, then others
                    var boundaryIps = results.Where(r => _context?.BoundaryGatewayIp != null && r.TargetIp.Equals(_context.BoundaryGatewayIp));
                    foreach (var result in boundaryIps)
                    {
                        _tcpResults.Add(result);
                    }
                    
                    foreach (var result in results.Where(r => _context?.BoundaryGatewayIp == null || !r.TargetIp.Equals(_context.BoundaryGatewayIp)))
                    {
                        _tcpResults.Add(result);
                    }

                    _step3Completed = true;
                    RunTcpChecksButton.IsEnabled = true;
                });
            }
            catch (OperationCanceledException)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    // Button state restored by wrapper
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    await ShowMessageAsync("Error", $"Error running TCP checks: {ex.Message}");
                });
            }
        }

        private async void RunTcpChecksButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                RunTcpChecksButton.IsEnabled = false;
                RunTcpChecksButton.Content = "Running...";
                TcpProgressBar.IsVisible = true;
                await RunStep3Async();
            }
            finally
            {
                RunTcpChecksButton.IsEnabled = true;
                RunTcpChecksButton.Content = "Run TCP Checks";
                TcpProgressBar.IsVisible = false;
            }
        }

        private async Task RunStep4Async()
        {
            if (_context == null || _service == null)
                return;

            try
            {
                // Button state is managed by NextButton_Click wrapper when calling this

                // Determine target IP for display
                IPAddress? targetIp = null;
                if (_context.Mode == AnalysisMode.RemoteNetworkKnown)
                {
                    // Prefer reachable target, else first gateway candidate or known asset
                    var reachableIps = _icmpResults
                        .Where(r => r.Reachable && r.Role != "Boundary device")
                        .Select(r => r.TargetIp)
                        .Concat(_tcpResults
                            .Where(r => r.State != Models.TcpState.Filtered)
                            .Select(r => r.TargetIp))
                        .Distinct()
                        .ToList();

                    if (reachableIps.Any())
                    {
                        targetIp = reachableIps.First();
                    }
                    else
                    {
                        // Fallback to first gateway candidate or known asset
                        var gatewayCandidates = _service.ExtractGatewayCandidates(_context.TargetCidr);
                        targetIp = gatewayCandidates.FirstOrDefault() ?? _context.InsideAssets.FirstOrDefault()?.AssetIp;
                    }
                }
                else
                {
                    targetIp = _context.ExternalTestIp;
                }

                if (targetIp != null)
                {
                    PathTargetIpTextBox.Text = targetIp.ToString();
                }

                _cancellationTokenSource = new CancellationTokenSource();
                var token = _cancellationTokenSource.Token;

                var progress = new Progress<(string message, int percent)>(update =>
                {
                    _ = Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        PathNotesTextBlock.Text = update.message;
                        PathProgressBar.Value = update.percent;
                    });
                });

                var result = await _service.RunPathAnalysisAsync(_context, _icmpResults, _tcpResults, progress, token);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (result != null)
                    {
                        _pathResult = result; // Store the path result for saving
                        PathTargetIpTextBox.Text = result.TargetIpString;
                        _pathHops.Clear();
                        foreach (var hop in result.Hops)
                        {
                            _pathHops.Add(hop);
                        }
                        PathNotesTextBlock.Text = result.Notes ?? "Path analysis completed.";
                        _step4Completed = true;
                    }
                    else
                    {
                        _pathResult = null;
                        PathNotesTextBlock.Text = "No suitable target found for path analysis.";
                    }
                });
            }
            catch (OperationCanceledException)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    PathNotesTextBlock.Text = "Path analysis canceled.";
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    await ShowMessageAsync("Error", $"Error running path analysis: {ex.Message}");
                });
            }
        }

        private async void RunDeeperScanButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (_context == null || _service == null)
                return;

            try
            {
                RunDeeperScanButton.IsEnabled = false;
                RunDeeperScanButton.Content = "Running...";
                DeeperScanProgressBar.IsVisible = true;

                // Parse scan ports
                var portStrings = DeeperScanPortsTextBox.Text.Split(',', StringSplitOptions.RemoveEmptyEntries);
                var ports = new List<int>();
                foreach (var portStr in portStrings)
                {
                    if (int.TryParse(portStr.Trim(), out int port) && port > 0 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }

                if (ports.Count == 0)
                {
                    await ShowMessageAsync("Invalid Input", "Please enter valid ports to scan.");
                    RunDeeperScanButton.IsEnabled = true;
                    RunDeeperScanButton.Content = "Run deeper scan";
                    return;
                }

                _cancellationTokenSource = new CancellationTokenSource();
                var token = _cancellationTokenSource.Token;

                DeeperScanProgressBar.Value = 0;

                var progress = new Progress<(string message, int percent)>(update =>
                {
                    _ = Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        DeeperScanProgressBar.Value = update.percent;
                    });
                });

                var results = await _service.RunDeeperScanAsync(_context, _icmpResults, _tcpResults, ports, progress, token);

                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    _deeperScanResults.Clear();
                    foreach (var result in results)
                    {
                        _deeperScanResults.Add(result);
                    }

                    _step5Completed = true;
                    RunDeeperScanButton.IsEnabled = true;
                    RunDeeperScanButton.Content = "Run deeper scan";
                    DeeperScanProgressBar.IsVisible = false;
                    DeeperScanProgressBar.Value = 0;
                    GenerateSummary(); // Regenerate summary with deeper scan results
                });
            }
            catch (OperationCanceledException)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    RunDeeperScanButton.IsEnabled = true;
                    RunDeeperScanButton.Content = "Run deeper scan";
                    DeeperScanProgressBar.IsVisible = false;
                    DeeperScanProgressBar.Value = 0;
                });
            }
            catch (Exception ex)
            {
                await Dispatcher.UIThread.InvokeAsync(async () =>
                {
                    await ShowMessageAsync("Error", $"Error running deeper scan: {ex.Message}");
                    RunDeeperScanButton.IsEnabled = true;
                    RunDeeperScanButton.Content = "Run deeper scan";
                    DeeperScanProgressBar.IsVisible = false;
                    DeeperScanProgressBar.Value = 0;
                });
            }
        }

        private void GenerateSummary()
        {
            if (_context == null)
                return;

            var summary = new StringBuilder();
            summary.AppendLine($"Vantage Point: {_context.VantagePointName} ({_context.SourceIp})");
            summary.AppendLine($"Target Network: {_context.TargetNetworkName} ({_context.TargetCidr})");
            summary.AppendLine();

            // Boundary device summary
            if (_context.BoundaryGatewayIp != null)
            {
                var boundaryIcmp = _icmpResults.FirstOrDefault(r => r.Role == "Boundary device");
                var boundaryTcp = _tcpResults.Where(r => r.TargetIp.Equals(_context.BoundaryGatewayIp)).ToList();
                var boundaryTcpOpen = boundaryTcp.Count(r => r.State == Models.TcpState.Open);
                
                summary.AppendLine("Boundary Device:");
                summary.AppendLine($"  {_context.BoundaryGatewayIp}" + 
                    (!string.IsNullOrEmpty(_context.BoundaryVendor) ? $" (Vendor: {_context.BoundaryVendor})" : ""));
                summary.AppendLine($"  ICMP: {(boundaryIcmp?.Reachable == true ? "reachable" : "not reachable")}");
                summary.AppendLine($"  TCP: {(boundaryTcpOpen > 0 ? $"{boundaryTcpOpen} ports open" : "no open ports")}");
                summary.AppendLine();
            }

            // ICMP Summary
            summary.AppendLine("ICMP Reachability:");
            var icmpReachable = _icmpResults.Count(r => r.Reachable);
            summary.AppendLine($"  {icmpReachable}/{_icmpResults.Count} targets reachable via ICMP");
            
            if (_context.Mode == AnalysisMode.RemoteNetworkKnown)
            {
                var gatewayReachable = _icmpResults.Count(r => r.Role == "Gateway candidate" && r.Reachable);
                summary.AppendLine($"  Remote gateways: {gatewayReachable}/{_icmpResults.Count(r => r.Role == "Gateway candidate")} reachable");
            }
            summary.AppendLine();

            // TCP Summary
            summary.AppendLine("TCP Reachability:");
            var tcpOpen = _tcpResults.Count(r => r.State == Models.TcpState.Open);
            var tcpClosed = _tcpResults.Count(r => r.State == Models.TcpState.Closed);
            summary.AppendLine($"  {tcpOpen} ports open, {tcpClosed} ports closed");
            summary.AppendLine();

            // Path Summary
            if (_pathHops.Count > 0)
            {
                summary.AppendLine("Path Analysis:");
                var pathResult = new PathAnalysisResult { Hops = _pathHops.ToList() };
                if (pathResult.Completed)
                {
                    summary.AppendLine($"  Path completed in {_pathHops.Count} hops");
                }
                else
                {
                    summary.AppendLine($"  Path stopped at hop {_pathHops.Count}");
                }
                if (_pathHops.LastOrDefault()?.HopIp != null)
                {
                    summary.AppendLine($"  Last hop: {_pathHops.Last().HopIpString}");
                }
                summary.AppendLine();
            }
            else if (_context.Mode == AnalysisMode.RemoteNetworkKnown)
            {
                summary.AppendLine("Path Analysis:");
                summary.AppendLine("  Path analysis attempted but no hops recorded.");
                summary.AppendLine();
            }

            // Deeper Scan Summary
            if (_deeperScanResults.Count > 0)
            {
                summary.AppendLine("Deeper Scan Results:");
                foreach (var scan in _deeperScanResults)
                {
                    summary.AppendLine($"  {scan.TargetIpString}: {scan.Summary}");
                }
            }

            SummaryTextBlock.Text = summary.ToString();
        }

        private async Task ShowMessageAsync(string title, string message)
        {
            var msgBox = new Window
            {
                Title = title,
                Content = new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                Width = 400,
                Height = 200,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            };
            await msgBox.ShowDialog(this);
        }
    }
}

