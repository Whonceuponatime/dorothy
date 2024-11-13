using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Controllers;
using Dorothy.Models;
using NLog;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Dorothy.Views
{
    public partial class MainWindow : Window
    {
        private readonly MainController _mainController;
        private readonly NetworkStorm _networkStorm;
        private readonly ILogger _logger = LogManager.GetCurrentClassLogger();
        private string? _sourceIp;

        public MainWindow()
        {
            InitializeComponent();
            _networkStorm = new NetworkStorm(LogTextBox);
            _mainController = new MainController(_networkStorm, StartButton, StopButton, StatusLabel, LogTextBox, this);
            NetworkInterfaceComboBox.SelectionChanged += NetworkInterfaceComboBox_SelectionChanged;
            AttackTypeComboBox.SelectionChanged += AttackTypeComboBox_SelectionChanged;
            AdvancedAttackTypeComboBox.SelectionChanged += AdvancedAttackTypeComboBox_SelectionChanged;
            PopulateNetworkInterfaces();
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            string targetIp = TargetIpTextBox.Text.Trim();
            string portText = TargetPortTextBox.Text.Trim();
            string mbpsText = MegabitsPerSecondTextBox.Text.Trim();

            if (string.IsNullOrEmpty(targetIp))
            {
                MessageBox.Show("Please enter a Target IP.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!IPAddress.TryParse(targetIp, out IPAddress? ipAddress))
            {
                MessageBox.Show("Please enter a valid Target IP.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                MessageBox.Show("Only IPv4 addresses are supported.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!int.TryParse(portText, out int targetPort))
            {
                MessageBox.Show("Please enter a valid Target Port.", "Invalid Port", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!long.TryParse(mbpsText, out long mbps))
            {
                MessageBox.Show("Please enter a valid Mbps value.", "Invalid Mbps", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var selectedAttackTypeItem = AttackTypeComboBox.SelectedItem as ComboBoxItem;
            if (selectedAttackTypeItem == null)
            {
                MessageBox.Show("Please select an Attack Type.", "No Attack Type Selected", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string attackTypeContent = selectedAttackTypeItem.Content?.ToString() ?? string.Empty;
            AttackType attackType;
            switch (attackTypeContent)
            {
                case "TCP SYN Flood":
                    attackType = AttackType.SynFlood;
                    break;
                case "UDP Flood":
                    attackType = AttackType.UdpFlood;
                    break;
                case "ICMP Flood":
                    attackType = AttackType.IcmpFlood;
                    break;
                case "HTTP Flood":
                    attackType = AttackType.HttpFlood;
                    break;
                default:
                    MessageBox.Show("Invalid Attack Type selected.", "Invalid Attack Type", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
            }

            await _mainController.StartAttackAsync(attackType, targetIp, targetPort, mbps);
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            await _mainController.StopAttackAsync();
        }

        private void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (NetworkInterfaceComboBox.SelectedItem is ComboBoxItem selectedItem && selectedItem.Tag is NetworkInterface selectedInterface)
            {
                var ipProperties = selectedInterface.GetIPProperties();
                var unicastAddress = ipProperties.UnicastAddresses
                                               .FirstOrDefault(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

                if (unicastAddress != null)
                {
                    _sourceIp = unicastAddress.Address.ToString();
                    SourceIpTextBox.Text = _sourceIp;
                    SetSourceMac(selectedInterface);
                }
                else
                {
                    _sourceIp = null;
                    SourceIpTextBox.Text = "No IPv4 Address";
                    SourceMacTextBox.Text = "N/A";
                }
            }
        }

        private void AttackTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle Attack Type selection changes if necessary
        }

        private void AdvancedAttackTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle Advanced Attack Type selection changes if necessary
        }

        private async void LoadInformationButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetIp = TargetIpTextBox.Text.Trim();

                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("Please enter a Target IP to load information.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!IPAddress.TryParse(targetIp, out IPAddress? ipAddress))
                {
                    MessageBox.Show("Please enter a valid Target IP.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Show loading indicator
                PingButton.IsEnabled = false;
                PingButton.Content = "Pinging...";

                // Perform the async operation
                var pingResult = await _mainController.PingHostAsync(targetIp);
                LogResult($"Ping result for {targetIp}: {(pingResult.Success ? "Success" : "Failed")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error pinging host: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                PingButton.IsEnabled = true;
                PingButton.Content = "Ping";
            }
        }

        private async void GetMacButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetIp = TargetIpTextBox.Text.Trim();

                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("Please enter a Target IP first.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (!IPAddress.TryParse(targetIp, out IPAddress? ipAddress))
                {
                    MessageBox.Show("Please enter a valid Target IP.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Show loading indicator
                GetMacButton.IsEnabled = false;
                GetMacButton.Content = "Getting MAC...";

                // Get MAC address using the existing method
                string macAddress = GetMacAddress(targetIp);
                TargetMacTextBox.Text = macAddress;
                LogResult($"MAC Address for {targetIp}: {macAddress}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error getting MAC address: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                GetMacButton.IsEnabled = true;
                GetMacButton.Content = "Get MAC";
            }
        }

        private void PopulateNetworkInterfaces()
        {
            NetworkInterfaceComboBox.Items.Clear();
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                                            .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback && ni.OperationalStatus == OperationalStatus.Up);

            foreach (var ni in interfaces)
            {
                ComboBoxItem item = new ComboBoxItem
                {
                    Content = ni.Name, // Display the interface name
                    Tag = ni
                };
                NetworkInterfaceComboBox.Items.Add(item);
            }

            if (NetworkInterfaceComboBox.Items.Count > 0)
                NetworkInterfaceComboBox.SelectedIndex = 0;
        }

        private void LogResult(string message)
        {
            LogTextBox.AppendText(message + Environment.NewLine);
            LogTextBox.ScrollToEnd();
        }

        private void SetSourceMac(NetworkInterface networkInterface)
        {
            byte[] macBytes = networkInterface.GetPhysicalAddress().GetAddressBytes();
            string formattedMac = BytesToMacString(macBytes);
            SourceMacTextBox.Text = formattedMac;
            _networkStorm.SetSourceInfo(_sourceIp, macBytes);
        }

        private string BytesToMacString(byte[] macBytes)
        {
            return string.Join(":", macBytes.Select(b => b.ToString("X2")));
        }

        private async void ApplyAdvancedSettings_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Retrieve values from Advanced Settings UI controls
                if (AdvancedAttackTypeComboBox.SelectedItem is ComboBoxItem selectedAdvancedAttackTypeItem)
                {
                    string additionalAttackType = selectedAdvancedAttackTypeItem.Content?.ToString() ?? string.Empty;
                    bool enableLogging = EnableLoggingCheckBox.IsChecked ?? false;
                    string customParameters = CustomParametersTextBox.Text;

                    await _mainController.ApplyAdvancedSettingsAsync(additionalAttackType, enableLogging, customParameters);
                    LogResult("Advanced settings applied successfully.");
                }
                else
                {
                    MessageBox.Show("Please select an additional attack type.", "Missing Selection", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to apply advanced settings.");
                MessageBox.Show($"Failed to apply advanced settings: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(Int32 destIp, Int32 srcIp, ref Int64 macAddress, ref Int32 physicalAddrLen);

        [DllImport("ws2_32.dll")]
        private static extern Int32 inet_addr(string ipAddress);

        private string GetMacAddress(string ipAddress)
        {
            try
            {
                Int32 destIp = inet_addr(ipAddress);
                Int32 srcIp = 0;
                long macAddr = 0;
                Int32 macAddrLen = 6;

                int result = SendARP(destIp, srcIp, ref macAddr, ref macAddrLen);

                if (result != 0)
                {
                    throw new Exception($"SendARP failed with error code {result}.");
                }

                byte[] macBytes = BitConverter.GetBytes(macAddr);
                // Ensure correct byte order
                Array.Reverse(macBytes);
                string mac = BitConverter.ToString(macBytes).Substring(0, macAddrLen * 3 - 1);
                return mac;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Failed to retrieve MAC address.");
                return "Error Retrieving MAC Address";
            }
        }

    } 
} 