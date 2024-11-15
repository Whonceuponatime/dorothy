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
using Microsoft.Win32;
using System.IO;
using System.Windows.Media.Animation;
using System.Collections.Generic;

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
            PopulateNetworkInterfaces();
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            try
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
                    default:
                        MessageBox.Show("Invalid Attack Type selected.", "Invalid Attack Type", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                }

                LockBasicControls(true);
                await _mainController.StartAttackAsync(attackType, targetIp, targetPort, mbps);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting attack: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LockBasicControls(false);
            }
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await _mainController.StopAttackAsync();
                LockBasicControls(false);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error stopping attack: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LockBasicControls(false);
            }
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

            SyncNetworkInfo();
        }

        private void AttackTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle Attack Type selection changes if necessary
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
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            string logMessage = $"[{timestamp}] {message}{Environment.NewLine}";
            LogTextBox.AppendText(logMessage);
            AdvLogTextBox.AppendText(logMessage);
            LogTextBox.ScrollToEnd();
            AdvLogTextBox.ScrollToEnd();
        }

        private void SetSourceMac(NetworkInterface networkInterface)
        {
            byte[] macBytes = networkInterface.GetPhysicalAddress().GetAddressBytes();
            string formattedMac = BytesToMacString(macBytes);
            SourceMacTextBox.Text = formattedMac;
            if (_sourceIp != null)
            {
                _networkStorm.SetSourceInfo(_sourceIp, macBytes);
            }
        }

        private string BytesToMacString(byte[] macBytes)
        {
            return string.Join(":", macBytes.Select(b => b.ToString("X2")));
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

        private void ArpTargetIpTextBox_LostFocus(object sender, RoutedEventArgs e)
        {
            if (sender is TextBox textBox)
            {
                string ipAddress = textBox.Text.Trim();
                if (!string.IsNullOrEmpty(ipAddress))
                {
                    try
                    {
                        IPAddress.Parse(ipAddress); // Validate IP address format
                    }
                    catch
                    {
                        MessageBox.Show("Invalid IP address format", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        textBox.Text = string.Empty;
                    }
                }
            }
        }

        private async void PingButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string targetIp = TargetIpTextBox.Text.Trim();
                if (string.IsNullOrEmpty(targetIp))
                {
                    MessageBox.Show("Please enter a Target IP.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                PingButton.IsEnabled = false;
                var result = await _mainController.PingHostAsync(targetIp);
                
                if (result.Success)
                {
                    LogResult($"Ping successful! Round-trip time: {result.RoundtripTime}ms");
                }
                else
                {
                    LogResult("Ping failed!");
                }
            }
            catch (Exception ex)
            {
                LogResult($"Error during ping: {ex.Message}");
            }
            finally
            {
                PingButton.IsEnabled = true;
            }
        }

        private void SyncNetworkInfo()
        {
            // Sync Source Information
            AdvSourceIpTextBox.Text = SourceIpTextBox.Text;
            AdvSourceMacTextBox.Text = SourceMacTextBox.Text;
            
            // Sync Target Information
            AdvTargetIpTextBox.Text = TargetIpTextBox.Text;
            AdvTargetMacTextBox.Text = TargetMacTextBox.Text;
        }

        private async void StartAdvancedAttack_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                LockAdvancedControls(true);
                
                var selectedAttackTypeItem = AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem;
                if (selectedAttackTypeItem != null)
                {
                    string attackTypeContent = selectedAttackTypeItem.Content?.ToString() ?? string.Empty;
                    switch (attackTypeContent)
                    {
                        case "ARP Spoofing":
                            await StartArpSpoofing();
                            break;
                        case "Broadcast Attack":
                            await StartBroadcastAttack();
                            break;
                        case "Multicast Attack":
                            await StartMulticastAttack();
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting attack: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LockAdvancedControls(false);
            }
        }

        private async void StopAdvancedAttack_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var selectedAttackTypeItem = AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem;
                if (selectedAttackTypeItem != null)
                {
                    string attackTypeContent = selectedAttackTypeItem.Content?.ToString() ?? string.Empty;
                    switch (attackTypeContent)
                    {
                        case "ARP Spoofing":
                            await _mainController.StopArpSpoofingAsync();
                            break;
                        case "Broadcast Attack":
                            await _mainController.StopBroadcastAttackAsync();
                            break;
                        case "Multicast Attack":
                            await _mainController.StopMulticastAttackAsync();
                            break;
                    }
                }
                LockAdvancedControls(false);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error stopping attack: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                LockAdvancedControls(false);
            }
        }

        private async Task StartArpSpoofing()
        {
            if (string.IsNullOrEmpty(AdvTargetIpTextBox.Text) || 
                string.IsNullOrEmpty(AdvTargetMacTextBox.Text))
            {
                throw new InvalidOperationException("Target information is required for ARP spoofing");
            }

            StartAdvancedAttackButton.IsEnabled = false;
            StopAdvancedAttackButton.IsEnabled = true;  // Enable immediately

            await _mainController.StartArpSpoofingAsync(
                AdvSourceIpTextBox.Text,
                AdvSourceMacTextBox.Text,
                AdvTargetIpTextBox.Text,
                AdvTargetMacTextBox.Text.Replace('-', ':'),
                SpoofedMacTextBox.Text.Replace('-', ':')
            );
        }

        private async Task StartBroadcastAttack()
        {
            if (string.IsNullOrEmpty(AdvTargetIpTextBox.Text))
            {
                throw new InvalidOperationException("Target IP is required for Broadcast attack");
            }

            if (!int.TryParse(AdvTargetPortTextBox.Text, out int targetPort))
            {
                throw new InvalidOperationException("Invalid target port");
            }

            if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out long mbps))
            {
                throw new InvalidOperationException("Invalid megabits per second value");
            }

            await _mainController.StartBroadcastAttackAsync(
                AdvTargetIpTextBox.Text,
                targetPort,
                mbps
            );
        }

        private async Task StartMulticastAttack()
        {
            if (string.IsNullOrEmpty(AdvTargetIpTextBox.Text))
            {
                throw new InvalidOperationException("Target IP is required for Multicast attack");
            }

            if (!int.TryParse(AdvTargetPortTextBox.Text, out int targetPort))
            {
                throw new InvalidOperationException("Invalid target port");
            }

            if (!long.TryParse(AdvMegabitsPerSecondTextBox.Text, out long mbps))
            {
                throw new InvalidOperationException("Invalid megabits per second value");
            }

            await _mainController.StartMulticastAttackAsync(
                AdvTargetIpTextBox.Text,
                targetPort,
                mbps
            );
        }

        private void AdvancedAttackTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedItem = AdvancedAttackTypeComboBox.SelectedItem as ComboBoxItem;
            if (selectedItem != null)
            {
                bool isArpSpoof = selectedItem.Content.ToString() == "ARP Spoofing";
                
                // Show/hide fields based on attack type
                AdvTargetPortTextBox.IsEnabled = !isArpSpoof;
                AdvMegabitsPerSecondTextBox.IsEnabled = !isArpSpoof;
                SpoofedMacTextBox.IsEnabled = isArpSpoof;
            }
        }

        private async void AdvTargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                string targetIp = AdvTargetIpTextBox.Text.Trim();
                if (string.IsNullOrEmpty(targetIp) || !IPAddress.TryParse(targetIp, out _))
                {
                    AdvTargetMacTextBox.Text = string.Empty;
                    return;
                }

                // Use existing ping functionality
                var pingResult = await _mainController.PingHostAsync(targetIp);
                if (pingResult.Success)
                {
                    string macAddress = await _mainController.GetMacAddressAsync(targetIp);
                    if (!string.IsNullOrEmpty(macAddress))
                    {
                        AdvTargetMacTextBox.Text = macAddress;
                    }
                }
            }
            catch (Exception ex)
            {
                LogResult($"Failed to get MAC address: {ex.Message}");
            }
        }

        private void SpoofedMacTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var textBox = (TextBox)sender;
            string text = textBox.Text.Replace(":", "").Replace("-", "");
            
            if (text.Length > 12)
            {
                text = text.Substring(0, 12);
            }

            // Format with colons
            string formattedText = string.Empty;
            for (int i = 0; i < text.Length; i++)
            {
                if (i > 0 && i % 2 == 0 && i < text.Length)
                {
                    formattedText += ":";
                }
                formattedText += text[i];
            }

            textBox.Text = formattedText;
            textBox.CaretIndex = formattedText.Length;
        }

        private async void SaveLogButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*",
                DefaultExt = "log",
                FileName = $"Dorothy_Log_{DateTime.Now:yyyyMMdd_HHmmss}.log"
            };

            if (dialog.ShowDialog() == true)
            {
                var textBox = ((Button)sender).Name.StartsWith("Adv") ? AdvLogTextBox : LogTextBox;
                await File.WriteAllTextAsync(dialog.FileName, textBox.Text);
                LogResult("Log file saved successfully");
            }
        }

        private void ClearLogButton_Click(object sender, RoutedEventArgs e)
        {
            var textBox = ((Button)sender).Name.StartsWith("Adv") ? AdvLogTextBox : LogTextBox;
            textBox.Clear();
            LogResult("Log cleared");
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            // Set default attack type to ARP Spoofing
            AdvancedAttackTypeComboBox.SelectedIndex = 0;
            SyncNetworkInfo();
        }

        private bool CheckAdvancedPassword()
        {
            var passwordDialog = new PasswordBox
            {
                Width = 200,
                Margin = new Thickness(10)
            };

            var dialog = new Window
            {
                Title = "Advanced Settings Authentication",
                Width = 300,
                Height = 150,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                ResizeMode = ResizeMode.NoResize
            };

            var stackPanel = new StackPanel
            {
                Margin = new Thickness(10)
            };
            
            stackPanel.Children.Add(new TextBlock 
            { 
                Text = "Enter password:", 
                Margin = new Thickness(0, 0, 0, 10) 
            });
            stackPanel.Children.Add(passwordDialog);

            var buttonPanel = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 10, 0, 0)
            };

            var okButton = new Button
            {
                Content = "OK",
                Width = 60,
                Margin = new Thickness(0, 0, 10, 0)
            };
            var cancelButton = new Button
            {
                Content = "Cancel",
                Width = 60
            };

            okButton.Click += (s, e) => { dialog.DialogResult = true; };
            cancelButton.Click += (s, e) => { dialog.DialogResult = false; };

            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            stackPanel.Children.Add(buttonPanel);

            dialog.Content = stackPanel;

            if (dialog.ShowDialog() == true)
            {
                return passwordDialog.Password == "dagger";
            }

            return false;
        }

        private void TabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (e.Source is TabControl tabControl && tabControl.SelectedItem == AdvancedTab)
            {
                if (!CheckAdvancedPassword())
                {
                    tabControl.SelectedIndex = 0; // Switch back to basic tab
                    MessageBox.Show("Invalid password!", "Authentication Failed", 
                                  MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }

        private async void TargetIpTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            try
            {
                string targetIp = TargetIpTextBox.Text.Trim();
                if (string.IsNullOrEmpty(targetIp) || !IPAddress.TryParse(targetIp, out _))
                {
                    TargetMacTextBox.Text = string.Empty;
                    return;
                }

                // Use existing ping functionality
                var pingResult = await _mainController.PingHostAsync(targetIp);
                if (pingResult.Success)
                {
                    string macAddress = await _mainController.GetMacAddressAsync(targetIp);
                    if (!string.IsNullOrEmpty(macAddress))
                    {
                        TargetMacTextBox.Text = macAddress;
                    }
                }
            }
            catch (Exception ex)
            {
                LogResult($"Failed to get MAC address: {ex.Message}");
            }
        }

        private void LockBasicControls(bool isLocked)
        {
            // Lock/unlock input fields
            TargetIpTextBox.IsEnabled = !isLocked;
            TargetPortTextBox.IsEnabled = !isLocked;
            TargetMacTextBox.IsEnabled = !isLocked;
            MegabitsPerSecondTextBox.IsEnabled = !isLocked;
            NetworkInterfaceComboBox.IsEnabled = !isLocked;
            AttackTypeComboBox.IsEnabled = !isLocked;
            
            // Lock/unlock buttons
            StartButton.IsEnabled = !isLocked;
            StopButton.IsEnabled = isLocked;
        }

        private void LockAdvancedControls(bool isLocked)
        {
            // Lock/unlock input fields
            AdvTargetIpTextBox.IsEnabled = !isLocked;
            AdvTargetPortTextBox.IsEnabled = !isLocked;
            AdvTargetMacTextBox.IsEnabled = !isLocked;
            AdvMegabitsPerSecondTextBox.IsEnabled = !isLocked;
            AdvancedAttackTypeComboBox.IsEnabled = !isLocked;
            SpoofedMacTextBox.IsEnabled = !isLocked;
            
            // Lock/unlock buttons
            StartAdvancedAttackButton.IsEnabled = !isLocked;
            StopAdvancedAttackButton.IsEnabled = isLocked;
        }

    } 
} 