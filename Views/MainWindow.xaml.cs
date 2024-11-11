using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Controllers;
using Dorothy.Models;

namespace Dorothy.Views
{
    public partial class MainWindow : Window
    {
        private readonly MainController _mainController;
        private readonly NetworkStorm _networkStorm;

        public MainWindow()
        {
            InitializeComponent();
            _networkStorm = new NetworkStorm(LogTextBox);
            _mainController = new MainController(_networkStorm, StartButton, StopButton, StatusLabel, LogTextBox, this);
            NetworkInterfaceComboBox.SelectionChanged += NetworkInterfaceComboBox_SelectionChanged;
            PopulateNetworkInterfaces();
        }

        private void PopulateNetworkInterfaces()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback && ni.OperationalStatus == OperationalStatus.Up)
                .ToList();

            foreach (var ni in interfaces)
            {
                ComboBoxItem item = new ComboBoxItem
                {
                    Content = ni.Name
                };
                NetworkInterfaceComboBox.Items.Add(item);
            }

            if (NetworkInterfaceComboBox.Items.Count > 0)
            {
                NetworkInterfaceComboBox.SelectedIndex = 0;
            }
            else
            {
                MessageBox.Show("No active network interfaces found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            string attackType = (AttackTypeComboBox.SelectedItem as ComboBoxItem)?.Content as string;
            if (string.IsNullOrEmpty(attackType))
            {
                MessageBox.Show("Please select an attack type.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string targetIp = TargetIpTextBox.Text;
            if (string.IsNullOrEmpty(targetIp))
            {
                MessageBox.Show("Please enter a target IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!int.TryParse(TargetPortTextBox.Text, out int targetPort))
            {
                MessageBox.Show("Please enter a valid target port.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!long.TryParse(BytesPerSecondTextBox.Text, out long targetBytesPerSecond))
            {
                MessageBox.Show("Please enter a valid number for bytes per second.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            await _mainController.StartAttackAsync(attackType, targetIp, targetPort, targetBytesPerSecond);
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            await _mainController.StopAttackAsync();
        }

        private void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedItem = NetworkInterfaceComboBox.SelectedItem as ComboBoxItem;
            if (selectedItem != null)
            {
                string interfaceName = selectedItem.Content as string;
                if (!string.IsNullOrEmpty(interfaceName))
                {
                    _mainController.UpdateNetworkInterface(interfaceName);
                }
            }
        }

        public void SetSourceIp(string sourceIp)
        {
            SourceIpTextBox.Text = sourceIp;
        }

        public void SetSourceMac(byte[] sourceMac)
        {
            SourceMacTextBox.Text = BytesToMacString(sourceMac);
        }

        private string BytesToMacString(byte[] mac)
        {
            if (mac == null || mac.Length != 6)
                throw new ArgumentException("Invalid MAC address", nameof(mac));

            return string.Join("-", mac.Select(b => b.ToString("X2")));
        }

        // Optional: Implement PingButton_Click event handler if you want ping functionality
        private async void PingButton_Click(object sender, RoutedEventArgs e)
        {
            string targetIp = TargetIpTextBox.Text;
            if (string.IsNullOrEmpty(targetIp))
            {
                MessageBox.Show("Please enter a target IP address to ping.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            using (var ping = new System.Net.NetworkInformation.Ping())
            {
                try
                {
                    var reply = await ping.SendPingAsync(targetIp);
                    if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                    {
                        PingResultText.Text = $"Ping successful: Time={reply.RoundtripTime}ms";
                    }
                    else
                    {
                        PingResultText.Text = $"Ping failed: {reply.Status}";
                    }
                }
                catch (Exception ex)
                {
                    PingResultText.Text = $"Ping error: {ex.Message}";
                }
            }
        }
    }
} 