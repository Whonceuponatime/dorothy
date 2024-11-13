using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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

            NetworkInterfaceComboBox.ItemsSource = interfaces;
            NetworkInterfaceComboBox.DisplayMemberPath = "Name";
            NetworkInterfaceComboBox.SelectedIndex = 0;
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            string targetIp = TargetIpTextBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(targetIp))
            {
                MessageBox.Show("Please enter a valid Target IP.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!int.TryParse(TargetPortTextBox.Text.Trim(), out int targetPort))
            {
                MessageBox.Show("Please enter a valid Target Port.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!long.TryParse(MegabitsPerSecondTextBox.Text.Trim(), out long megabitsPerSecond) || megabitsPerSecond <= 0)
            {
                MessageBox.Show("Please enter a valid Mbps value.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (AttackTypeComboBox.SelectedItem is ComboBoxItem selectedAttackType)
            {
                string attackTypeString = selectedAttackType.Content.ToString();
                AttackType attackType = attackTypeString switch
                {
                    "UDP Flood" => AttackType.UdpFlood,
                    "ICMP Flood" => AttackType.IcmpFlood,
                    "TCP SYN Flood" => AttackType.TcpSynFlood,
                    _ => AttackType.UdpFlood
                };

                await _mainController.StartAttackAsync(attackType, targetIp, targetPort, megabitsPerSecond);
            }
            else
            {
                MessageBox.Show("Please select an Attack Type.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            await _mainController.StopAttackAsync();
        }

        private void PingButton_Click(object sender, RoutedEventArgs e)
        {
            // Implement the ping logic here
            // For example, you could call a method in _mainController to perform a ping
        }

        private void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var selectedInterface = NetworkInterfaceComboBox.SelectedItem as NetworkInterface;
            if (selectedInterface != null)
            {
                var ipProps = selectedInterface.GetIPProperties();
                var ipv4Address = ipProps.UnicastAddresses
                    .FirstOrDefault(ua => ua.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString() 
                    ?? "N/A";

                SourceIpTextBox.Text = ipv4Address;
                SourceMacTextBox.Text = selectedInterface.GetPhysicalAddress().ToString();
            }
            else
            {
                SourceIpTextBox.Text = "N/A";
                SourceMacTextBox.Text = "N/A";
            }
        }

        protected override async void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (_networkStorm.IsAttackRunning)
            {
                var result = MessageBox.Show("An attack is currently running. Do you want to stop it and exit?", "Confirm Exit", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    await _mainController.StopAttackAsync();
                }
                else
                {
                    e.Cancel = true;
                }
            }
            base.OnClosing(e);
        }

        public void Log(string message)
        {
            Dispatcher.Invoke(() =>
            {
                LogTextBox.AppendText($"{DateTime.Now}: {message}\n");
                LogTextBox.ScrollToEnd();
            });
        }

        public void UpdateStatus(string status)
        {
            Dispatcher.Invoke(() =>
            {
                StatusLabel.Content = $"Status: {status}";
            });
        }

        private string BytesToMacString(byte[] macBytes)
        {
            return string.Join(":", macBytes.Select(b => b.ToString("X2")));
        }
    }
} 