using System;
using System.Net.NetworkInformation;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using Dorothy.Models;
using Dorothy.Controllers;

namespace Dorothy.Views
{
    public partial class MainWindow : Window
    {
        private readonly NetworkStorm _networkStorm;
        private readonly MainController _controller;

        public MainWindow()
        {
            InitializeComponent();
            
            _networkStorm = new NetworkStorm();
            _controller = new MainController(
                _networkStorm,
                StartButton,
                StopButton,
                StatusLabel,
                LogTextBox
            );

            StartButton.Click += StartButton_Click;
            StopButton.Click += StopButton_Click;
            PingButton.Click += PingButton_Click;
            Loaded += Window_Loaded;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            LoadNetworkInterfaces();
        }

        private void LoadNetworkInterfaces()
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up &&
                            ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .ToList();

            NetworkInterfaceComboBox.ItemsSource = interfaces;
            NetworkInterfaceComboBox.DisplayMemberPath = "Description";
            
            if (interfaces.Any())
            {
                NetworkInterfaceComboBox.SelectedIndex = 0;
            }
        }

        private void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (NetworkInterfaceComboBox.SelectedItem is NetworkInterface networkInterface)
            {
                var ipProps = networkInterface.GetIPProperties();
                var ipAddress = ipProps.UnicastAddresses
                    .FirstOrDefault(addr => addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    ?.Address.ToString();
                
                var macAddress = string.Join(":", networkInterface.GetPhysicalAddress()
                    .GetAddressBytes()
                    .Select(b => b.ToString("X2")));

                SourceIpTextBox.Text = ipAddress;
                SourceMacTextBox.Text = macAddress;

                if (ipAddress != null)
                {
                    _networkStorm.SetSourceIp(ipAddress);
                    _networkStorm.SetSourceMac(networkInterface.GetPhysicalAddress().GetAddressBytes());
                }
            }
        }

        private async void StartButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(SourceIpTextBox.Text))
            {
                MessageBox.Show("Please select a network interface first");
                return;
            }

            if (!long.TryParse(BytesPerSecondTextBox.Text, out long targetMbps) || targetMbps <= 0)
            {
                MessageBox.Show("Target rate must be a positive number (Mbps)");
                return;
            }
            long bytesPerSecond = targetMbps * 1_000_000 / 8; // Convert Mbps to bytes per second

            if (!int.TryParse(TargetPortTextBox.Text, out int targetPort) || targetPort <= 0 || targetPort > 65535)
            {
                MessageBox.Show("Port must be between 1 and 65535");
                return;
            }

            await _controller.StartAttackAsync(
                AttackTypeComboBox.Text,
                TargetIpTextBox.Text,
                targetPort,
                bytesPerSecond
            );
        }

        private async void StopButton_Click(object sender, RoutedEventArgs e)
        {
            await _controller.StopAttackAsync();
        }

        private async void PingButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(TargetIpTextBox.Text))
            {
                MessageBox.Show("Please enter a target IP address");
                return;
            }

            PingButton.IsEnabled = false;
            PingResultText.Text = "Pinging...";
            
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(TargetIpTextBox.Text, 1000);
                PingResultText.Text = $"Response: {reply.Status}, Time: {reply.RoundtripTime}ms";
            }
            catch (Exception ex)
            {
                PingResultText.Text = $"Error: {ex.Message}";
            }
            finally
            {
                PingButton.IsEnabled = true;
            }
        }
    }
} 