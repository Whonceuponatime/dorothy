using System;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace Dorothy.Views
{
    public partial class CustomGatewayDialog : Window
    {
        public string GatewayIp { get; private set; } = string.Empty;

        public CustomGatewayDialog(string currentGateway)
        {
            InitializeComponent();
            GatewayIpTextBox.Text = currentGateway;
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (IPAddress.TryParse(GatewayIpTextBox.Text, out _))
            {
                GatewayIp = GatewayIpTextBox.Text;
                DialogResult = true;
            }
            else
            {
                MessageBox.Show("Please enter a valid IP address.", "Invalid IP", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
} 