using System;
using System.Net;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Dorothy.Views
{
    public partial class CustomGatewayDialog : Window
    {
        public string GatewayIp { get; private set; } = string.Empty;

        public CustomGatewayDialog(string currentGateway)
        {
            AvaloniaXamlLoader.Load(this);
            GatewayIpTextBox.Text = currentGateway;
        }

        private async void OkButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            if (IPAddress.TryParse(GatewayIpTextBox.Text, out _))
            {
                GatewayIp = GatewayIpTextBox.Text;
                Close(true);
            }
            else
            {
                var msgBox = new Window
                {
                    Title = "Invalid IP",
                    Content = new TextBlock { Text = "Please enter a valid IP address." },
                    Width = 300,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
            }
        }

        private void CancelButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(false);
        }
    }
} 