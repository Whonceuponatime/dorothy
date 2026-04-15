using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Dorothy.Services;

namespace Dorothy.Views
{

    public partial class LicenseWindow : Window
    {
        private readonly string _hardwareId;
        private readonly string _statusMessage;

        public LicenseWindow(string hardwareId, string statusMessage)
        {
            InitializeComponent();
            _hardwareId = hardwareId;
            _statusMessage = statusMessage;

            HardwareIdTextBlock.Text = _hardwareId.ToLowerInvariant();
            StatusTextBlock.Text = _statusMessage;
        }

        private void CopyIdButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            if (button == null) return;

            try
            {

                Clipboard.SetText(_hardwareId);

                var originalContent = button.Content;
                button.Content = "Copied!";
                button.IsEnabled = false;

                var timer = new System.Windows.Threading.DispatcherTimer();
                timer.Interval = TimeSpan.FromSeconds(2);
                timer.Tick += (s, args) =>
                {
                    button.Content = originalContent;
                    button.IsEnabled = true;
                    timer.Stop();
                };
                timer.Start();
            }
            catch (Exception ex)
            {

                MessageBox.Show($"Hardware ID:\n\n{_hardwareId}\n",
                    "Hardware ID", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RestartButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {

                string? exePath = Environment.ProcessPath;

                if (string.IsNullOrEmpty(exePath))
                {

                    exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                }

                if (string.IsNullOrEmpty(exePath))
                {
                    throw new Exception("Could not determine application executable path");
                }

                var startInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true
                };

                Process.Start(startInfo);

                Application.Current.Shutdown();
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to restart application: {ex.Message}",
                    "Restart Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private async void RequestLicense_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RequestLicenseButton.IsEnabled = false;
                RequestLicenseButton.Content = "Requesting...";
                RequestStatusText.Text = "";

                var status = await RequestLicensePublicAsync(
                    _hardwareId,
                    Environment.MachineName,
                    Environment.UserName);

                if (status == "already_licensed")
                {
                    RequestStatusText.Text = "This machine is already licensed. Please restart the application.";
                    RequestStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                }
                else if (status == "pending")
                {
                    RequestStatusText.Text = "License request submitted. An administrator will review your request.";
                    RequestStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x5B, 0x8A, 0xF5));
                }
                else
                {
                    RequestStatusText.Text = $"Status: {status}";
                    RequestStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x99, 0xAA));
                }
            }
            catch (Exception ex)
            {
                RequestStatusText.Text = $"Failed to submit request: {ex.Message}";
                RequestStatusText.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
            }
            finally
            {
                RequestLicenseButton.IsEnabled = true;
                RequestLicenseButton.Content = "Request License";
            }
        }

        private static async Task<string> RequestLicensePublicAsync(string hardwareId, string machineName, string deviceName)
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            var url = $"{SeacureConfig.ApiUrl.TrimEnd('/')}/api/license/request-public";
            var payload = new { hardware_id = hardwareId, machine_name = machineName, device_name = deviceName };
            using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await client.PostAsync(url, content).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
            return json.RootElement.TryGetProperty("status", out var s)
                ? (s.GetString() ?? "unknown")
                : "unknown";
        }
    }
}

