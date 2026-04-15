using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Navigation;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class AboutWindow : Window
    {
        private readonly UpdateCheckService? _updateCheckService;

        public AboutWindow(UpdateCheckService? updateCheckService = null)
        {
            InitializeComponent();
            _updateCheckService = updateCheckService;

            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            if (version != null)
            {
                ProductVersionText.Text = $"SEACURE(TOOL) - Version {version.Major}.{version.Minor}.{version.Build}";
            }

            _ = CheckForUpdatesAsync();
        }

        private void SetBadge(string text, byte bgR, byte bgG, byte bgB, byte fgR, byte fgG, byte fgB)
        {
            VersionStatusText.Text = text;
            VersionStatusBadge.Background = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(bgR, bgG, bgB));
            VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(fgR, fgG, fgB));
            VersionStatusBadge.Visibility = Visibility.Visible;
        }

        private async Task CheckForUpdatesAsync()
        {
            if (_updateCheckService == null)
            {
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                string currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "Unknown";
                SetBadge($"Cloud (v{currentVersion})", 0x1A, 0x3A, 0x2A, 0x4A, 0xDE, 0x80);
                return;
            }

            try
            {
                var result = await _updateCheckService.CheckForUpdatesAsync();

                Dispatcher.Invoke(() =>
                {
                    if (result.IsOnline)
                    {
                        if (result.IsUpdateAvailable)
                        {
                            SetBadge($"Not Latest (v{result.LatestVersion})", 0x3A, 0x15, 0x19, 0xF8, 0x71, 0x71);
                            UpdateMessageText.Text = $"Update available! Latest version: {result.LatestVersion}\nCurrent version: {result.CurrentVersion}";
                            UpdateAvailableBorder.Visibility = Visibility.Visible;
                        }
                        else
                        {
                            SetBadge($"Latest (v{result.CurrentVersion})", 0x1A, 0x3A, 0x2A, 0x4A, 0xDE, 0x80);
                            UpdateAvailableBorder.Visibility = Visibility.Collapsed;
                        }
                    }
                    else
                    {
                        SetBadge($"Cloud (v{result.CurrentVersion})", 0x2A, 0x34, 0x44, 0x88, 0x99, 0xAA);
                        UpdateAvailableBorder.Visibility = Visibility.Collapsed;
                    }
                });
            }
            catch
            {
                Dispatcher.Invoke(() =>
                {
                    var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                    string currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "Unknown";
                    SetBadge($"Cloud (v{currentVersion})", 0x2A, 0x34, 0x44, 0x88, 0x99, 0xAA);
                });
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void WebsiteLink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = e.Uri.AbsoluteUri,
                    UseShellExecute = true
                });
                e.Handled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening website: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DownloadUpdateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {

                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://seacuredb.vercel.app/network-data?tab=releases",
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error opening update page: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}

