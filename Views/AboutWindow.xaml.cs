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
            
            // Set version from assembly
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            if (version != null)
            {
                ProductVersionText.Text = $"SEACURE(TOOL) - Version {version.Major}.{version.Minor}.{version.Build}";
            }
            
            // Check for updates asynchronously
            _ = CheckForUpdatesAsync();
        }

        private async Task CheckForUpdatesAsync()
        {
            if (_updateCheckService == null)
            {
                // No update service available - show current version
                var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                string currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "Unknown";
                VersionStatusText.Text = $"Cloud (v{currentVersion})";
                VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(107, 114, 128)); // Gray
                VersionStatusText.Visibility = Visibility.Visible;
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
                            // Update available
                            VersionStatusText.Text = $"Not Latest (v{result.LatestVersion})";
                            VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                                System.Windows.Media.Color.FromRgb(239, 68, 68)); // Red
                            VersionStatusText.Visibility = Visibility.Visible;
                            
                            // Show update message
                            UpdateMessageText.Text = $"Update available! Latest version: {result.LatestVersion}\nCurrent version: {result.CurrentVersion}";
                            UpdateAvailableBorder.Visibility = Visibility.Visible;
                        }
                        else
                        {
                            // Latest version
                            VersionStatusText.Text = $"Latest (v{result.CurrentVersion})";
                            VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                                System.Windows.Media.Color.FromRgb(5, 150, 105)); // Green
                            VersionStatusText.Visibility = Visibility.Visible;
                            UpdateAvailableBorder.Visibility = Visibility.Collapsed;
                        }
                    }
                    else
                    {
                        // Offline - show current version
                        VersionStatusText.Text = $"Cloud (v{result.CurrentVersion})";
                        VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                            System.Windows.Media.Color.FromRgb(107, 114, 128)); // Gray
                        VersionStatusText.Visibility = Visibility.Visible;
                        UpdateAvailableBorder.Visibility = Visibility.Collapsed;
                    }
                });
            }
            catch (Exception ex)
            {
                // Error checking updates - show as offline with current version
                Dispatcher.Invoke(() =>
                {
                    var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                    string currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "Unknown";
                    VersionStatusText.Text = $"Cloud (v{currentVersion})";
                    VersionStatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromRgb(107, 114, 128)); // Gray
                    VersionStatusText.Visibility = Visibility.Visible;
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
                // Redirect to releases page
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

