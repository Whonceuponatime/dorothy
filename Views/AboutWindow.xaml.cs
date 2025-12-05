using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Avalonia.Threading;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class AboutWindow : Window
    {
        private readonly UpdateCheckService? _updateCheckService;

        private TextBlock? ProductVersionText => this.FindControl<TextBlock>("ProductVersionText");
        private TextBlock? VersionStatusText => this.FindControl<TextBlock>("VersionStatusText");
        private TextBlock? UpdateMessageText => this.FindControl<TextBlock>("UpdateMessageText");
        private Border? UpdateAvailableBorder => this.FindControl<Border>("UpdateAvailableBorder");

        public AboutWindow(UpdateCheckService? updateCheckService = null)
        {
            AvaloniaXamlLoader.Load(this);
            _updateCheckService = updateCheckService;
            
            // Set version from assembly
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            if (version != null && ProductVersionText != null)
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
                if (VersionStatusText != null)
                {
                    VersionStatusText.Text = $"Cloud (v{currentVersion})";
                    VersionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(107, 114, 128)); // Gray
                    VersionStatusText.IsVisible = true;
                }
                return;
            }

            try
            {
                var result = await _updateCheckService.CheckForUpdatesAsync();
                
                Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (result.IsOnline)
                    {
                        if (result.IsUpdateAvailable)
                        {
                            // Update available
                            if (VersionStatusText != null)
                            {
                                VersionStatusText.Text = $"Not Latest (v{result.LatestVersion})";
                                VersionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68)); // Red
                                VersionStatusText.IsVisible = true;
                            }
                            
                            // Show update message
                            if (UpdateMessageText != null)
                            {
                                UpdateMessageText.Text = $"Update available! Latest version: {result.LatestVersion}\nCurrent version: {result.CurrentVersion}";
                            }
                            if (UpdateAvailableBorder != null)
                            {
                                UpdateAvailableBorder.IsVisible = true;
                            }
                        }
                        else
                        {
                            // Latest version
                            if (VersionStatusText != null)
                            {
                                VersionStatusText.Text = $"Latest (v{result.CurrentVersion})";
                                VersionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(5, 150, 105)); // Green
                                VersionStatusText.IsVisible = true;
                            }
                            if (UpdateAvailableBorder != null)
                            {
                                UpdateAvailableBorder.IsVisible = false;
                            }
                        }
                    }
                    else
                    {
                        // Offline - show current version
                        if (VersionStatusText != null)
                        {
                            VersionStatusText.Text = $"Cloud (v{result.CurrentVersion})";
                            VersionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(107, 114, 128)); // Gray
                            VersionStatusText.IsVisible = true;
                        }
                        if (UpdateAvailableBorder != null)
                        {
                            UpdateAvailableBorder.IsVisible = false;
                        }
                    }
                });
            }
            catch (Exception ex)
            {
                // Error checking updates - show as offline with current version
                Dispatcher.UIThread.InvokeAsync(() =>
                {
                    var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
                    string currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "Unknown";
                    if (VersionStatusText != null)
                    {
                        VersionStatusText.Text = $"Cloud (v{currentVersion})";
                        VersionStatusText.Foreground = new SolidColorBrush(Color.FromRgb(107, 114, 128)); // Gray
                        VersionStatusText.IsVisible = true;
                    }
                });
            }
        }

        private void CloseButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(true);
        }

        private void WebsiteLink_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                var url = "https://www.sea-net.co.kr/seacure";
                if (OperatingSystem.IsWindows())
                {
                    Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
                }
                else if (OperatingSystem.IsLinux())
                {
                    Process.Start("xdg-open", url);
                }
                else if (OperatingSystem.IsMacOS())
                {
                    Process.Start("open", url);
                }
            }
            catch (Exception ex)
            {
                // Use Avalonia message box
                var msgBox = new Window
                {
                    Title = "Error",
                    Content = new TextBlock { Text = $"Error opening website: {ex.Message}" },
                    Width = 400,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                msgBox.ShowDialog(this);
            }
        }

        private void DownloadUpdateButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                var url = "https://seacuredb.vercel.app/network-data?tab=releases";
                if (OperatingSystem.IsWindows())
                {
                    Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
                }
                else if (OperatingSystem.IsLinux())
                {
                    Process.Start("xdg-open", url);
                }
                else if (OperatingSystem.IsMacOS())
                {
                    Process.Start("open", url);
                }
            }
            catch (Exception ex)
            {
                // Use Avalonia message box
                var msgBox = new Window
                {
                    Title = "Error",
                    Content = new TextBlock { Text = $"Error opening update page: {ex.Message}" },
                    Width = 400,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                msgBox.ShowDialog(this);
            }
        }
    }
}

