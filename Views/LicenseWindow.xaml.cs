using System;
using System.Diagnostics;
using System.Threading;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace Dorothy.Views
{
    /// <summary>
    /// Interaction logic for LicenseWindow.xaml
    /// </summary>
    public partial class LicenseWindow : Window
    {
        private readonly string _hardwareId;
        private readonly string _statusMessage;

        public LicenseWindow(string hardwareId, string statusMessage)
        {
            AvaloniaXamlLoader.Load(this);
            _hardwareId = hardwareId;
            _statusMessage = statusMessage;
            
            // Display hardware ID in lowercase
            HardwareIdTextBlock.Text = _hardwareId.ToLowerInvariant();
            StatusTextBlock.Text = _statusMessage;
        }

        private async void CopyIdButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var button = sender as Button;
            if (button == null) return;

            try
            {
                // Use Avalonia clipboard
                if (Application.Current?.Clipboard != null)
                {
                    await Application.Current.Clipboard.SetTextAsync(_hardwareId);
                }
                
                // Immediate visual feedback
                var originalContent = button.Content;
                button.Content = "Copied!";
                button.IsEnabled = false;
                
                // Reset button after 2 seconds
                var timer = new DispatcherTimer();
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
                // If clipboard fails, show in message box as fallback
                var msgBox = new Window
                {
                    Title = "Hardware ID",
                    Content = new TextBlock { Text = $"Hardware ID:\n\n{_hardwareId}\n" },
                    Width = 400,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
            }
        }

        private void RestartButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                // Get the current application executable path
                // Use Environment.ProcessPath for .NET 6+ (works for both dev and published apps)
                string? exePath = Environment.ProcessPath;
                
                if (string.IsNullOrEmpty(exePath))
                {
                    // Fallback: use the current process path
                    exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                }
                
                if (string.IsNullOrEmpty(exePath))
                {
                    throw new Exception("Could not determine application executable path");
                }
                
                // Start a new instance of the application
                var startInfo = new ProcessStartInfo
                {
                    FileName = exePath,
                    UseShellExecute = true
                };
                
                Process.Start(startInfo);
                
                // Close the current application
                if (Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
                {
                    desktop.Shutdown();
                }
            }
            catch (Exception ex)
            {
                var msgBox = new Window
                {
                    Title = "Restart Error",
                    Content = new TextBlock { Text = $"Failed to restart application: {ex.Message}" },
                    Width = 400,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                _ = msgBox.ShowDialog(this);
            }
        }

        private void ExitButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(false);
        }
    }
}

