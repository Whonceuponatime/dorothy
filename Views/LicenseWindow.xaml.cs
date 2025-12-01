using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;

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
            InitializeComponent();
            _hardwareId = hardwareId;
            _statusMessage = statusMessage;
            
            // Display hardware ID in lowercase
            HardwareIdTextBlock.Text = _hardwareId.ToLowerInvariant();
            StatusTextBlock.Text = _statusMessage;
        }

        private void CopyIdButton_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            if (button == null) return;

            try
            {
                // Use Clipboard.SetText directly - WPF handles STA thread automatically
                Clipboard.SetText(_hardwareId);
                
                // Immediate visual feedback
                var originalContent = button.Content;
                button.Content = "Copied!";
                button.IsEnabled = false;
                
                // Reset button after 2 seconds
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
                // If clipboard fails, show in message box as fallback
                MessageBox.Show($"Hardware ID:\n\n{_hardwareId}\n", 
                    "Hardware ID", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void RestartButton_Click(object sender, RoutedEventArgs e)
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
    }
}

