using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using Dorothy.Models.Database;
using Dorothy.Services;
using Supabase;

namespace Dorothy.Views
{
    public partial class SettingsWindow : Window
    {
        public string LogLocation { get; private set; } = string.Empty;
        public double FontSize { get; private set; } = 12.0;
        public int ThemeIndex { get; private set; } = 0;

        public SettingsWindow(string currentLogLocation, double currentFontSize, int currentThemeIndex)
        {
            AvaloniaXamlLoader.Load(this);
            LogLocation = currentLogLocation;
            FontSize = currentFontSize;
            ThemeIndex = currentThemeIndex;

            LogLocationTextBox.Text = string.IsNullOrEmpty(LogLocation) 
                ? AppDomain.CurrentDomain.BaseDirectory 
                : LogLocation;
            FontSizeTextBox.Text = FontSize.ToString("F1");
            ThemeComboBox.SelectedIndex = ThemeIndex;
            
            // Set Supabase URL from config
            if (SupabaseUrlTextBlock != null)
            {
                try
                {
                    var supabaseUrl = Services.SupabaseConfig.Url;
                    SupabaseUrlTextBlock.Text = $"Supabase URL: {supabaseUrl}";
                }
                catch
                {
                    SupabaseUrlTextBlock.Text = "Supabase URL: Not configured";
                }
            }
            
            // Load license information
            LoadLicenseInfo();
        }

        private async void BrowseLogLocationButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            var selectedPath = await FileDialogHelper.ShowFolderDialogAsync(this, LogLocationTextBox.Text);
            if (!string.IsNullOrEmpty(selectedPath))
            {
                LogLocationTextBox.Text = selectedPath;
            }
        }

        private async void SaveButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            LogLocation = LogLocationTextBox.Text ?? string.Empty;
            
            // Parse font size from textbox
            if (double.TryParse(FontSizeTextBox.Text, out double fontSize) && fontSize >= 8 && fontSize <= 24)
            {
                FontSize = fontSize;
            }
            else
            {
                var msgBox = new Window
                {
                    Title = "Invalid Font Size",
                    Content = new TextBlock { Text = "Font size must be a number between 8 and 24." },
                    Width = 350,
                    Height = 150,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
                return;
            }
            
            ThemeIndex = ThemeComboBox.SelectedIndex;

            // Validate log location
            if (!Directory.Exists(LogLocation))
            {
                try
                {
                    Directory.CreateDirectory(LogLocation);
                }
                catch (Exception ex)
                {
                    var msgBox = new Window
                    {
                        Title = "Error",
                        Content = new TextBlock { Text = $"Cannot create directory: {ex.Message}" },
                        Width = 400,
                        Height = 200,
                        WindowStartupLocation = WindowStartupLocation.CenterOwner
                    };
                    await msgBox.ShowDialog(this);
                    return;
                }
            }

            // Supabase credentials are hardcoded - no validation needed

            Close(true);
        }
        
        private void FontSizeTextBox_OnTextInput(object? sender, TextInputEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                e.Handled = true;
                return;
            }
            
            // Allow only digits and decimal point
            if (!char.IsDigit(e.Text?[0] ?? '\0') && e.Text != ".")
            {
                e.Handled = true;
                return;
            }
            
            // Prevent multiple decimal points
            if (e.Text == "." && (textBox.Text?.Contains(".") ?? false))
            {
                e.Handled = true;
                return;
            }
            
            // Get the resulting text after insertion
            string currentText = textBox.Text ?? string.Empty;
            int caretIndex = textBox.CaretIndex;
            string newText = currentText.Insert(caretIndex, e.Text ?? "");
            
            // Allow empty text (user is deleting/clearing)
            if (string.IsNullOrEmpty(newText))
            {
                return; // Allow it
            }
            
            // Allow partial input during typing (like "1", "12", "12.")
            // Only block if we can parse a complete number and it's clearly out of range
            if (double.TryParse(newText, out double value))
            {
                // Only block if value is clearly out of range
                // Allow intermediate values during typing (e.g., allow "2" even though it's < 8, user might type "12")
                if (value < 0 || value > 24)
                {
                    e.Handled = true;
                    return;
                }
            }
            // If it's not a valid number yet (partial input), allow it
            // Examples: "1", "12", "12." are all valid partial inputs
        }
        
        private void FontSizeTextBox_TextChanged(object? sender, Avalonia.Controls.TextChangedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null) return;
            
            // Validate and provide visual feedback
            if (double.TryParse(textBox.Text, out double value))
            {
                if (value >= 8 && value <= 24)
                {
                    textBox.Background = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                    textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(209, 213, 219));
                }
                else
                {
                    textBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                    textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
                }
            }
            else if (string.IsNullOrEmpty(textBox.Text))
            {
                textBox.Background = new SolidColorBrush(Color.FromRgb(255, 255, 255));
                textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(209, 213, 219));
            }
            else
            {
                textBox.Background = new SolidColorBrush(Color.FromRgb(255, 200, 200));
                textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(239, 68, 68));
            }
        }

        private void CancelButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(false);
        }

        // Supabase URL and Anon Key are now hardcoded - no UI handlers needed

        private async void CopyHardwareIdButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            try
            {
                if (CurrentHardwareIdTextBlock != null && !string.IsNullOrEmpty(CurrentHardwareIdTextBlock.Text))
                {
                    var topLevel = TopLevel.GetTopLevel(this);
                    if (topLevel?.Clipboard != null)
                    {
                        await topLevel.Clipboard.SetTextAsync(CurrentHardwareIdTextBlock.Text);
                    }
                    
                    var msgBox = new Window
                    {
                        Title = "Copied",
                        Content = new TextBlock 
                        { 
                            Text = "Hardware ID copied to clipboard!\n\nYou can now send this to your administrator for authorization.",
                            TextWrapping = Avalonia.Media.TextWrapping.Wrap
                        },
                        Width = 400,
                        Height = 200,
                        WindowStartupLocation = WindowStartupLocation.CenterOwner
                    };
                    await msgBox.ShowDialog(this);
                }
            }
            catch (Exception ex)
            {
                var msgBox = new Window
                {
                    Title = "Error",
                    Content = new TextBlock { Text = $"Failed to copy to clipboard: {ex.Message}" },
                    Width = 400,
                    Height = 200,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner
                };
                await msgBox.ShowDialog(this);
            }
        }

        private async void LoadLicenseInfo()
        {
            try
            {
                // Initialize Supabase client with hardcoded credentials
                var supabaseClient = new Supabase.Client(
                    Services.SupabaseConfig.Url,
                    Services.SupabaseConfig.AnonKey,
                    new Supabase.SupabaseOptions
                    {
                        AutoConnectRealtime = false,
                        AutoRefreshToken = false
                    });

                var licenseService = new LicenseService(supabaseClient);
                var hardwareId = licenseService.HardwareId;
                
                // Check Supabase license (centralized control)
                var validationResult = await licenseService.ValidateLicenseAsync();

                if (CurrentHardwareIdTextBlock != null)
                {
                    CurrentHardwareIdTextBlock.Text = hardwareId;
                }

                if (LicenseStatusTextBlock != null)
                {
                    LicenseStatusTextBlock.Text = validationResult.IsValid
                        ? "[OK] Status: Authorized (Supabase)"
                        : "[X] Status: Not Authorized - Contact Administrator";
                    LicenseStatusTextBlock.Foreground = validationResult.IsValid
                        ? new SolidColorBrush(Color.FromRgb(34, 197, 94)) // Green
                        : new SolidColorBrush(Color.FromRgb(239, 68, 68)); // Red
                }

                if (LicenseMessageTextBlock != null)
                {
                    LicenseMessageTextBlock.Text = validationResult.IsValid
                        ? "Your license is managed by the administrator through Supabase."
                        : $"To request a license:\n1. Log into seacuredb and go to Settings\n2. Request for a license\n3. Ask the admin to approve your request\n\nYour Hardware ID: {hardwareId}";
                }
            }
            catch (Exception ex)
            {
                // Silently fail - license info is optional
                if (LicenseStatusTextBlock != null)
                {
                    LicenseStatusTextBlock.Text = "[!] Status: Unable to verify license";
                    LicenseStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(234, 179, 8)); // Yellow
                }
            }
        }

    }

    // FolderBrowser removed - using FileDialogHelper for cross-platform support
}
