using System;
using System.IO;
using System.Windows;
using WinForms = System.Windows.Forms;
using Microsoft.Win32;

namespace Dorothy.Views
{
    public partial class SettingsWindow : Window
    {
        public string LogLocation { get; private set; } = string.Empty;
        public int FontSizeIndex { get; private set; } = 1;
        public int ThemeIndex { get; private set; } = 0;

        public SettingsWindow(string currentLogLocation, int currentFontSizeIndex, int currentThemeIndex)
        {
            InitializeComponent();
            LogLocation = currentLogLocation;
            FontSizeIndex = currentFontSizeIndex;
            ThemeIndex = currentThemeIndex;

            LogLocationTextBox.Text = string.IsNullOrEmpty(LogLocation) 
                ? AppDomain.CurrentDomain.BaseDirectory 
                : LogLocation;
            FontSizeComboBox.SelectedIndex = FontSizeIndex;
            ThemeComboBox.SelectedIndex = ThemeIndex;
        }

        private void BrowseLogLocationButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new WinForms.FolderBrowserDialog
            {
                Description = "Select folder for log files",
                SelectedPath = LogLocationTextBox.Text
            };

            if (dialog.ShowDialog() == WinForms.DialogResult.OK)
            {
                LogLocationTextBox.Text = dialog.SelectedPath;
            }
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            LogLocation = LogLocationTextBox.Text;
            FontSizeIndex = FontSizeComboBox.SelectedIndex;
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
                    MessageBox.Show(
                        $"Cannot create directory: {ex.Message}",
                        "Error",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                    return;
                }
            }

            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}

