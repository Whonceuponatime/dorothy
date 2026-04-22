using System;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using Dorothy.Models.Database;
using Dorothy.Services;
using Microsoft.Win32;

namespace Dorothy.Views
{
    public partial class SettingsWindow : Window
    {
        public string LogLocation { get; private set; } = string.Empty;
        public double FontSize { get; private set; } = 12.0;
        public int ThemeIndex { get; private set; } = 0;

        public SettingsWindow(string currentLogLocation, double currentFontSize, int currentThemeIndex)
        {
            InitializeComponent();
            LogLocation = currentLogLocation;
            FontSize = currentFontSize;
            ThemeIndex = currentThemeIndex;

            LogLocationTextBox.Text = string.IsNullOrEmpty(LogLocation)
                ? AppDomain.CurrentDomain.BaseDirectory
                : LogLocation;
            FontSizeTextBox.Text = FontSize.ToString("F1");
            ThemeComboBox.SelectedIndex = ThemeIndex;

            if (SupabaseUrlTextBlock != null)
            {
                try
                {
                    SupabaseUrlTextBlock.Text = $"API endpoint: {SeacureConfig.ApiUrl}";
                }
                catch
                {
                    SupabaseUrlTextBlock.Text = "API endpoint: Not configured";
                }
            }

            LoadLicenseInfo();
            _ = CheckApiConnectionAsync();
        }

        private static readonly HttpClient _healthHttp = new()
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        private async Task CheckApiConnectionAsync()
        {
            if (ApiConnectionStatusTextBlock == null) return;

            try
            {
                var url = $"{SeacureConfig.ApiUrl.TrimEnd('/')}/api/health";
                using var resp = await _healthHttp.GetAsync(url).ConfigureAwait(true);
                if (resp.IsSuccessStatusCode)
                {
                    ApiConnectionStatusTextBlock.Text = "Status: \u2713 Connected";
                    ApiConnectionStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80));
                }
                else
                {
                    ApiConnectionStatusTextBlock.Text = "Status: \u2717 Unreachable";
                    ApiConnectionStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                }
            }
            catch
            {
                ApiConnectionStatusTextBlock.Text = "Status: \u2717 Unreachable";
                ApiConnectionStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
            }
        }

        private void BrowseLogLocationButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedPath = ShowFolderBrowserDialog("Select folder for log files", LogLocationTextBox.Text);
            if (!string.IsNullOrEmpty(selectedPath))
            {
                LogLocationTextBox.Text = selectedPath;
            }
        }

        private string ShowFolderBrowserDialog(string description, string initialPath)
            {
            var hwnd = new WindowInteropHelper(this).Handle;
            return FolderBrowser.ShowDialog(hwnd, description, initialPath);
        }

        private void SaveButton_Click(object sender, RoutedEventArgs e)
        {
            LogLocation = LogLocationTextBox.Text;

            if (double.TryParse(FontSizeTextBox.Text, out double fontSize) && fontSize >= 8 && fontSize <= 24)
            {
                FontSize = fontSize;
            }
            else
            {
                MessageBox.Show(
                    "Font size must be a number between 8 and 24.",
                    "Invalid Font Size",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            ThemeIndex = ThemeComboBox.SelectedIndex;

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

        private void FontSizeTextBox_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null)
            {
                e.Handled = true;
                return;
            }

            if (!char.IsDigit(e.Text, 0) && e.Text != ".")
            {
                e.Handled = true;
                return;
            }

            if (e.Text == "." && textBox.Text.Contains("."))
            {
                e.Handled = true;
                return;
            }

            string currentText = textBox.Text ?? string.Empty;
            int caretIndex = textBox.CaretIndex;
            string newText = currentText.Insert(caretIndex, e.Text);

            if (string.IsNullOrEmpty(newText))
            {
                return;
            }

            if (double.TryParse(newText, out double value))
            {

                if (value < 0 || value > 24)
                {
                    e.Handled = true;
                    return;
                }
            }

        }

        private void FontSizeTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox == null) return;

            if (double.TryParse(textBox.Text, out double value))
            {
                if (value >= 8 && value <= 24)
                {
                    textBox.ClearValue(TextBox.BackgroundProperty);
                    textBox.ClearValue(TextBox.ForegroundProperty);
                    textBox.ClearValue(TextBox.BorderBrushProperty);
                }
                else
                {
                    textBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                    textBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                    textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
                }
            }
            else if (string.IsNullOrEmpty(textBox.Text))
            {
                textBox.ClearValue(TextBox.BackgroundProperty);
                textBox.ClearValue(TextBox.ForegroundProperty);
                textBox.ClearValue(TextBox.BorderBrushProperty);
            }
            else
            {
                textBox.Background  = new SolidColorBrush(Color.FromRgb(0x3A, 0x20, 0x20));
                textBox.Foreground  = new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                textBox.BorderBrush = new SolidColorBrush(Color.FromRgb(0x5A, 0x30, 0x30));
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void CopyHardwareIdButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (CurrentHardwareIdTextBlock != null && !string.IsNullOrEmpty(CurrentHardwareIdTextBlock.Text))
                {
                    Clipboard.SetText(CurrentHardwareIdTextBlock.Text);
                    MessageBox.Show(
                        "Hardware ID copied to clipboard!\n\nYou can now send this to your administrator for authorization.",
                        "Copied",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Failed to copy to clipboard: {ex.Message}",
                    "Error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }

        private async void LoadLicenseInfo()
        {
            try
            {

                var licenseService = new LicenseService();
                var hardwareId = licenseService.HardwareId;

                var validationResult = await licenseService.ValidateLicenseAsync();

                if (CurrentHardwareIdTextBlock != null)
                {
                    CurrentHardwareIdTextBlock.Text = hardwareId;
                }

                if (LicenseStatusTextBlock != null)
                {
                    LicenseStatusTextBlock.Text = validationResult.IsValid
                        ? "[OK] Status: Authorized"
                        : "[X] Status: Not Authorized - Contact Administrator";
                    LicenseStatusTextBlock.Foreground = validationResult.IsValid
                        ? new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80))
                        : new SolidColorBrush(Color.FromRgb(0xF8, 0x71, 0x71));
                }

                if (LicenseMessageTextBlock != null)
                {
                    LicenseMessageTextBlock.Text = validationResult.IsValid
                        ? "Your license is managed by the administrator through the Seacure API."
                        : $"To request a license:\n1. Log into api.seacuredb.com and go to Licensing\n2. Request a license\n3. Ask the admin to approve your request\n\nYour Hardware ID: {hardwareId}";
                }
            }
            catch (Exception ex)
            {

                if (LicenseStatusTextBlock != null)
                {
                    LicenseStatusTextBlock.Text = "[!] Status: Unable to verify license";
                    LicenseStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24));
                }
            }
        }

    }

    public static class FolderBrowser
    {
        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern int SHBrowseForFolder(ref BROWSEINFO lpbi);

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        private static extern bool SHGetPathFromIDList(IntPtr pidl, StringBuilder pszPath);

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        private const uint BFFM_SETSELECTION = 0x400 + 103;
        private const uint BFFM_INITIALIZED = 1;

        public static string ShowDialog(IntPtr ownerHandle, string description, string initialPath)
        {
            var bi = new BROWSEINFO
            {
                hwndOwner = ownerHandle,
                pidlRoot = IntPtr.Zero,
                pszDisplayName = new string('\0', 260),
                lpszTitle = description,
                ulFlags = 0x00000040 | 0x00000010,
                lpfn = BrowseCallbackProc,
                lParam = IntPtr.Zero,
                iImage = 0
            };

            if (!string.IsNullOrEmpty(initialPath))
            {
                bi.lParam = Marshal.StringToHGlobalAuto(initialPath);
            }

            IntPtr pidl = (IntPtr)SHBrowseForFolder(ref bi);

            if (bi.lParam != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(bi.lParam);
            }

            if (pidl == IntPtr.Zero)
            {
                return string.Empty;
            }

            var path = new StringBuilder(260);
            if (SHGetPathFromIDList(pidl, path))
            {
                Marshal.FreeCoTaskMem(pidl);
                return path.ToString();
            }

            Marshal.FreeCoTaskMem(pidl);
            return string.Empty;
        }

        private static int BrowseCallbackProc(IntPtr hwnd, uint uMsg, IntPtr lParam, IntPtr lpData)
        {
            if (uMsg == BFFM_INITIALIZED && lpData != IntPtr.Zero)
            {
                string path = Marshal.PtrToStringAuto(lpData);
                SendMessage(hwnd, BFFM_SETSELECTION, new IntPtr(1), lpData);
            }
            return 0;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct BROWSEINFO
        {
            public IntPtr hwndOwner;
            public IntPtr pidlRoot;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string pszDisplayName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpszTitle;
            public uint ulFlags;
            public BrowseCallbackProcDelegate lpfn;
            public IntPtr lParam;
            public int iImage;
        }

        private delegate int BrowseCallbackProcDelegate(IntPtr hwnd, uint uMsg, IntPtr lParam, IntPtr lpData);
    }
}

