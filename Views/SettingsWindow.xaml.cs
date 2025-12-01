using System;
using System.IO;
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
using Supabase;

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
            
            // Load license information
            LoadLicenseInfo();
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

            // Supabase credentials are hardcoded - no validation needed

            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        // Supabase URL and Anon Key are now hardcoded - no UI handlers needed

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
                        ? "✅ Status: Authorized (Supabase)"
                        : "❌ Status: Not Authorized - Contact Administrator";
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
                    LicenseStatusTextBlock.Text = "⚠️ Status: Unable to verify license";
                    LicenseStatusTextBlock.Foreground = new SolidColorBrush(Color.FromRgb(234, 179, 8)); // Yellow
                }
            }
        }

    }

    // Pure WPF folder browser using Windows API
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
                pszDisplayName = new StringBuilder(260),
                lpszTitle = description,
                ulFlags = 0x00000040 | 0x00000010, // BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS
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
            public StringBuilder pszDisplayName;
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
