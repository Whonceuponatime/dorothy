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
using Microsoft.Win32;
using Supabase;

namespace Dorothy.Views
{
    public partial class SettingsWindow : Window
    {
        public string LogLocation { get; private set; } = string.Empty;
        public int FontSizeIndex { get; private set; } = 1;
        public int ThemeIndex { get; private set; } = 0;
        public string SupabaseUrl { get; private set; } = string.Empty;
        public string SupabaseAnonKey { get; private set; } = string.Empty;

        public SettingsWindow(string currentLogLocation, int currentFontSizeIndex, int currentThemeIndex, 
                             string currentSupabaseUrl, string currentSupabaseAnonKey)
        {
            InitializeComponent();
            LogLocation = currentLogLocation;
            FontSizeIndex = currentFontSizeIndex;
            ThemeIndex = currentThemeIndex;
            SupabaseUrl = currentSupabaseUrl;
            SupabaseAnonKey = currentSupabaseAnonKey;

            LogLocationTextBox.Text = string.IsNullOrEmpty(LogLocation) 
                ? AppDomain.CurrentDomain.BaseDirectory 
                : LogLocation;
            FontSizeComboBox.SelectedIndex = FontSizeIndex;
            ThemeComboBox.SelectedIndex = ThemeIndex;
            SupabaseUrlTextBox.Text = SupabaseUrl;
            SupabaseAnonKeyPasswordBox.Password = SupabaseAnonKey;
            SupabaseAnonKeyTextBox.Text = SupabaseAnonKey;
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
            SupabaseUrl = SupabaseUrlTextBox.Text.Trim();
            SupabaseAnonKey = SupabaseAnonKeyPasswordBox.Visibility == Visibility.Visible 
                ? SupabaseAnonKeyPasswordBox.Password.Trim() 
                : SupabaseAnonKeyTextBox.Text.Trim();

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

            // Validate Supabase URL format if provided
            if (!string.IsNullOrWhiteSpace(SupabaseUrl))
            {
                if (!Uri.TryCreate(SupabaseUrl, UriKind.Absolute, out var uri) || 
                    (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                {
                    MessageBox.Show(
                        "Invalid Supabase URL format. Please enter a valid URL (e.g., https://your-project.supabase.co)",
                        "Invalid URL",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
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

        private void SupabaseUrlTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            // Update property as user types
            SupabaseUrl = SupabaseUrlTextBox.Text.Trim();
        }

        private void SupabaseAnonKeyTextBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            // Sync password box to text box
            if (sender is System.Windows.Controls.PasswordBox passwordBox)
            {
                SupabaseAnonKey = passwordBox.Password.Trim();
                SupabaseAnonKeyTextBox.Text = passwordBox.Password;
            }
        }

        private void SupabaseAnonKeyTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
        {
            // Sync text box to password box
            if (sender is System.Windows.Controls.TextBox textBox)
            {
                SupabaseAnonKey = textBox.Text.Trim();
                SupabaseAnonKeyPasswordBox.Password = textBox.Text;
            }
        }

        private void TogglePasswordVisibilityButton_Click(object sender, RoutedEventArgs e)
        {
            if (SupabaseAnonKeyPasswordBox.Visibility == Visibility.Visible)
            {
                // Switch to visible text
                SupabaseAnonKeyTextBox.Text = SupabaseAnonKeyPasswordBox.Password;
                SupabaseAnonKeyPasswordBox.Visibility = Visibility.Collapsed;
                SupabaseAnonKeyTextBox.Visibility = Visibility.Visible;
                var button = sender as Button;
                if (button != null)
                {
                    button.Content = new TextBlock 
                    { 
                        Text = "🙈", 
                        FontSize = 14, 
                        Foreground = new SolidColorBrush(Color.FromRgb(107, 114, 128)) 
                    };
                }
            }
            else
            {
                // Switch to password box
                SupabaseAnonKeyPasswordBox.Password = SupabaseAnonKeyTextBox.Text;
                SupabaseAnonKeyTextBox.Visibility = Visibility.Collapsed;
                SupabaseAnonKeyPasswordBox.Visibility = Visibility.Visible;
                var button = sender as Button;
                if (button != null)
                {
                    button.Content = new TextBlock 
                    { 
                        Text = "👁", 
                        FontSize = 14, 
                        Foreground = new SolidColorBrush(Color.FromRgb(107, 114, 128)) 
                    };
                }
            }
        }

        private async void TestConnectionButton_Click(object sender, RoutedEventArgs e)
        {
            var url = SupabaseUrlTextBox.Text.Trim();
            var anonKey = SupabaseAnonKeyPasswordBox.Visibility == Visibility.Visible 
                ? SupabaseAnonKeyPasswordBox.Password.Trim() 
                : SupabaseAnonKeyTextBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(anonKey))
            {
                MessageBox.Show(
                    "Please enter both Supabase URL and Anon Key",
                    "Missing Information",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            // Validate URL format
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || 
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                MessageBox.Show(
                    "Invalid URL format. Please enter a valid URL (e.g., https://your-project.supabase.co)",
                    "Invalid URL",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            TestConnectionButton.IsEnabled = false;
            TestConnectionButton.Content = "Testing...";
            TestConnectionResultText.Visibility = Visibility.Collapsed;

            try
            {
                var options = new SupabaseOptions
                {
                    AutoConnectRealtime = false,
                    AutoRefreshToken = false
                };

                var testClient = new Client(url, anonKey, options);
                
                // Try to query a simple table to test connection
                // We'll try to query attack_logs table (it's okay if it doesn't exist yet)
                try
                {
                    var testResponse = await testClient
                        .From<AttackLogEntry>()
                        .Select("id")
                        .Limit(1)
                        .Get();

                    MessageBox.Show(
                        "Connection successful! ✓\n\nYour Supabase credentials are valid and the connection is working.",
                        "Connection Successful",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    // If table doesn't exist, that's okay - connection works
                    if (ex.Message.Contains("relation") && ex.Message.Contains("does not exist"))
                    {
                        MessageBox.Show(
                            "Connection successful! ✓\n\nYour Supabase credentials are valid.\nNote: The attack_logs table hasn't been created yet. Please run the SQL schema script in your Supabase dashboard.",
                            "Connection Successful",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(
                            $"Connection test failed:\n\n{ex.Message}\n\nPlease check your Supabase URL and Anon Key.",
                            "Connection Failed",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Connection failed:\n\n{ex.Message}\n\nPlease check your Supabase URL and Anon Key.",
                    "Connection Failed",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
            finally
            {
                TestConnectionButton.IsEnabled = true;
                TestConnectionButton.Content = "Test Connection";
            }
        }

        private void ShowTestResult(string message, bool isSuccess)
        {
            TestConnectionResultText.Text = message;
            TestConnectionResultText.Foreground = isSuccess 
                ? new SolidColorBrush(Color.FromRgb(5, 150, 105)) // Green
                : new SolidColorBrush(Color.FromRgb(220, 38, 38)); // Red
            TestConnectionResultText.Visibility = Visibility.Visible;
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
