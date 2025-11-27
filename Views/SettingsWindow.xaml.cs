using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Interop;
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

            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
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
