using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Interop;

namespace Dorothy.Services
{

    public class UIScalingService
    {
        private static UIScalingService? _instance;
        public static UIScalingService Instance => _instance ??= new UIScalingService();

        private double _currentScaleFactor = 1.0;
        private const double MinScale = 0.5;
        private const double MaxScale = 2.0;
        private const double ScaleStep = 0.1;

        [DllImport("user32.dll")]
        private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

        [DllImport("user32.dll")]
        private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

        [DllImport("shcore.dll")]
        private static extern int GetDpiForMonitor(IntPtr hmonitor, int dpiType, out uint dpiX, out uint dpiY);

        private const int MONITOR_DEFAULTTONEAREST = 0x00000002;
        private const int MDT_EFFECTIVE_DPI = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int Size;
            public RECT Monitor;
            public RECT WorkArea;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;

            public int Width => Right - Left;
            public int Height => Bottom - Top;
        }

        public double CurrentScaleFactor
        {
            get => _currentScaleFactor;
            private set
            {
                _currentScaleFactor = Math.Max(MinScale, Math.Min(MaxScale, value));
                ScaleChanged?.Invoke(this, EventArgs.Empty);
            }
        }

        public event EventHandler? ScaleChanged;

        private UIScalingService()
        {

            CurrentScaleFactor = GetSystemDpiScale();
        }

        public double GetSystemDpiScale()
        {
            try
            {
                var source = PresentationSource.FromVisual(Application.Current.MainWindow);
                if (source?.CompositionTarget != null)
                {
                    var dpiX = source.CompositionTarget.TransformToDevice.M11;
                    var dpiY = source.CompositionTarget.TransformToDevice.M22;
                    return (dpiX + dpiY) / 2.0;
                }
            }
            catch
            {

            }

            return SystemParameters.PrimaryScreenHeight / 1080.0;
        }

        public double GetDpiScaleForWindow(Window window)
        {
            try
            {
                var source = PresentationSource.FromVisual(window);
                if (source?.CompositionTarget != null)
                {
                    var dpiX = source.CompositionTarget.TransformToDevice.M11;
                    var dpiY = source.CompositionTarget.TransformToDevice.M22;
                    return (dpiX + dpiY) / 2.0;
                }
            }
            catch
            {

            }

            return 1.0;
        }

        public (double Width, double Height) GetScreenDimensionsForWindow(Window window)
        {
            try
            {
                var windowHandle = new WindowInteropHelper(window).Handle;
                if (windowHandle != IntPtr.Zero)
                {

                    var monitor = MonitorFromWindow(windowHandle, MONITOR_DEFAULTTONEAREST);
                    if (monitor != IntPtr.Zero)
                    {

                        var monitorInfo = new MONITORINFO
                        {
                            Size = Marshal.SizeOf(typeof(MONITORINFO))
                        };

                        if (GetMonitorInfo(monitor, ref monitorInfo))
                        {

                            var screenWidth = (double)monitorInfo.WorkArea.Width;
                            var screenHeight = (double)monitorInfo.WorkArea.Height;

                            var fullScreenWidth = (double)monitorInfo.Monitor.Width;
                            var fullScreenHeight = (double)monitorInfo.Monitor.Height;

                            return (fullScreenWidth, fullScreenHeight);
                        }
                    }
                }
            }
            catch (Exception ex)
            {

                System.Diagnostics.Debug.WriteLine($"Error getting monitor info: {ex.Message}");
            }

            if (window.WindowState == WindowState.Maximized)
            {
                return (SystemParameters.WorkArea.Width, SystemParameters.WorkArea.Height);
            }
            return (SystemParameters.PrimaryScreenWidth, SystemParameters.PrimaryScreenHeight);
        }

        public double CalculateResponsiveScale(Window? window = null, double baseWidth = 1920, double baseHeight = 1080)
        {
            double screenWidth, screenHeight;

            if (window != null)
            {
                var dimensions = GetScreenDimensionsForWindow(window);
                screenWidth = dimensions.Width;
                screenHeight = dimensions.Height;
            }
            else
            {
                screenWidth = SystemParameters.PrimaryScreenWidth;
                screenHeight = SystemParameters.PrimaryScreenHeight;
            }

            var widthScale = screenWidth / baseWidth;
            var heightScale = screenHeight / baseHeight;

            var scale = Math.Min(widthScale, heightScale);

            if (screenWidth < 1366 || screenHeight < 768)
            {

                scale = Math.Max(0.7, Math.Min(0.85, scale));
            }
            else if (screenWidth < 1600 || screenHeight < 900)
            {

                scale = Math.Max(0.85, Math.Min(0.95, scale));
            }
            else
            {

                scale = Math.Max(0.9, Math.Min(1.2, scale));
            }

            return scale;
        }

        public void ZoomIn()
        {
            CurrentScaleFactor += ScaleStep;
        }

        public void ZoomOut()
        {
            CurrentScaleFactor -= ScaleStep;
        }

        public void ResetZoom()
        {
            CurrentScaleFactor = 1.0;
        }

        public void SetScale(double scale)
        {
            CurrentScaleFactor = scale;
        }

        public void ApplyScaleTransform(FrameworkElement element, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;

            if (element.RenderTransform is not ScaleTransform scaleTransform)
            {
                scaleTransform = new ScaleTransform();
                element.RenderTransform = scaleTransform;
                element.RenderTransformOrigin = new Point(0.5, 0.5);
            }

            scaleTransform.ScaleX = scaleValue;
            scaleTransform.ScaleY = scaleValue;
        }

        public void ApplyFontScaling(Window window, double baseFontSize = 12, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            window.FontSize = baseFontSize * scaleValue;
        }

        public double GetScaledFontSize(double baseFontSize, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            return baseFontSize * scaleValue;
        }

        public Thickness GetScaledThickness(double baseThickness, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            var scaled = baseThickness * scaleValue;
            return new Thickness(scaled);
        }

        public Thickness GetScaledThickness(double left, double top, double right, double bottom, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            return new Thickness(
                left * scaleValue,
                top * scaleValue,
                right * scaleValue,
                bottom * scaleValue
            );
        }

        public ScreenCategory GetScreenCategory(Window? window = null)
        {
            double screenWidth, screenHeight;

            if (window != null)
            {
                var dimensions = GetScreenDimensionsForWindow(window);
                screenWidth = dimensions.Width;
                screenHeight = dimensions.Height;
            }
            else
            {
                screenWidth = SystemParameters.PrimaryScreenWidth;
                screenHeight = SystemParameters.PrimaryScreenHeight;
            }

            if (screenWidth < 1366 || screenHeight < 768)
                return ScreenCategory.Small;
            if (screenWidth < 1600 || screenHeight < 900)
                return ScreenCategory.Medium;
            if (screenWidth < 2560 || screenHeight < 1440)
                return ScreenCategory.Large;

            return ScreenCategory.ExtraLarge;
        }

        public (double Width, double Height) GetRecommendedMinSize(Window? window = null)
        {
            return GetScreenCategory(window) switch
            {
                ScreenCategory.Small => (800, 600),
                ScreenCategory.Medium => (1000, 650),
                ScreenCategory.Large => (1200, 700),
                ScreenCategory.ExtraLarge => (1400, 800),
                _ => (1200, 700)
            };
        }
    }

    public enum ScreenCategory
    {
        Small,
        Medium,
        Large,
        ExtraLarge
    }
}

