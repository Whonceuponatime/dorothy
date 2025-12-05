using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace Dorothy.Services
{
    /// <summary>
    /// Service for managing UI scaling, DPI awareness, and zoom functionality
    /// </summary>
    public class UIScalingService
    {
        private static UIScalingService? _instance;
        public static UIScalingService Instance => _instance ??= new UIScalingService();

        private double _currentScaleFactor = 1.0;
        private const double MinScale = 0.5;
        private const double MaxScale = 2.0;
        private const double ScaleStep = 0.1;

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
            // Initialize with system DPI scale
            CurrentScaleFactor = GetSystemDpiScale();
        }

        /// <summary>
        /// Gets the system DPI scale factor for the primary monitor
        /// </summary>
        public double GetSystemDpiScale()
        {
            try
            {
                var app = Application.Current;
                if (app?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
                {
                    var mainWindow = desktop.MainWindow;
                    if (mainWindow != null)
                    {
                        var screen = mainWindow.Screens.Primary;
                        if (screen != null)
                        {
                            return screen.PixelDensity;
                        }
                    }
                }
            }
            catch
            {
                // Fallback if window not yet created
            }

            // Fallback: assume 1.0 scale
            return 1.0;
        }

        /// <summary>
        /// Gets DPI scale for a specific window
        /// </summary>
        public double GetDpiScaleForWindow(Window window)
        {
            try
            {
                var screen = window.Screens.ScreenFromVisual(window);
                if (screen != null)
                {
                    return screen.PixelDensity;
                }
            }
            catch
            {
                // Fallback
            }

            return 1.0;
        }

        /// <summary>
        /// Calculates responsive scale based on screen size
        /// </summary>
        public double CalculateResponsiveScale(double baseWidth = 1920, double baseHeight = 1080)
        {
            try
            {
                var app = Application.Current;
                if (app?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
                {
                    var mainWindow = desktop.MainWindow;
                    if (mainWindow != null)
                    {
                        var screen = mainWindow.Screens.Primary;
                        if (screen != null)
                        {
                            var screenWidth = screen.Bounds.Width;
                            var screenHeight = screen.Bounds.Height;

                            var widthScale = screenWidth / baseWidth;
                            var heightScale = screenHeight / baseHeight;

                            // Use the smaller scale to ensure everything fits
                            var scale = Math.Min(widthScale, heightScale);

                            // Clamp between reasonable bounds
                            return Math.Max(0.6, Math.Min(1.5, scale));
                        }
                    }
                }
            }
            catch
            {
                // Fallback
            }

            return 1.0;
        }

        /// <summary>
        /// Increases UI scale
        /// </summary>
        public void ZoomIn()
        {
            CurrentScaleFactor += ScaleStep;
        }

        /// <summary>
        /// Decreases UI scale
        /// </summary>
        public void ZoomOut()
        {
            CurrentScaleFactor -= ScaleStep;
        }

        /// <summary>
        /// Resets UI scale to default (1.0)
        /// </summary>
        public void ResetZoom()
        {
            CurrentScaleFactor = 1.0;
        }

        /// <summary>
        /// Sets UI scale to a specific value
        /// </summary>
        public void SetScale(double scale)
        {
            CurrentScaleFactor = scale;
        }

        /// <summary>
        /// Applies scaling transform to a Control
        /// </summary>
        public void ApplyScaleTransform(Control element, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            
            if (element.RenderTransform is not ScaleTransform scaleTransform)
            {
                scaleTransform = new ScaleTransform();
                element.RenderTransform = scaleTransform;
                element.RenderTransformOrigin = new RelativePoint(0.5, 0.5, RelativeUnit.Relative);
            }

            scaleTransform.ScaleX = scaleValue;
            scaleTransform.ScaleY = scaleValue;
        }

        /// <summary>
        /// Applies scaling to window-level font size
        /// </summary>
        public void ApplyFontScaling(Window window, double baseFontSize = 12, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            window.FontSize = baseFontSize * scaleValue;
        }

        /// <summary>
        /// Gets recommended font size based on scale
        /// </summary>
        public double GetScaledFontSize(double baseFontSize, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            return baseFontSize * scaleValue;
        }

        /// <summary>
        /// Gets recommended margin/padding based on scale
        /// </summary>
        public Thickness GetScaledThickness(double baseThickness, double? scale = null)
        {
            var scaleValue = scale ?? CurrentScaleFactor;
            var scaled = baseThickness * scaleValue;
            return new Thickness(scaled);
        }

        /// <summary>
        /// Gets recommended margin/padding with individual values
        /// </summary>
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

        /// <summary>
        /// Gets screen category for responsive design
        /// </summary>
        public ScreenCategory GetScreenCategory()
        {
            try
            {
                var app = Application.Current;
                if (app?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop)
                {
                    var mainWindow = desktop.MainWindow;
                    if (mainWindow != null)
                    {
                        var screen = mainWindow.Screens.Primary;
                        if (screen != null)
                        {
                            var screenWidth = screen.Bounds.Width;
                            var screenHeight = screen.Bounds.Height;

                            if (screenWidth < 1366 || screenHeight < 768)
                                return ScreenCategory.Small;
                            if (screenWidth < 1600 || screenHeight < 900)
                                return ScreenCategory.Medium;
                            if (screenWidth < 2560 || screenHeight < 1440)
                                return ScreenCategory.Large;
                            
                            return ScreenCategory.ExtraLarge;
                        }
                    }
                }
            }
            catch
            {
                // Fallback
            }

            return ScreenCategory.Medium;
        }

        /// <summary>
        /// Gets recommended minimum window size based on screen category
        /// </summary>
        public (double Width, double Height) GetRecommendedMinSize()
        {
            return GetScreenCategory() switch
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
        Small,      // < 1366x768
        Medium,     // 1366x768 - 1600x900
        Large,      // 1600x900 - 2560x1440
        ExtraLarge  // > 2560x1440
    }
}







