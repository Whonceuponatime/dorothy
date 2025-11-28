using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace Dorothy.Services
{
    public class ToastNotificationService
    {
        private readonly Window _parentWindow;
        private Panel? _toastContainer;

        public ToastNotificationService(Window parentWindow)
        {
            _parentWindow = parentWindow;
        }

        public void Initialize(Panel container)
        {
            _toastContainer = container;
        }

        public void ShowSuccess(string message, int durationMs = 3000)
        {
            ShowToast(message, "#059669", durationMs);
        }

        public void ShowInfo(string message, int durationMs = 3000)
        {
            ShowToast(message, "#2563EB", durationMs);
        }

        public void ShowWarning(string message, int durationMs = 4000)
        {
            ShowToast(message, "#D97706", durationMs);
        }

        public void ShowError(string message, int durationMs = 5000)
        {
            ShowToast(message, "#DC2626", durationMs);
        }

        private void ShowToast(string message, string backgroundColor, int durationMs)
        {
            if (_toastContainer == null)
            {
                // Fallback to MessageBox if container not initialized
                MessageBox.Show(message, "Notification", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            _parentWindow.Dispatcher.Invoke(() =>
            {
                var toast = new Border
                {
                    Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(backgroundColor)),
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(16, 12, 16, 12),
                    Margin = new Thickness(0, 0, 0, 12),
                    MaxWidth = 400,
                    HorizontalAlignment = HorizontalAlignment.Right,
                    VerticalAlignment = VerticalAlignment.Top,
                    Opacity = 0,
                    RenderTransform = new TranslateTransform { X = 400 }
                };

                var stackPanel = new StackPanel
                {
                    Orientation = Orientation.Horizontal
                };

                var textBlock = new TextBlock
                {
                    Text = message,
                    Foreground = Brushes.White,
                    FontSize = 13,
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Center
                };

                var closeButton = new Button
                {
                    Content = "×",
                    FontSize = 18,
                    FontWeight = FontWeights.Bold,
                    Foreground = Brushes.White,
                    Background = Brushes.Transparent,
                    BorderThickness = new Thickness(0),
                    Padding = new Thickness(8, 0, 0, 0),
                    Cursor = System.Windows.Input.Cursors.Hand,
                    VerticalAlignment = VerticalAlignment.Center
                };

                closeButton.Click += (s, e) =>
                {
                    DismissToast(toast);
                };

                stackPanel.Children.Add(textBlock);
                stackPanel.Children.Add(closeButton);
                toast.Child = stackPanel;

                _toastContainer.Children.Add(toast);

                // Animate in
                var fadeIn = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(300));
                var slideIn = new DoubleAnimation(400, 0, TimeSpan.FromMilliseconds(300));

                toast.BeginAnimation(UIElement.OpacityProperty, fadeIn);
                toast.RenderTransform.BeginAnimation(TranslateTransform.XProperty, slideIn);

                // Auto dismiss
                var timer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMilliseconds(durationMs)
                };
                timer.Tick += (s, e) =>
                {
                    timer.Stop();
                    DismissToast(toast);
                };
                timer.Start();
            });
        }

        private void DismissToast(Border toast)
        {
            var fadeOut = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(250));
            var slideOut = new DoubleAnimation(0, 400, TimeSpan.FromMilliseconds(250));

            fadeOut.Completed += (s, e) =>
            {
                if (_toastContainer != null && _toastContainer.Children.Contains(toast))
                {
                    _toastContainer.Children.Remove(toast);
                }
            };

            toast.BeginAnimation(UIElement.OpacityProperty, fadeOut);
            toast.RenderTransform.BeginAnimation(TranslateTransform.XProperty, slideOut);
        }
    }
}

