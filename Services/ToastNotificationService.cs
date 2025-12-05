using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Animation;
using Avalonia.Threading;

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
                // Fallback - just return if container not initialized
                return;
            }

            _ = Dispatcher.UIThread.InvokeAsync(() =>
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
                    Cursor = new Cursor(StandardCursorType.Hand),
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
            // Simple fade out animation
            _ = Task.Run(async () =>
            {
                for (int i = 10; i >= 0; i--)
                {
                    await Task.Delay(25);
                    await Dispatcher.UIThread.InvokeAsync(() =>
                    {
                        toast.Opacity = i / 10.0;
                        if (toast.RenderTransform is TranslateTransform transform)
                        {
                            transform.X = 400 * (1 - i / 10.0);
                        }
                    });
                }
                
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    if (_toastContainer != null && _toastContainer.Children.Contains(toast))
                    {
                        _toastContainer.Children.Remove(toast);
                    }
                });
            });
        }
    }
}

