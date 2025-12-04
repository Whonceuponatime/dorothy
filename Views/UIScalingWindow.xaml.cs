using System;
using System.Windows;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class UIScalingWindow : Window
    {
        private readonly UIScalingService _scalingService;

        public UIScalingWindow()
        {
            InitializeComponent();
            _scalingService = UIScalingService.Instance;
            
            // Initialize slider with current scale
            ScaleSlider.Value = _scalingService.CurrentScaleFactor;
            UpdateScaleText();
            
            // Subscribe to scale changes
            _scalingService.ScaleChanged += ScalingService_ScaleChanged;
        }

        private void ScalingService_ScaleChanged(object? sender, EventArgs e)
        {
            if (Math.Abs(ScaleSlider.Value - _scalingService.CurrentScaleFactor) > 0.01)
            {
                ScaleSlider.Value = _scalingService.CurrentScaleFactor;
                UpdateScaleText();
            }
        }

        private void ScaleSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            if (e.NewValue > 0)
            {
                _scalingService.SetScale(e.NewValue);
                UpdateScaleText();
            }
        }

        private void ZoomInButton_Click(object sender, RoutedEventArgs e)
        {
            _scalingService.ZoomIn();
            ScaleSlider.Value = _scalingService.CurrentScaleFactor;
        }

        private void ZoomOutButton_Click(object sender, RoutedEventArgs e)
        {
            _scalingService.ZoomOut();
            ScaleSlider.Value = _scalingService.CurrentScaleFactor;
        }

        private void ResetButton_Click(object sender, RoutedEventArgs e)
        {
            _scalingService.ResetZoom();
            ScaleSlider.Value = _scalingService.CurrentScaleFactor;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void UpdateScaleText()
        {
            ScaleValueText.Text = $"{_scalingService.CurrentScaleFactor * 100:F0}%";
        }

        protected override void OnClosed(EventArgs e)
        {
            _scalingService.ScaleChanged -= ScalingService_ScaleChanged;
            base.OnClosed(e);
        }
    }
}







