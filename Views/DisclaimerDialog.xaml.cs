using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Dorothy.Views
{
    public partial class DisclaimerDialog : Window
    {
        public bool IsAuthorized { get; private set; } = false;

        public DisclaimerDialog()
        {
            AvaloniaXamlLoader.Load(this);
        }

        private void BackButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            IsAuthorized = false;
            Close(false);
        }
        
        protected override void OnClosing(WindowClosingEventArgs e)
        {
            // If dialog is closed without clicking Acknowledged, ensure IsAuthorized is false
            // Note: In Avalonia, we check the result after closing
            base.OnClosing(e);
        }

        private void ContinueButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            IsAuthorized = true;
            Close(true);
        }
    }
}
