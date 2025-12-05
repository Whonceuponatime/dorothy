using System;
using System.IO;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace Dorothy.Views
{
    public partial class DisclaimerWindow : Window
    {
        public bool DontShowAgain { get; private set; }

        public DisclaimerWindow()
        {
            AvaloniaXamlLoader.Load(this);
        }

        private void AcceptButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            DontShowAgain = DontShowAgainCheckBox.IsChecked ?? false;
            Close(true);
        }

        private void ExitButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close(false);
        }
    }
}

