using System;
using System.IO;
using System.Windows;

namespace Dorothy.Views
{
    public partial class DisclaimerWindow : Window
    {
        public bool DontShowAgain { get; private set; }

        public DisclaimerWindow()
        {
            InitializeComponent();
        }

        private void AcceptButton_Click(object sender, RoutedEventArgs e)
        {
            DontShowAgain = DontShowAgainCheckBox.IsChecked ?? false;
            DialogResult = true;
            Close();
        }

        private void ExitButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}

