using System.Windows;

namespace Dorothy.Views
{
    public partial class DisclaimerDialog : Window
    {
        public bool IsAuthorized { get; private set; } = false;

        public DisclaimerDialog()
        {
            InitializeComponent();
        }

        private void BackButton_Click(object sender, RoutedEventArgs e)
        {
            IsAuthorized = false;
            DialogResult = false;
            Close();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {

            if (DialogResult != true)
            {
                IsAuthorized = false;
            }
            base.OnClosing(e);
        }

        private void ContinueButton_Click(object sender, RoutedEventArgs e)
        {
            IsAuthorized = true;
            DialogResult = true;
            Close();
        }
    }
}
