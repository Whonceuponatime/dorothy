using System;
using System.Linq;
using System.Windows;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class SnmpWalkResultsWindow : Window
    {
        public SnmpWalkResultsWindow(SnmpWalkResult result)
        {
            InitializeComponent();
            DisplayResults(result);
        }

        private void DisplayResults(SnmpWalkResult result)
        {
            if (result.Success)
            {
                // SNMP is vulnerable - show success card
                SuccessCard.Visibility = Visibility.Visible;
                SecureCard.Visibility = Visibility.Collapsed;

                HeaderTextBlock.Text = "SNMP Walk - Vulnerability Found";
                SummaryTextBlock.Text = $"Target: {result.TargetIp}:{result.Port} | Attempts: {result.Attempts} | Duration: {result.Duration.TotalSeconds:F2}s";

                VulnerabilityDetailsTextBlock.Text = 
                    $"A successful SNMP authentication was found using community string: '{result.SuccessfulCommunity}'\n\n" +
                    $"This indicates the device is using a weak or default SNMP community string, which is a security vulnerability.";

                // Display OIDs (limit to first 50 for display)
                var oidsToShow = result.SuccessfulOids.Take(50).ToList();
                OidsTextBlock.Text = string.Join("\n", oidsToShow);
                
                if (result.SuccessfulOids.Count > 50)
                {
                    OidsTextBlock.Text += $"\n\n... and {result.SuccessfulOids.Count - 50} more OIDs";
                }
            }
            else
            {
                // SNMP is secure - show secure card
                SuccessCard.Visibility = Visibility.Collapsed;
                SecureCard.Visibility = Visibility.Visible;

                HeaderTextBlock.Text = "SNMP Walk - No Vulnerabilities Found";
                SummaryTextBlock.Text = $"Target: {result.TargetIp}:{result.Port} | Attempts: {result.Attempts} | Duration: {result.Duration.TotalSeconds:F2}s";

                SecureDetailsTextBlock.Text = 
                    $"No successful SNMP authentication was found after testing {result.Attempts} common community strings.\n\n" +
                    $"The device appears to be using a non-default or strong SNMP community string, which is a good security practice.";
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}

