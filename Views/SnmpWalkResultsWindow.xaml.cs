using System;
using System.Linq;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Dorothy.Services;

namespace Dorothy.Views
{
    public partial class SnmpWalkResultsWindow : Window
    {
        // FindControl properties for XAML-named controls
        private Border? SuccessCard => this.FindControl<Border>("SuccessCard");
        private Border? SecureCard => this.FindControl<Border>("SecureCard");
        private TextBlock? HeaderTextBlock => this.FindControl<TextBlock>("HeaderTextBlock");
        private TextBlock? SummaryTextBlock => this.FindControl<TextBlock>("SummaryTextBlock");
        private TextBlock? VulnerabilityDetailsTextBlock => this.FindControl<TextBlock>("VulnerabilityDetailsTextBlock");
        private TextBlock? SecureDetailsTextBlock => this.FindControl<TextBlock>("SecureDetailsTextBlock");
        private TextBlock? OidsTextBlock => this.FindControl<TextBlock>("OidsTextBlock");

        public SnmpWalkResultsWindow(SnmpWalkResult result)
        {
            AvaloniaXamlLoader.Load(this);
            DisplayResults(result);
        }

        private void DisplayResults(SnmpWalkResult result)
        {
            if (result.Success)
            {
                // SNMP is vulnerable - show success card
                if (SuccessCard != null) SuccessCard.IsVisible = true;
                if (SecureCard != null) SecureCard.IsVisible = false;

                if (HeaderTextBlock != null) HeaderTextBlock.Text = "SNMP Walk - Vulnerability Found";
                if (SummaryTextBlock != null) SummaryTextBlock.Text = $"Target: {result.TargetIp}:{result.Port} | Attempts: {result.Attempts} | Duration: {result.Duration.TotalSeconds:F2}s";

                if (VulnerabilityDetailsTextBlock != null)
                    VulnerabilityDetailsTextBlock.Text = 
                        $"A successful SNMP authentication was found using community string: '{result.SuccessfulCommunity}'\n\n" +
                        $"This indicates the device is using a weak or default SNMP community string, which is a security vulnerability.";

                // Display OIDs (limit to first 50 for display)
                var oidsToShow = result.SuccessfulOids.Take(50).ToList();
                if (OidsTextBlock != null)
                {
                    OidsTextBlock.Text = string.Join("\n", oidsToShow);
                    
                    if (result.SuccessfulOids.Count > 50)
                    {
                        OidsTextBlock.Text += $"\n\n... and {result.SuccessfulOids.Count - 50} more OIDs";
                    }
                }
            }
            else
            {
                // SNMP is secure - show secure card
                if (SuccessCard != null) SuccessCard.IsVisible = false;
                if (SecureCard != null) SecureCard.IsVisible = true;

                if (HeaderTextBlock != null) HeaderTextBlock.Text = "SNMP Walk - No Vulnerabilities Found";
                if (SummaryTextBlock != null) SummaryTextBlock.Text = $"Target: {result.TargetIp}:{result.Port} | Attempts: {result.Attempts} | Duration: {result.Duration.TotalSeconds:F2}s";

                if (SecureDetailsTextBlock != null)
                    SecureDetailsTextBlock.Text = 
                        $"No successful SNMP authentication was found after testing {result.Attempts} common community strings.\n\n" +
                        $"The device appears to be using a non-default or strong SNMP community string, which is a good security practice.";
            }
        }

        private void CloseButton_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
        {
            Close();
        }
    }
}

