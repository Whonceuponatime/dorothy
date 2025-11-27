using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;
using Dorothy.Models;
using ClosedXML.Excel;
using Microsoft.Win32;

namespace Dorothy.Views
{
    public partial class NetworkScanWindow : Window
    {
        private readonly NetworkScan _networkScan;
        private readonly AttackLogger _attackLogger;
        private List<NetworkAsset> _assets = new List<NetworkAsset>();
        private CancellationTokenSource? _cancellationTokenSource;

        public NetworkScanWindow(NetworkScan networkScan, AttackLogger attackLogger)
        {
            InitializeComponent();
            _networkScan = networkScan;
            _attackLogger = attackLogger;
        }

        public async Task StartScanAsync(string networkAddress, string subnetMask)
        {
            try
            {
                _cancellationTokenSource = new CancellationTokenSource();
                StatusTextBlock.Text = "Scanning network... Please wait.";
                ExportExcelButton.IsEnabled = false;

                _assets = await _networkScan.ScanNetworkAsync(networkAddress, subnetMask, _cancellationTokenSource.Token);
                
                ResultsDataGrid.ItemsSource = _assets;
                StatusTextBlock.Text = $"Scan complete. Found {_assets.Count} active devices.";
                ExportExcelButton.IsEnabled = _assets.Count > 0;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Scan failed: {ex.Message}";
                MessageBox.Show($"Network scan failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportExcelButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var saveDialog = new SaveFileDialog
                {
                    Filter = "Excel Files (*.xlsx)|*.xlsx|All Files (*.*)|*.*",
                    FileName = $"NetworkScan_{DateTime.Now:yyyyMMdd_HHmmss}.xlsx",
                    DefaultExt = "xlsx"
                };

                if (saveDialog.ShowDialog() == true)
                {
                    ExportToExcel(saveDialog.FileName);
                    MessageBox.Show($"Network scan results exported to:\n{saveDialog.FileName}", "Export Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export to Excel: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportToExcel(string filePath)
        {
            using var workbook = new XLWorkbook();
            var worksheet = workbook.Worksheets.Add("Network Assets");

            // Add headers
            worksheet.Cell(1, 1).Value = "IP Address";
            worksheet.Cell(1, 2).Value = "MAC Address";
            worksheet.Cell(1, 3).Value = "Hostname";
            worksheet.Cell(1, 4).Value = "Vendor";
            worksheet.Cell(1, 5).Value = "Status";
            worksheet.Cell(1, 6).Value = "Round Trip Time (ms)";

            // Style headers
            var headerRange = worksheet.Range(1, 1, 1, 6);
            headerRange.Style.Font.Bold = true;
            headerRange.Style.Fill.BackgroundColor = XLColor.LightGray;
            headerRange.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;

            // Add data
            int row = 2;
            foreach (var asset in _assets)
            {
                worksheet.Cell(row, 1).Value = asset.IpAddress;
                worksheet.Cell(row, 2).Value = asset.MacAddress;
                worksheet.Cell(row, 3).Value = asset.Hostname;
                worksheet.Cell(row, 4).Value = asset.Vendor;
                worksheet.Cell(row, 5).Value = asset.Status;
                worksheet.Cell(row, 6).Value = asset.RoundTripTime?.ToString() ?? "N/A";
                row++;
            }

            // Auto-fit columns
            worksheet.Columns().AdjustToContents();

            // Add summary sheet
            var summarySheet = workbook.Worksheets.Add("Summary");
            summarySheet.Cell(1, 1).Value = "Network Scan Summary";
            summarySheet.Cell(1, 1).Style.Font.Bold = true;
            summarySheet.Cell(1, 1).Style.Font.FontSize = 14;
            
            summarySheet.Cell(3, 1).Value = "Total Devices Found:";
            summarySheet.Cell(3, 2).Value = _assets.Count;
            summarySheet.Cell(4, 1).Value = "Scan Date:";
            summarySheet.Cell(4, 2).Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            
            summarySheet.Columns().AdjustToContents();

            workbook.SaveAs(filePath);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            Close();
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            _cancellationTokenSource?.Cancel();
            base.OnClosing(e);
        }
    }

    public class NullableLongConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            var nullableLong = value as long?;
            if (nullableLong.HasValue)
            {
                return nullableLong.Value.ToString();
            }
            return "N/A";
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}

