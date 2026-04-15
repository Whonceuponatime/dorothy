using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Dorothy.Services;
using NLog;

namespace Dorothy
{
    public partial class App : Application
    {

        private static bool IsRunningAsAdministrator()
        {
            try
            {
                using var identity =
                    System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal =
                    new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(
                    System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;

            if (!IsRunningAsAdministrator())
            {
                System.Windows.MessageBox.Show(
                    "SEACURE(TOOL) must run as Administrator.\n\n" +
                    "Reason:\n" +
                    "  Raw packet generation (flood attacks, Layer-2 injection) uses Npcap / SharpPcap,\n" +
                    "  which requires elevated access to open packet capture devices.\n\n" +
                    "Note:\n" +
                    "  TCP Connect Scan and Reachability Test features do not inherently require\n" +
                    "  Administrator access, but the application runs elevated because raw packet\n" +
                    "  generation is the primary use-case.\n\n" +
                    "Please restart using 'Run as Administrator'.",
                    "Administrator Privileges Required",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Warning);
                Shutdown(1);
                return;
            }

            var logger = LogManager.GetCurrentClassLogger();
            logger.Info("Application starting (elevated: Administrator)");

            var licenseService = new LicenseService();
            var licenseResult = await licenseService.ValidateLicenseAsync();

            if (!licenseResult.IsValid)
            {

                var displayHardwareId = !string.IsNullOrEmpty(licenseResult.CachedHardwareId)
                    ? licenseResult.CachedHardwareId
                    : licenseService.HardwareId;
                var licenseWindow = new Views.LicenseWindow(displayHardwareId, licenseResult.Message)
                {
                    WindowStartupLocation = WindowStartupLocation.CenterScreen
                };

                if (licenseWindow.ShowDialog() != true)
                {
                    Shutdown();
                    return;
                }
            }

            var mainWindow = new Views.MainWindow();
            mainWindow.Show();
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            var exception = e.ExceptionObject as Exception;
            var message = exception != null
                ? $"Unhandled Exception: {exception.Message}\n\n{exception.StackTrace}"
                : "An unknown error occurred.";

            MessageBox.Show(message, "Application Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private void App_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            var message = $"Unhandled Exception: {e.Exception.Message}\n\n{e.Exception.StackTrace}";
            MessageBox.Show(message, "Application Error", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }

    }
}
