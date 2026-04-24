using System;
using System.IO;
using System.Linq;
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

            // Subscribe BEFORE the first validation so mid-startup revocation
            // (e.g. re-check after LicenseWindow returns valid) is handled.
            int revocationInFlight = 0;
            licenseService.LicenseRevoked += (_, _) =>
            {
                // Guard against the periodic-revalidation timer firing the event
                // multiple times (e.g. if the 10-minute check completes after
                // the grace-period check already fired). The user should only
                // see one dialog.
                if (System.Threading.Interlocked.CompareExchange(
                        ref revocationInFlight, 1, 0) != 0) return;

                Dispatcher.InvokeAsync(async () =>
                {
                    try
                    {
                        // 1. Cut off any in-progress attack immediately —
                        //    revoked licenses must not keep sending traffic.
                        if (Current?.MainWindow is Views.MainWindow mw)
                        {
                            try { await mw.StopAttackIfRunningAsync(); }
                            catch (Exception ex)
                            {
                                LogManager.GetCurrentClassLogger()
                                    .Warn(ex, "[LICENSE] Error stopping attack on revocation");
                            }
                        }

                        // 2. Stop the periodic revalidation timer so it doesn't
                        //    keep firing while the dialog is up.
                        try { licenseService.StopPeriodicRevalidation(); } catch { }

                        // 3. Warning dialog so the user knows why the app just
                        //    transitioned to the License Validation screen.
                        MessageBox.Show(
                            "Your SEACURE(TOOL) license is no longer valid.\n\n" +
                            "This can happen if:\n" +
                            "  - Your license was revoked by the administrator\n" +
                            "  - The machine has been offline for more than 24 hours\n\n" +
                            "You can copy your Hardware ID to send to your administrator " +
                            "for re-approval, then click 'Restart Application' once " +
                            "approval is granted.",
                            "License Not Valid",
                            MessageBoxButton.OK,
                            MessageBoxImage.Warning);

                        // 4. Hide the main window and reopen the License
                        //    Validation dialog. That window's Copy / Restart /
                        //    Exit buttons are already wired — Restart does
                        //    Process.Start + Shutdown; Exit sets DialogResult
                        //    to false. We only need to react to the false case.
                        var main = Current?.MainWindow;
                        try { main?.Hide(); } catch { }

                        var lic = new Views.LicenseWindow(
                            licenseService.HardwareId,
                            "License revoked — contact your administrator to restore access.")
                        {
                            WindowStartupLocation = WindowStartupLocation.CenterScreen
                        };
                        var dlg = lic.ShowDialog();

                        // If we reach this point and the process is still alive,
                        // Restart button didn't fire (it Shutdowns on its own) —
                        // so the user clicked Exit. Shut the app down cleanly.
                        if (dlg != true)
                        {
                            Current?.Shutdown();
                        }
                    }
                    catch (Exception ex)
                    {
                        LogManager.GetCurrentClassLogger()
                            .Error(ex, "[LICENSE] Revocation handler threw");
                        try { Current?.Shutdown(); } catch { }
                    }
                });
            };

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

        public static void SetTheme(string theme)
        {
            if (Current == null) return;

            var themeName = string.Equals(theme, "Light", StringComparison.OrdinalIgnoreCase) ? "Light" : "Dark";
            var newUri = new Uri($"/Dorothy;component/Resources/Themes/{themeName}.xaml", UriKind.Relative);

            var merged = Current.Resources.MergedDictionaries;
            var existing = merged.FirstOrDefault(d =>
                d.Source != null &&
                d.Source.OriginalString.IndexOf("/Resources/Themes/", StringComparison.OrdinalIgnoreCase) >= 0);

            var replacement = new ResourceDictionary { Source = newUri };

            if (existing != null)
            {
                var index = merged.IndexOf(existing);
                merged.RemoveAt(index);
                merged.Insert(index, replacement);
            }
            else
            {
                merged.Add(replacement);
            }
        }

    }
}
