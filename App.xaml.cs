using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Dorothy.Services;
using NLog;
using NLog.Config;
using NLog.Targets;

namespace Dorothy
{
    public partial class App : Application
    {
        // Process-wide reference to the license service so MainWindow's
        // banner Refresh button can call ValidateLicenseAsync without
        // duplicating the singleton.
        public LicenseService? LicenseService { get; private set; }

        private static void ConfigureFileLogging()
        {
            try
            {
                var logDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "SEACURE(TOOL)",
                    "logs");
                Directory.CreateDirectory(logDir);

                var fileTarget = new FileTarget("logfile")
                {
                    FileName = Path.Combine(logDir, "dorothy-${shortdate}.log"),
                    Layout = "${longdate} [${level:uppercase=true}] " +
                             "${logger:shortName=true} - ${message} " +
                             "${exception:format=tostring}",
                    KeepFileOpen = false,
                    ConcurrentWrites = true,
                    AutoFlush = true,
                    ArchiveAboveSize = 10 * 1024 * 1024,   // 10 MB
                    MaxArchiveFiles = 5
                };

                var config = LogManager.Configuration ?? new LoggingConfiguration();
                config.AddTarget(fileTarget);
                config.AddRule(LogLevel.Info, LogLevel.Fatal, fileTarget);
                LogManager.Configuration = config;

                var logger = LogManager.GetCurrentClassLogger();
                logger.Info($"[STARTUP] Logging configured. Log directory: {logDir}");
                logger.Info("[STARTUP] If you can read this entry in dorothy-{date}.log, file logging works.");
            }
            catch (Exception ex)
            {
                // If logging setup itself fails, fall back to a debug breadcrumb
                // so we don't take down the app on a logging issue.
                System.Diagnostics.Debug.WriteLine($"[NLog] ConfigureFileLogging failed: {ex.Message}");
            }
        }

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

            // Configure NLog programmatically — the bundled nlog.config was never
            // copied into dist/ or dist-lite/ during publish, so the file target
            // silently no-op'd on shipped builds and surveyors couldn't find logs
            // to debug submit hangs. Setting it up here is bulletproof against
            // deployment quirks and lands every Logger.Info call into a real file.
            ConfigureFileLogging();

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
            LicenseService = licenseService;

            // Subscribe BEFORE the first validation so mid-startup transitions
            // (e.g. re-check after LicenseWindow returns valid) are handled.
            // Tri-state replaces the prior LicenseRevoked event:
            //   Active  → hide stale banner if showing
            //   Stale   → show yellow banner above MainWindow's TabControl
            //   Expired → existing License Validation overlay flow
            int expiredInFlight = 0;
            licenseService.LicenseStateChanged += (_, e) =>
            {
                switch (e.NewState)
                {
                    case Dorothy.Models.LicenseState.Active:
                        if (Current?.MainWindow is Views.MainWindow activeMain)
                            activeMain.HideStaleBanner();
                        break;

                    case Dorothy.Models.LicenseState.Stale:
                        if (Current?.MainWindow is Views.MainWindow staleMain
                            && e.ValidityPeriodDays.HasValue
                            && e.AgeSinceValidation.HasValue)
                        {
                            staleMain.ShowStaleBanner(
                                e.ValidityPeriodDays.Value,
                                e.AgeSinceValidation.Value.TotalDays);
                        }
                        break;

                    case Dorothy.Models.LicenseState.Expired:
                        // Same single-fire guard as before — periodic timer +
                        // grace-expiry can both land within one beat.
                        if (System.Threading.Interlocked.CompareExchange(
                                ref expiredInFlight, 1, 0) != 0) return;

                        var reason = e.Reason ?? "License is no longer valid";
                        Dispatcher.InvokeAsync(async () =>
                        {
                            try
                            {
                                // 1. Cut off any in-progress attack — expired
                                //    licenses must not keep sending traffic.
                                if (Current?.MainWindow is Views.MainWindow mw)
                                {
                                    try { await mw.StopAttackIfRunningAsync(); }
                                    catch (Exception ex)
                                    {
                                        LogManager.GetCurrentClassLogger()
                                            .Warn(ex, "[LICENSE] Error stopping attack on expiry");
                                    }
                                    // Hide the stale banner if the user was on it
                                    // when the state escalated to Expired.
                                    try { mw.HideStaleBanner(); } catch { }
                                }

                                // 2. Stop periodic revalidation while dialog is up.
                                try { licenseService.StopPeriodicRevalidation(); } catch { }

                                // 3. Warning dialog. Reason text comes from the
                                //    state-change event so the user sees the
                                //    actual cause (revoked / hard-limit / etc).
                                MessageBox.Show(
                                    "Your SEACURE(TOOL) license is no longer valid.\n\n" +
                                    reason + "\n\n" +
                                    "You can copy your Hardware ID to send to your administrator " +
                                    "for re-approval, then click 'Restart Application' once " +
                                    "approval is granted.",
                                    "License Not Valid",
                                    MessageBoxButton.OK,
                                    MessageBoxImage.Warning);

                                // 4. Hide MainWindow, reopen License Validation.
                                var main = Current?.MainWindow;
                                try { main?.Hide(); } catch { }

                                var lic = new Views.LicenseWindow(
                                    licenseService.HardwareId,
                                    reason)
                                {
                                    WindowStartupLocation = WindowStartupLocation.CenterScreen
                                };
                                var dlg = lic.ShowDialog();

                                // Restart button does Process.Start + Shutdown
                                // itself; if we land here, user clicked Exit.
                                if (dlg != true)
                                {
                                    Current?.Shutdown();
                                }
                            }
                            catch (Exception ex)
                            {
                                LogManager.GetCurrentClassLogger()
                                    .Error(ex, "[LICENSE] Expired-state handler threw");
                                try { Current?.Shutdown(); } catch { }
                            }
                        });
                        break;
                }
            };

            var licenseResult = await licenseService.ValidateLicenseAsync();

            // Expired blocks startup — open License Validation window, exit on No.
            // Stale and Active both proceed to MainWindow; Stale shows a banner
            // after the window is up (deferred since MainWindow doesn't exist yet).
            if (licenseResult.State == Dorothy.Models.LicenseState.Expired)
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

            // 2.6.0 rework: engagement is now a packaging concept materialized
            // at submit time, not a session pre-requisite. MainWindow loads
            // immediately; scans accumulate against EngagementContext.SessionId
            // until the user clicks Submit assessment.
            var mainWindow = new Views.MainWindow();
            mainWindow.Show();

            // If startup validation landed in Stale, show the banner now that
            // MainWindow exists. The LicenseStateChanged subscriber above only
            // ran during validation if the state actually transitioned from
            // Expired (default) → Stale; even on first run this fires because
            // _state starts as Expired. But MainWindow wasn't constructed yet
            // when that fired, so re-trigger the banner display here using
            // current LicenseService.State as the source of truth.
            if (licenseService.State == Dorothy.Models.LicenseState.Stale
                && licenseResult.CachedHardwareId != null)
            {
                // We don't have ValidityPeriodDays + age handy here without
                // re-reading the cache; the banner text gets refreshed on
                // the next state transition. For startup-Stale, render a
                // generic "License unchecked — refresh recommended" banner.
                mainWindow.ShowStaleBanner(0, 0);
            }
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
