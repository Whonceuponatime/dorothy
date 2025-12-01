using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Dorothy.Services;
using NLog;
using Supabase;

namespace Dorothy
{
    public partial class App : Application
    {
        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            // Global exception handling
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;

            var logger = LogManager.GetCurrentClassLogger();
            logger.Info("Application starting");

            // Initialize Supabase client with hardcoded credentials for license validation
            Supabase.Client? supabaseClient = null;
            try
            {
                var options = new SupabaseOptions
                        {
                            AutoConnectRealtime = false,
                            AutoRefreshToken = false
                        };
                supabaseClient = new Client(SupabaseConfig.Url, SupabaseConfig.AnonKey, options);
                        logger.Info("Supabase client initialized for license validation");
            }
            catch (Exception ex)
            {
                logger.Warn(ex, "Failed to initialize Supabase client, using local whitelist only");
            }

            // License validation - checks Supabase first (if configured), then local file
            var licenseService = new LicenseService(supabaseClient);
            var licenseResult = await licenseService.ValidateLicenseAsync();

            if (!licenseResult.IsValid)
            {
                // Show license window and exit if not authorized
                // Use cached hardware ID if available (for offline display), otherwise use current hardware ID
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
            e.Handled = true; // Prevent app crash
        }

    }
}
