using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Dorothy.Services;
using NLog;
using Supabase;

namespace Dorothy
{
    public partial class App : Application
    {
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                // Global exception handling
                AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

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
                _ = InitializeAndShowMainWindow(desktop, supabaseClient);
            }

            base.OnFrameworkInitializationCompleted();
        }

        private async Task InitializeAndShowMainWindow(IClassicDesktopStyleApplicationLifetime desktop, Supabase.Client? supabaseClient)
        {
            try
            {
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

                    var result = await licenseWindow.ShowDialog<bool>(desktop.MainWindow ?? new Window());
                    if (!result)
                    {
                        desktop.Shutdown();
                        return;
                    }
                }

                desktop.MainWindow = new Views.MainWindow();
                desktop.MainWindow.Show();
            }
            catch (Exception ex)
            {
                var logger = LogManager.GetCurrentClassLogger();
                logger.Error(ex, "Failed to initialize application");
                desktop.Shutdown();
            }
        }

        private void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            var exception = e.ExceptionObject as Exception;
            var message = exception != null
                ? $"Unhandled Exception: {exception.Message}\n\n{exception.StackTrace}"
                : "An unknown error occurred.";

            // Use Avalonia message box
            var window = new Window
            {
                Title = "Application Error",
                Content = new TextBlock
                {
                    Text = message,
                    TextWrapping = Avalonia.Media.TextWrapping.Wrap,
                    Margin = new Thickness(20)
                },
                Width = 600,
                Height = 400,
                WindowStartupLocation = WindowStartupLocation.CenterScreen
            };
            window.Show();
        }
    }
}
