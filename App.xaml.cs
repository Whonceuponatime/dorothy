using System;
using System.Windows;
using System.Windows.Threading;
using NLog;

namespace Dorothy
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            
            // Global exception handling
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            DispatcherUnhandledException += App_DispatcherUnhandledException;
            
            var mainWindow = new Views.MainWindow();
            mainWindow.Show();

            var logger = LogManager.GetCurrentClassLogger();
            logger.Info("Application starting");
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
