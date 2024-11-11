using System;
using System.IO;
using System.Windows;
using NLog;

namespace Dorothy
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            var mainWindow = new Views.MainWindow();
            mainWindow.Show();

            var logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            
            if (!Directory.Exists(logPath))
            {
                Directory.CreateDirectory(logPath);
            }

            var logger = LogManager.GetCurrentClassLogger();
            logger.Info("Application starting");
            logger.Debug("Log directory created at: " + logPath);
        }
    }
}
