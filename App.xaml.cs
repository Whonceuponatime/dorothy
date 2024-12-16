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

            var logger = LogManager.GetCurrentClassLogger();
            logger.Info("Application starting");
        }
    }
}
