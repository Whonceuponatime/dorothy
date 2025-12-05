using System;
using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.ReactiveUI;

namespace Dorothy
{
    internal class Program
    {
        // Initialization code. Don't use any Avalonia, third-party APIs or any
        // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
        // yet and stuff might break.
        [STAThread]
        public static void Main(string[] args)
        {
            // Check for X11 display on Linux before attempting to initialize GUI
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var display = Environment.GetEnvironmentVariable("DISPLAY");
                if (string.IsNullOrEmpty(display))
                {
                    Console.Error.WriteLine("ERROR: DISPLAY environment variable is not set.");
                    Console.Error.WriteLine();
                    Console.Error.WriteLine("This application requires a graphical display to run.");
                    Console.Error.WriteLine();
                    Console.Error.WriteLine("Possible solutions:");
                    Console.Error.WriteLine("  1. If running over SSH, use X11 forwarding:");
                    Console.Error.WriteLine("     ssh -X username@hostname");
                    Console.Error.WriteLine("  2. If on a headless server, install and configure X11:");
                    Console.Error.WriteLine("     sudo apt-get install xorg xauth");
                    Console.Error.WriteLine("  3. Set DISPLAY variable if using a remote X server:");
                    Console.Error.WriteLine("     export DISPLAY=:0.0");
                    Console.Error.WriteLine();
                    Environment.Exit(1);
                }
            }

            try
            {
                BuildAvaloniaApp()
                    .StartWithClassicDesktopLifetime(args);
            }
            catch (Exception ex) when (ex.Message.Contains("XOpenDisplay") || ex.Message.Contains("X11"))
            {
                Console.Error.WriteLine("ERROR: Failed to connect to X11 display server.");
                Console.Error.WriteLine();
                Console.Error.WriteLine($"Details: {ex.Message}");
                Console.Error.WriteLine();
                Console.Error.WriteLine("This application requires a graphical display to run.");
                Console.Error.WriteLine();
                Console.Error.WriteLine("Possible solutions:");
                Console.Error.WriteLine("  1. Ensure X11 is running and accessible");
                Console.Error.WriteLine("  2. If running over SSH, use X11 forwarding:");
                Console.Error.WriteLine("     ssh -X username@hostname");
                Console.Error.WriteLine("  3. Install X11 libraries if missing:");
                Console.Error.WriteLine("     sudo apt-get install libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev");
                Console.Error.WriteLine("  4. Verify DISPLAY variable is set correctly:");
                Console.Error.WriteLine($"     Current DISPLAY: {Environment.GetEnvironmentVariable("DISPLAY") ?? "(not set)"}");
                Console.Error.WriteLine();
                Environment.Exit(1);
            }
        }

        // Avalonia configuration, don't remove; also used by visual designer.
        public static AppBuilder BuildAvaloniaApp()
            => AppBuilder.Configure<App>()
                .UsePlatformDetect()
                .WithInterFont()
                .LogToTrace()
                .UseReactiveUI();
    }
}

