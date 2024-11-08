using System;
using System.Windows;
using System.Windows.Controls;
using NLog;

namespace Dorothy.Models
{
    public class AttackLogger
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private const int LOG_INTERVAL_MS = 1000;
        private readonly string _attackType;
        private readonly string _targetIp;
        private readonly string _sourceIp;
        private readonly string _sourceMac;
        private readonly string _targetMac;
        private readonly long _targetBytesPerSecond;
        private readonly TextBox _logArea;
        private long _lastLogTime;
        private readonly DateTime _attackStartTime;

        public AttackLogger(string attackType, string targetIp, string targetMac, 
                          string sourceIp, string sourceMac, long targetBytesPerSecond, 
                          TextBox logArea)
        {
            _attackType = attackType ?? throw new ArgumentNullException(nameof(attackType));
            _targetIp = targetIp ?? throw new ArgumentNullException(nameof(targetIp));
            _targetMac = targetMac ?? throw new ArgumentNullException(nameof(targetMac));
            _sourceIp = sourceIp ?? throw new ArgumentNullException(nameof(sourceIp));
            _sourceMac = sourceMac ?? throw new ArgumentNullException(nameof(sourceMac));
            _targetBytesPerSecond = targetBytesPerSecond;
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _attackStartTime = DateTime.UtcNow;

            LogInitialDetails();
        }

        private void LogInitialDetails()
        {
            var message = $"[{DateTime.UtcNow:HH:mm:ss}] Attack Details:\n" +
                         $"Type: {_attackType}\n" +
                         $"Source: {_sourceIp} ({_sourceMac})\n" +
                         $"Target: {_targetIp} ({_targetMac})\n" +
                         $"Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         "Status: Started\n";

            LogEvent(message);
            Logger.Info($"Starting {_attackType} attack from {_sourceIp} to {_targetIp}");
        }

        public void LogStats(double currentRate, double targetRate, long totalPackets, double totalDataSent)
        {
            var now = DateTime.UtcNow;
            if ((now - new DateTime(_lastLogTime).ToUniversalTime()).TotalMilliseconds < LOG_INTERVAL_MS)
                return;

            var performance = GetPerformanceStatus(currentRate, targetRate);
            var duration = now - _attackStartTime;
            
            var stats = $"[{now:HH:mm:ss}] Attack Progress:\n" +
                       $"Source: {_sourceIp} ({_sourceMac})\n" +
                       $"Target: {_targetIp} ({_targetMac})\n" +
                       $"Attack Type: {_attackType}\n" +
                       $"Current Rate: {currentRate:F2} Mbps\n" +
                       $"Target Rate: {targetRate:F2} Mbps\n" +
                       $"Total Data: {FormatDataSize(totalDataSent)}\n" +
                       $"Packets Sent: {totalPackets:N0}\n" +
                       $"Performance: {performance}\n" +
                       $"Duration: {duration:hh\\:mm\\:ss}\n";

            LogEvent(stats);
            _lastLogTime = now.Ticks;
        }

        public void LogStop()
        {
            var duration = DateTime.UtcNow - _attackStartTime;
            var message = $"[{DateTime.UtcNow:HH:mm:ss}] Attack Terminated:\n" +
                         $"Type: {_attackType}\n" +
                         $"Source: {_sourceIp} ({_sourceMac})\n" +
                         $"Target: {_targetIp} ({_targetMac})\n" +
                         $"Duration: {duration:hh\\:mm\\:ss}\n";

            LogEvent(message);
            Logger.Info($"Stopped {_attackType} attack after {duration:hh\\:mm\\:ss}");
        }

        private string GetPerformanceStatus(double currentRate, double targetRate)
        {
            var ratio = currentRate / targetRate;
            return ratio switch
            {
                < 0.8 => "BELOW TARGET",
                > 1.2 => "EXCEEDING TARGET",
                _ => "ON TARGET"
            };
        }

        private string FormatDataSize(double bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            while (bytes >= 1024 && order < sizes.Length - 1)
            {
                order++;
                bytes /= 1024;
            }
            return $"{bytes:F2} {sizes[order]}";
        }

        private void LogEvent(string message)
        {
            try
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    _logArea.AppendText(message + "\n\n");
                    _logArea.ScrollToEnd();
                });
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to log to UI");
            }
        }
    }
} 