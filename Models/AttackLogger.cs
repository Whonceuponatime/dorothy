using System;
using System.Windows;
using System.Windows.Controls;
using NLog;

namespace Dorothy.Models
{
    public class AttackLogger
    {
        private readonly TextBox _logArea;
        private DateTime _attackStartTime;
        private string _attackType = string.Empty;
        private string _sourceIp = string.Empty;
        private string _sourceMac = string.Empty;
        private string _targetIp = string.Empty;
        private string _targetMac = string.Empty;
        private long _targetBytesPerSecond;

        public AttackLogger(TextBox logArea)
        {
            _logArea = logArea;
        }

        public void StartAttack(AttackType attackType, string sourceIp, byte[] sourceMac, 
                          string targetIp, byte[] targetMac, long megabitsPerSecond)
        {
            _attackStartTime = DateTime.Now;
            _attackType = attackType.ToString();
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetBytesPerSecond = megabitsPerSecond * 1_000_000 / 8;

            var message = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Attack Details\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"Protocol: UDP\n" +
                         $"Source Host: {_sourceIp}\n" +
                         $"Source MAC: {_sourceMac}\n" +
                         $"Target Host: {_targetIp}\n" +
                         $"Target MAC: {_targetMac}\n" +
                         $"Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"Attack Type: {_attackType}\n" +
                         "Status: Attack Started";
            Log(message, "INFO", true);
        }

        public void LogInfo(string message)
        {
            Log(message, "INFO");
        }

        public void LogError(string message)
        {
            Log(message, "ERROR");
        }

        public void LogWarning(string message)
        {
            Log(message, "WARNING");
        }

        public void LogDebug(string message)
        {
            Log(message, "DEBUG");
        }

        private void Log(string message, string level, bool isEvent = false)
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            var logMessage = isEvent ? message : $"[{timestamp}] [{level}] {message}";
            
            _logArea.Dispatcher.Invoke(() =>
            {
                _logArea.AppendText(logMessage + Environment.NewLine);
                _logArea.ScrollToEnd();
            });
        }
    }
} 