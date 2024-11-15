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
        private int _messageCount = 0;

        public AttackLogger(TextBox logArea)
        {
            _logArea = logArea;
        }

        public void StartAttack(AttackType attackType, string sourceIp, byte[] sourceMac, 
                          string targetIp, byte[] targetMac, long megabitsPerSecond)
        {
            _attackStartTime = DateTime.UtcNow;
            _attackType = attackType.ToString();
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetBytesPerSecond = megabitsPerSecond * 1_000_000 / 8;

            var message = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] Attack Details\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"Protocol: UDP\n" +
                         $"Source Host: {_sourceIp}\n" +
                         $"Source MAC: {_sourceMac}\n" +
                         $"Target Host: {_targetIp}\n" +
                         $"Target MAC: {_targetMac}\n" +
                         $"Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"Attack Type: {_attackType}\n" +
                         "Status: Attack Started";
            LogEvent(message, true);
        }

        public void LogInfo(string message)
        {
            var formattedMessage = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] {message}";
            LogEvent(formattedMessage, false);
        }

        public void LogError(string message)
        {
            var formattedMessage = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] ERROR: {message}";
            LogEvent(formattedMessage, false);
        }

        public void LogWarning(string message)
        {
            var formattedMessage = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}] WARNING: {message}";
            LogEvent(formattedMessage, false);
        }

        private void LogEvent(string message, bool isAttackDetails)
        {
            _logArea.Dispatcher.Invoke(() =>
            {
                if (_messageCount > 0) _logArea.AppendText("\n");
                _logArea.AppendText(message);
                _messageCount++;
                
                if (message.Contains("Attack finished successfully") || isAttackDetails)
                {
                    _logArea.AppendText("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                }
                _logArea.ScrollToEnd();
            });
        }
    }
} 