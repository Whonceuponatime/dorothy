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

            var message = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"Status: Attack Started\n" +
                         $"Protocol: {attackType}\n" +
                         $"Source Host: {_sourceIp}\n" +
                         $"Source MAC: {_sourceMac}\n" +
                         $"Target Host: {_targetIp}\n" +
                         $"Target MAC: {_targetMac}\n" +
                         $"Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"Attack Type: {_attackType}\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            Log(message, true);
        }

        public void StartEthernetAttack(EthernetFlood.EthernetPacketType packetType, string sourceIp, byte[] sourceMac, 
                          string targetIp, byte[] targetMac, long megabitsPerSecond)
        {
            _attackStartTime = DateTime.Now;
            _attackType = $"Ethernet {packetType}";
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetBytesPerSecond = megabitsPerSecond * 1_000_000 / 8;

            var message = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"Status: Attack Started\n" +
                         $"Protocol: Ethernet\n" +
                         $"Source Host: {_sourceIp}\n" +
                         $"Source MAC: {_sourceMac}\n" +
                         $"Target Host: {_targetIp}\n" +
                         $"Target MAC: {_targetMac}\n" +
                         $"Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"Attack Type: {_attackType}\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            Log(message, true);
        }

        public void StopAttack()
        {
            var message = "Status: Attack Stopped\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            Log(message, true);
        }

        public void LogPing(string targetIp, bool success, int? rtt = null)
        {
            var result = success ? (rtt.HasValue ? $"success (RTT: {rtt}ms)" : "success") : "failed";
            Log($"Ping {targetIp}: {result}");
        }

        public void LogMacResolution(string ip, string mac, bool isGateway = false)
        {
            var target = isGateway ? "Gateway" : "Target";
            Log($"Using {target.ToLower()} MAC for {ip}: {mac}");
        }

        public void LogAttackTypeChange(string newType)
        {
            Log($"Attack type changed to: {newType}");
        }

        public void LogInfo(string message)
        {
            Log(message);
        }

        public void LogError(string message)
        {
            Log($"Error: {message}");
        }

        public void LogWarning(string message)
        {
            Log($"Warning: {message}");
        }

        public void LogDebug(string message)
        {
            Log($"Debug: {message}");
        }

        public void LogNote(string note)
        {
            try
            {
                _logArea.Dispatcher.Invoke(() =>
                {
                    _logArea.AppendText(note);
                    _logArea.ScrollToEnd();
                });
            }
            catch (Exception ex)
            {
                LogError($"Failed to log note: {ex.Message}");
            }
        }

        private void Log(string message, bool isEvent = false)
        {
            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var logMessage = isEvent ? message : $"[{timestamp}] {message}";
            
            _logArea.Dispatcher.Invoke(() =>
            {
                _logArea.AppendText($"{logMessage}{Environment.NewLine}");
                _logArea.ScrollToEnd();
            });
        }
    }
} 