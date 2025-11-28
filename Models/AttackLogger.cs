using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Dorothy.Models.Database;
using Dorothy.Services;
using NLog;

namespace Dorothy.Models
{
    public class AttackLogger
    {
        private readonly TextBox _logArea;
        private readonly DatabaseService? _databaseService;
        private DateTime _attackStartTime;
        private string _attackType = string.Empty;
        private string _protocol = string.Empty;
        private string _sourceIp = string.Empty;
        private string _sourceMac = string.Empty;
        private string _targetIp = string.Empty;
        private string _targetMac = string.Empty;
        private int _targetPort = 0;
        private long _targetBytesPerSecond;
        private long _packetsSent = 0;
        private string _currentLogContent = string.Empty;
        private long? _currentLogId = null;

        public AttackLogger(TextBox logArea, DatabaseService? databaseService = null)
        {
            _logArea = logArea;
            _databaseService = databaseService;
        }

        public void StartAttack(AttackType attackType, string sourceIp, byte[] sourceMac, 
                          string targetIp, byte[] targetMac, long megabitsPerSecond, int targetPort = 0)
        {
            _attackStartTime = DateTime.Now;
            _attackType = attackType.ToString();
            _protocol = attackType.ToString(); // Protocol same as attack type
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetPort = targetPort;
            _targetBytesPerSecond = megabitsPerSecond * 1_000_000 / 8;
            _packetsSent = 0;

            var targetPortStr = targetPort > 0 ? $":{targetPort}" : "";
            var message = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"⚡ Status: Attack Started\n" +
                         $"📡 Protocol: {attackType}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔌 Source MAC: {_sourceMac}\n" +
                         $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                         $"🔌 Target MAC: {_targetMac}\n" +
                         $"⚡ Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"📋 Attack Type: {_attackType}\n" +
                         $"🕐 Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            Log(message, LogLevel.Info, true);
        }

        public void StartEthernetAttack(EthernetFlood.EthernetPacketType packetType, string sourceIp, byte[] sourceMac, 
                          string targetIp, byte[] targetMac, long megabitsPerSecond, int targetPort = 0)
        {
            _attackStartTime = DateTime.Now;
            _attackType = $"Ethernet {packetType}";
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetPort = targetPort;
            _targetBytesPerSecond = megabitsPerSecond * 1_000_000 / 8;
            _packetsSent = 0;
            
            // Store protocol for database
            _protocol = $"Ethernet {packetType}";

            var targetPortStr = targetPort > 0 ? $":{targetPort}" : "";
            var message = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"⚡ Status: Attack Started\n" +
                         $"📡 Protocol: Ethernet\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔌 Source MAC: {_sourceMac}\n" +
                         $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                         $"🔌 Target MAC: {_targetMac}\n" +
                         $"⚡ Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"📋 Attack Type: {_attackType}\n" +
                         $"🕐 Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            Log(message, LogLevel.Info, true);
        }

        public void StopAttack(long packetsSent = 0)
        {
            var stopTime = DateTime.Now;
            var duration = stopTime - _attackStartTime;
            _packetsSent = packetsSent;

            var targetPortStr = _targetPort > 0 ? $":{_targetPort}" : "";
            var durationStr = duration.TotalHours >= 1 
                ? $"{(int)duration.TotalHours:D2}:{duration.Minutes:D2}:{duration.Seconds:D2}"
                : $"{duration.Minutes:D2}:{duration.Seconds:D2}";

            var message = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                         $"⏹️  Status: Attack Stopped\n" +
                         $"📡 Protocol: {_attackType}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔌 Source MAC: {_sourceMac}\n" +
                         $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                         $"🔌 Target MAC: {_targetMac}\n" +
                         $"⚡ Target Rate: {_targetBytesPerSecond * 8.0 / 1_000_000:F2} Mbps\n" +
                         $"📊 Packets Sent: {_packetsSent:N0}\n" +
                         $"⏱️  Duration: {durationStr}\n" +
                         $"🕐 Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         $"🕐 Stop Time: {stopTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
            Log(message, LogLevel.Info, true);

            // Save to database if available
            if (_databaseService != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        // Get current log content
                        _logArea.Dispatcher.Invoke(() =>
                        {
                            _currentLogContent = _logArea.Text;
                        });

                        var logEntry = new AttackLogEntry
                        {
                            AttackType = _attackType,
                            Protocol = string.IsNullOrEmpty(_protocol) ? _attackType : _protocol,
                            SourceIp = _sourceIp,
                            SourceMac = _sourceMac,
                            TargetIp = _targetIp,
                            TargetMac = _targetMac,
                            TargetPort = _targetPort,
                            TargetRateMbps = (float)(_targetBytesPerSecond * 8.0 / 1_000_000),
                            PacketsSent = _packetsSent,
                            DurationSeconds = (int)duration.TotalSeconds,
                            StartTime = _attackStartTime,
                            StopTime = stopTime,
                            LogContent = _currentLogContent,
                            CreatedAt = DateTime.Now,
                            IsSynced = false,
                            Synced = false
                        };

                        await _databaseService.SaveAttackLogAsync(logEntry);
                    }
                    catch (Exception ex)
                    {
                        // Log error but don't block UI
                        System.Diagnostics.Debug.WriteLine($"Failed to save attack log to database: {ex.Message}");
                    }
                });
            }
        }

        public void IncrementPacketCount()
        {
            _packetsSent++;
        }

        public void LogPing(string targetIp, bool success, int? rtt = null)
        {
            if (success)
            {
                var rttText = rtt.HasValue ? $" (RTT: {rtt}ms)" : "";
                LogSuccess($"Ping to {targetIp} successful{rttText}");
            }
            else
            {
                LogWarning($"Ping to {targetIp} failed - Target may be blocking ICMP or offline");
            }
        }

        public void LogMacResolution(string ip, string mac, bool isGateway = false)
        {
            var target = isGateway ? "Gateway" : "Target";
            LogSuccess($"{target} MAC resolved for {ip}: {mac}");
        }

        public void LogAttackTypeChange(string newType)
        {
            Log($"Attack type changed to: {newType}");
        }

        public void LogInfo(string message)
        {
            Log($"ℹ️  {message}", LogLevel.Info);
        }

        public void LogError(string message)
        {
            Log($"❌ Error: {message}", LogLevel.Error);
        }

        public void LogWarning(string message)
        {
            Log($"⚠️  Warning: {message}", LogLevel.Warning);
        }

        public void LogDebug(string message)
        {
            Log($"🔍 Debug: {message}", LogLevel.Debug);
        }

        public void LogSuccess(string message)
        {
            Log($"✅ {message}", LogLevel.Info);
        }

        public void LogNote(string note)
        {
            try
            {
                _logArea.Dispatcher.BeginInvoke(new Action(() =>
                {
                    _logArea.AppendText(note);
                    
                    // Scroll to end - find ScrollViewer parent if TextBox is inside one
                    var scrollViewer = FindVisualParent<ScrollViewer>(_logArea);
                    if (scrollViewer != null)
                    {
                        scrollViewer.ScrollToEnd();
                    }
                    else
                    {
                        // Fallback to TextBox scroll if no ScrollViewer found
                        _logArea.ScrollToEnd();
                    }
                }), System.Windows.Threading.DispatcherPriority.Loaded);
            }
            catch (Exception ex)
            {
                LogError($"Failed to log note: {ex.Message}");
            }
        }

        private enum LogLevel
        {
            Info,
            Warning,
            Error,
            Debug,
            Success
        }

        private void Log(string message, LogLevel level = LogLevel.Info, bool isEvent = false)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            string logMessage;
            
            if (isEvent)
            {
                logMessage = message;
            }
            else
            {
                // Format based on log level
                logMessage = $"[{timestamp}] {message}";
            }
            
            _logArea.Dispatcher.BeginInvoke(new Action(() =>
            {
                _logArea.AppendText($"{logMessage}{Environment.NewLine}");
                
                // Scroll to end - find ScrollViewer parent if TextBox is inside one
                var scrollViewer = FindVisualParent<ScrollViewer>(_logArea);
                if (scrollViewer != null)
                {
                    scrollViewer.ScrollToEnd();
                }
                else
                {
                    // Fallback to TextBox scroll if no ScrollViewer found
                    _logArea.ScrollToEnd();
                }
            }), System.Windows.Threading.DispatcherPriority.Loaded);
        }
        
        private static T? FindVisualParent<T>(DependencyObject child) where T : DependencyObject
        {
            var parentObject = VisualTreeHelper.GetParent(child);
            if (parentObject == null) return null;
            
            if (parentObject is T parent)
                return parent;
            else
                return FindVisualParent<T>(parentObject);
        }
    }
} 
