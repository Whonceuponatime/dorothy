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
        private string? _destinationIpForLogging = null;
        private long? _currentLogId = null;

        private readonly string? _hardwareId;
        private readonly string? _machineName;
        private readonly string? _username;
        private readonly Guid? _userId;
        private Action<LogEntry>? _logEntryCallback;

        public PacketFrameSnapshot? CurrentFrameSnapshot { get; set; }

        public AttackLogger(TextBox logArea, DatabaseService? databaseService = null,
                          string? hardwareId = null, string? machineName = null,
                          string? username = null, Guid? userId = null)
        {
            _logArea = logArea;
            _databaseService = databaseService;
            _hardwareId = hardwareId;
            _machineName = machineName ?? Environment.MachineName;
            _username = username ?? Environment.UserName;
            _userId = userId;
        }

        public void SetLogEntryCallback(Action<LogEntry> callback)
        {
            _logEntryCallback = callback;
        }

        public void StartAttack(AttackType attackType, string sourceIp, byte[] sourceMac,
                          string targetIp, byte[] targetMac, long bytesPerSecond, int targetPort = 0)
        {
            _attackStartTime = DateTime.Now;
            _attackType = attackType.ToString();
            _protocol = attackType.ToString();
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetPort = targetPort;
            _targetBytesPerSecond = bytesPerSecond;
            _packetsSent = 0;

            var targetPortStr = targetPort > 0 ? $":{targetPort}" : "";
            var message = "════════════════════════════════════════════════════════\n" +
                         $"✅ Status: Attack Started\n" +
                         $"📡 Protocol: {attackType}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔗 Source MAC: {_sourceMac}\n" +
                         $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                         $"🔗 Target MAC: {_targetMac}\n" +
                         $"⚡ Target Rate: {RateConverter.Format(_targetBytesPerSecond)}\n" +
                         $"🔥 Attack Type: {_attackType}\n" +
                         $"⏰ Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "════════════════════════════════════════════════════════";
            Log(message, LogLevel.Info, true);
        }

        public void StartNmea0183Attack(bool isMulticast, string sourceIp, byte[] sourceMac,
                          string targetIp, byte[] targetMac, long bytesPerSecond, int targetPort = 0, string? destinationIpForLogging = null)
        {
            _attackStartTime = DateTime.Now;
            _attackType = isMulticast ? "Navigation Data Flood (NMEA 0183 UDP Multicast)" : "Navigation Data Flood (NMEA 0183 UDP Unicast)";
            _protocol = "UDP (Navigation / NMEA 0183 " + (isMulticast ? "Multicast" : "Unicast") + ")";
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetPort = targetPort;
            _targetBytesPerSecond = bytesPerSecond;
            _packetsSent = 0;
            _destinationIpForLogging = destinationIpForLogging;

            var targetPortStr = targetPort > 0 ? $":{targetPort}" : "";

            string targetSection;
            if (isMulticast)
            {

                if (!string.IsNullOrEmpty(destinationIpForLogging) && destinationIpForLogging != targetIp)
                {

                    targetSection = $"📍 Destination IP: {destinationIpForLogging}\n" +
                                   $"🌐 Multicast IP: {_targetIp}{targetPortStr}\n" +
                                   $"🔗 Multicast MAC: {_targetMac}\n";
                }
                else
                {

                    targetSection = $"🌐 Multicast IP: {_targetIp}{targetPortStr}\n" +
                                   $"🔗 Multicast MAC: {_targetMac}\n";
                }
            }
            else
            {
                targetSection = $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                               $"🔗 Target MAC: {_targetMac}\n";
            }

            var message = "════════════════════════════════════════════════════════\n" +
                         $"✅ Status: Attack Started\n" +
                         $"📡 Protocol: {_protocol}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔗 Source MAC: {_sourceMac}\n" +
                         targetSection +
                         $"⚡ Target Rate: {RateConverter.Format(_targetBytesPerSecond)}\n" +
                         $"🔥 Attack Type: {_attackType}\n" +
                         $"⏰ Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "════════════════════════════════════════════════════════";
            Log(message, LogLevel.Info, true);
        }

        public void StartModbusTcpAttack(string sourceIp, byte[] sourceMac,
                          string targetIp, byte[] targetMac, long bytesPerSecond, int targetPort = 502)
        {
            _attackStartTime = DateTime.Now;
            _attackType = "ICS/OT Flood (Modbus/TCP Read Requests)";
            _protocol = "TCP (Modbus/TCP)";
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetPort = targetPort;
            _targetBytesPerSecond = bytesPerSecond;
            _packetsSent = 0;

            var targetPortStr = targetPort > 0 ? $":{targetPort}" : "";
            var message = "════════════════════════════════════════════════════════\n" +
                         $"✅ Status: Attack Started\n" +
                         $"📡 Protocol: {_protocol}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔗 Source MAC: {_sourceMac}\n" +
                         $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                         $"🔗 Target MAC: {_targetMac}\n" +
                         $"⚡ Target Rate: {RateConverter.Format(_targetBytesPerSecond)}\n" +
                         $"🔥 Attack Type: {_attackType}\n" +
                         $"📋 Function Code: 0x03 (Read Holding Registers - Non-destructive)\n" +
                         $"🔧 Unit ID: 1 (default)\n" +
                         $"⚠️  Note: Read-only requests (non-destructive)\n" +
                         $"⏰ Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "════════════════════════════════════════════════════════";
            Log(message, LogLevel.Info, true);
        }

        public void StartEthernetAttack(EthernetFlood.EthernetPacketType packetType, string sourceIp, byte[] sourceMac,
                          string targetIp, byte[] targetMac, long bytesPerSecond, int targetPort = 0)
        {
            _attackStartTime = DateTime.Now;
            _attackType = $"Ethernet {packetType}";
            _sourceIp = sourceIp;
            _sourceMac = BitConverter.ToString(sourceMac).Replace("-", ":");
            _targetIp = targetIp;
            _targetMac = BitConverter.ToString(targetMac).Replace("-", ":");
            _targetPort = targetPort;
            _targetBytesPerSecond = bytesPerSecond;
            _packetsSent = 0;
            _protocol = $"Ethernet {packetType}";

            var isMulticast = packetType == EthernetFlood.EthernetPacketType.Multicast;
            var targetPortStr = targetPort > 0 ? $":{targetPort}" : "";

            string targetSection;
            if (isMulticast)
            {

                string ipLabel = "Multicast IP";
                string ipValue;

                if (string.IsNullOrWhiteSpace(_targetIp))
                {

                    ipValue = "N/A (Layer 2 only)";
                }
                else if (System.Net.IPAddress.TryParse(_targetIp, out var parsedIp))
                {
                    if (IsMulticastAddress(parsedIp))
                    {

                        ipValue = _targetIp;
                    }
                    else
                    {

                        ipValue = "N/A (Unicast IP used for interface selection)";
                    }
                }
                else
                {

                    ipValue = "N/A (Layer 2 only)";
                }

                targetSection = $"🌐 {ipLabel}: {ipValue}\n" +
                               $"🔗 Multicast MAC: {_targetMac}\n";
            }
            else
            {

                targetSection = $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                               $"🔗 Target MAC: {_targetMac}\n";
            }

            var message = "════════════════════════════════════════════════════════\n" +
                         $"✅ Status: Attack Started\n" +
                         $"📡 Protocol: Ethernet {packetType}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔗 Source MAC: {_sourceMac}\n" +
                         targetSection +
                         $"⚡ Target Rate: {RateConverter.Format(_targetBytesPerSecond)}\n" +
                         $"🔥 Attack Type: {_attackType}\n" +
                         $"⏰ Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "════════════════════════════════════════════════════════";
            Log(message, LogLevel.Info, true);
        }

        public void StopAttack(long packetsSent = 0)
        {
            var stopTime = DateTime.Now;
            var duration = stopTime - _attackStartTime;
            _packetsSent = packetsSent;

            var isMulticast = _attackType.Contains("Multicast", StringComparison.OrdinalIgnoreCase);
            var targetPortStr = _targetPort > 0 ? $":{_targetPort}" : "";
            var durationStr = duration.TotalHours >= 1
                ? $"{(int)duration.TotalHours:D2}:{duration.Minutes:D2}:{duration.Seconds:D2}"
                : $"{duration.Minutes:D2}:{duration.Seconds:D2}";

            string targetSection;
            if (isMulticast)
            {

                string ipLabel = "Multicast IP";
                string ipValue;

                if (string.IsNullOrWhiteSpace(_targetIp))
                {

                    ipValue = "N/A (Layer 2 only)";
                }
                else if (System.Net.IPAddress.TryParse(_targetIp, out var parsedIp))
                {
                    if (IsMulticastAddress(parsedIp))
                    {

                        ipValue = _targetIp;
                    }
                    else
                    {

                        ipValue = "N/A (Unicast IP used for interface selection)";
                    }
                }
                else
                {

                    ipValue = "N/A (Layer 2 only)";
                }

                targetSection = $"🌐 {ipLabel}: {ipValue}\n" +
                               $"🔗 Multicast MAC: {_targetMac}\n";
            }
            else
            {

                targetSection = $"🎯 Target Host: {_targetIp}{targetPortStr}\n" +
                               $"🔗 Target MAC: {_targetMac}\n";
            }

            bool isNmeaAttackForProtocol = _protocol != null && _protocol.Contains("NMEA 0183");
            string protocolLabel = isNmeaAttackForProtocol ? _protocol : _attackType;

            var message = "════════════════════════════════════════════════════════\n" +
                         $"ℹ️  Status: Attack Stopped\n" +
                         $"📡 Protocol: {protocolLabel}\n" +
                         $"📍 Source Host: {_sourceIp}\n" +
                         $"🔗 Source MAC: {_sourceMac}\n" +
                         targetSection +
                         $"⚡ Target Rate: {RateConverter.Format(_targetBytesPerSecond)}\n" +
                         $"📊 Packets Sent: {_packetsSent:N0}\n" +
                         $"⏱️  Duration: {durationStr}\n" +
                         $"⏰ Start Time: {_attackStartTime:yyyy-MM-dd HH:mm:ss}\n" +
                         $"⏰ Stop Time: {stopTime:yyyy-MM-dd HH:mm:ss}\n" +
                         "════════════════════════════════════════════════════════";
            Log(message, LogLevel.Info, true);

            if (_databaseService != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {

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
                            TargetRateMbps = (float)(_targetBytesPerSecond * 8.0 / 1_000_000.0),
                            PacketsSent = _packetsSent,
                            DurationSeconds = (int)duration.TotalSeconds,
                            StartTime = _attackStartTime,
                            StopTime = stopTime,
                            LogContent = _currentLogContent,
                            CreatedAt = DateTime.Now,
                            IsSynced = false,
                            Synced = false,
                            HardwareId = _hardwareId,
                            MachineName = _machineName,
                            Username = _username,
                            UserId = _userId
                        };

                        await _databaseService.SaveAttackLogAsync(logEntry);
                    }
                    catch (Exception ex)
                    {

                        LogError($"Failed to save attack log to database: {ex.Message}");
                        System.Diagnostics.Debug.WriteLine($"Failed to save attack log to database: {ex.Message}\n{ex.StackTrace}");
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
            Log($"✅ {message}", LogLevel.Success);
        }

        public void LogNote(string note)
        {
            try
            {
                _logArea.Dispatcher.BeginInvoke(new Action(() =>
                {
                    _logArea.AppendText(note);

                    var scrollViewer = FindVisualParent<ScrollViewer>(_logArea);
                    if (scrollViewer != null)
                    {
                        scrollViewer.ScrollToEnd();
                    }
                    else
                    {
                        _logArea.ScrollToEnd();
                    }
                }), System.Windows.Threading.DispatcherPriority.Loaded);

                _logEntryCallback?.Invoke(new LogEntry
                {
                    Timestamp = DateTime.Now.ToString("HH:mm:ss"),
                    Icon = "ⓘ",
                    Message = note.TrimEnd('\r', '\n'),
                    Type = LogEntryType.System
                });
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
                logMessage = $"[{timestamp}] {message}";
            }

            _logArea.Dispatcher.BeginInvoke(new Action(() =>
            {
                _logArea.AppendText($"{logMessage}{Environment.NewLine}");

                var scrollViewer = FindVisualParent<ScrollViewer>(_logArea);
                if (scrollViewer != null)
                {
                    scrollViewer.ScrollToEnd();
                }
                else
                {
                    _logArea.ScrollToEnd();
                }
            }), System.Windows.Threading.DispatcherPriority.Loaded);

            EmitLogEntry(timestamp, message, level, isEvent);
        }

        private void EmitLogEntry(string timestamp, string message, LogLevel level, bool isEvent)
        {
            if (_logEntryCallback == null) return;

            var entry = new LogEntry { Timestamp = timestamp };

            if (isEvent)
            {
                entry.Type = LogEntryType.System;
                entry.Icon = "ⓘ";
                entry.Message = message;
            }
            else
            {
                switch (level)
                {
                    case LogLevel.Success:
                        entry.Type = LogEntryType.Ok;
                        entry.Icon = "✓";
                        break;
                    case LogLevel.Error:
                        entry.Type = LogEntryType.Error;
                        entry.Icon = "✕";
                        break;
                    case LogLevel.Warning:
                        entry.Type = LogEntryType.Error;
                        entry.Icon = "✕";
                        break;
                    default:
                        entry.Type = LogEntryType.System;
                        entry.Icon = "ⓘ";
                        break;
                }
                entry.Message = message;
            }

            _logEntryCallback(entry);
        }

        public void LogPacket(string message, string badgeText, string badgeColorKey,
                              PacketFrameSnapshot? frame = null)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            var logMessage = $"[{timestamp}] {message}";

            _logArea.Dispatcher.BeginInvoke(new Action(() =>
            {
                _logArea.AppendText($"{logMessage}{Environment.NewLine}");
                var scrollViewer = FindVisualParent<ScrollViewer>(_logArea);
                if (scrollViewer != null)
                    scrollViewer.ScrollToEnd();
                else
                    _logArea.ScrollToEnd();
            }), System.Windows.Threading.DispatcherPriority.Loaded);

            if (_logEntryCallback != null)
            {
                var entry = new LogEntry
                {
                    Timestamp = timestamp,
                    Icon = "◈",
                    Message = message,
                    Type = LogEntryType.Packet,
                    BadgeText = badgeText,
                    BadgeColorKey = badgeColorKey,
                    Frame = frame
                };
                _logEntryCallback(entry);
            }
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

        private static bool IsMulticastAddress(System.Net.IPAddress address)
        {
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {

                var bytes = address.GetAddressBytes();

                return bytes.Length >= 1 && bytes[0] >= 224 && bytes[0] <= 239;
            }
            else if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {

                var bytes = address.GetAddressBytes();
                return bytes.Length >= 1 && bytes[0] == 0xFF;
            }

            return false;
        }
    }
}
