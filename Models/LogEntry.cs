using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Dorothy.Models
{
    public enum LogEntryType
    {
        System,
        Ok,
        Error,
        Packet
    }

    public class LogEntry : INotifyPropertyChanged
    {
        private bool _isExpanded;

        public string Timestamp { get; set; } = string.Empty;
        public string Icon { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public LogEntryType Type { get; set; } = LogEntryType.System;
        public string? BadgeText { get; set; }
        public string? BadgeColorKey { get; set; }
        public PacketFrameSnapshot? Frame { get; set; }

        public bool IsExpanded
        {
            get => _isExpanded;
            set { if (_isExpanded != value) { _isExpanded = value; OnPropertyChanged(); } }
        }

        public string BadgeBg => BadgeColorKey switch
        {
            "TCP"      => "#1e3a5f",
            "UDP"      => "#1a2e1a",
            "ICMP"     => "#2e1a3a",
            "Ethernet" => "#1e2a3a",
            "Modbus"   => "#2e1e0a",
            "NMEA"     => "#0a2e2e",
            _          => "#1e293b"
        };

        public string BadgeFg => BadgeColorKey switch
        {
            "TCP"      => "#60a5fa",
            "UDP"      => "#4ade80",
            "ICMP"     => "#c084fc",
            "Ethernet" => "#94a3b8",
            "Modbus"   => "#fb923c",
            "NMEA"     => "#5eead4",
            _          => "#94a3b8"
        };

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
