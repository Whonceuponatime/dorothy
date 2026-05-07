using System;

namespace Dorothy.Models.Database
{
    public class PortEntry
    {
        public long Id { get; set; }
        public int EngagementId { get; set; }
        public long HostId { get; set; }
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string? Service { get; set; }
        public string? Banner { get; set; }
        public string Severity { get; set; } = "INFO";
        public DateTime ScanTime { get; set; }
        public DateTime CreatedAt { get; set; }
        public string? HardwareId { get; set; }
        public string? MachineName { get; set; }
        public string? Username { get; set; }
        public Guid? UserId { get; set; }
        public string HostIp { get; set; } = string.Empty;

        public long AssetId
        {
            get => HostId;
            set => HostId = value;
        }
    }
}
