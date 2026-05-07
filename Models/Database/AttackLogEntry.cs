using System;

namespace Dorothy.Models.Database
{
    public class AttackLogEntry : ICloneable
    {
        public long Id { get; set; }
        public int EngagementId { get; set; }
        public string AttackType { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public string? SourceMac { get; set; }
        public string TargetIp { get; set; } = string.Empty;
        public string? TargetMac { get; set; }
        public int TargetPort { get; set; }
        public double TargetRateMbps { get; set; }
        public long PacketsSent { get; set; }
        public int DurationSeconds { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime StopTime { get; set; }
        public DateTime CreatedAt { get; set; }
        public string? HardwareId { get; set; }
        public string? MachineName { get; set; }
        public string? Username { get; set; }
        public Guid? UserId { get; set; }
        public string? Note { get; set; }
        public string LogContent { get; set; } = string.Empty;

        public object Clone()
        {
            return new AttackLogEntry
            {
                EngagementId = EngagementId,
                AttackType = AttackType,
                Protocol = Protocol,
                SourceIp = SourceIp,
                SourceMac = SourceMac,
                TargetIp = TargetIp,
                TargetMac = TargetMac,
                TargetPort = TargetPort,
                TargetRateMbps = TargetRateMbps,
                PacketsSent = PacketsSent,
                DurationSeconds = DurationSeconds,
                StartTime = StartTime,
                StopTime = StopTime,
                CreatedAt = CreatedAt,
                HardwareId = HardwareId,
                MachineName = MachineName,
                Username = Username,
                UserId = UserId,
                Note = Note,
                LogContent = LogContent
            };
        }
    }
}
