using System;
using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace Dorothy.Models.Database
{
    [Table("attack_logs")]
    public class AttackLogEntry : BaseModel, ICloneable
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("project_name")]
        public string? ProjectName { get; set; }

        [Column("attack_type")]
        public string AttackType { get; set; } = string.Empty;

        [Column("protocol")]
        public string Protocol { get; set; } = string.Empty;

        [Column("source_ip")]
        public string SourceIp { get; set; } = string.Empty;

        [Column("source_mac")]
        public string? SourceMac { get; set; }

        [Column("target_ip")]
        public string TargetIp { get; set; } = string.Empty;

        [Column("target_mac")]
        public string? TargetMac { get; set; }

        [Column("target_port")]
        public int TargetPort { get; set; }

        [Column("target_rate_mbps")]
        public double TargetRateMbps { get; set; }

        [Column("packets_sent")]
        public long PacketsSent { get; set; }

        [Column("duration_seconds")]
        public int DurationSeconds { get; set; }

        [Column("start_time")]
        public DateTime StartTime { get; set; }

        [Column("stop_time")]
        public DateTime StopTime { get; set; }

        [Column("synced")]
        public bool Synced { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }

        // Local SQLite only fields (not in Supabase)
        public string? Note { get; set; }
        public string LogContent { get; set; } = string.Empty;
        public DateTime? SyncedAt { get; set; }
        public bool IsSynced { get; set; } // Maps to Synced in Supabase

        public object Clone()
        {
            return new AttackLogEntry
            {
                ProjectName = ProjectName,
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
                Synced = Synced,
                CreatedAt = CreatedAt,
                Note = Note,
                LogContent = LogContent,
                IsSynced = IsSynced,
                SyncedAt = SyncedAt
            };
        }
    }
}

