using System;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace Dorothy.Models.Database
{
    [Table("assets")]
    public class AssetEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("host_ip")]
        public string HostIp { get; set; } = string.Empty;

        [Column("host_name")]
        public string? HostName { get; set; }

        [Column("mac_address")]
        public string? MacAddress { get; set; }

        [Column("vendor")]
        public string? Vendor { get; set; }

        [Column("is_online")]
        public bool IsOnline { get; set; }

        [Column("ping_time")]
        public int? PingTime { get; set; }

        [Column("scan_time")]
        public DateTime ScanTime { get; set; }

        [Column("project_name")]
        public string? ProjectName { get; set; }

        [Column("synced")]
        public bool Synced { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }

        [Column("hardware_id")]
        public string? HardwareId { get; set; }

        [Column("machine_name")]
        public string? MachineName { get; set; }

        [Column("username")]
        public string? Username { get; set; }

        [Column("user_id")]
        public Guid? UserId { get; set; }

        [Column("ports")]
        public string? Ports { get; set; }

        // Local SQLite only field (not in Supabase schema)
        // Using both JsonIgnore and IgnoreDataMember to ensure exclusion
        [JsonIgnore]
        [IgnoreDataMember]
        public DateTime? SyncedAt { get; set; }
    }
}
