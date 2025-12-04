using System;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace Dorothy.Models.Database
{
    [Table("ports")]
    public class PortEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("host_id")]
        public long HostId { get; set; }

        [Column("port")]
        public int Port { get; set; }

        [Column("protocol")]
        public string Protocol { get; set; } = string.Empty;

        [Column("service")]
        public string? Service { get; set; }

        [Column("banner")]
        public string? Banner { get; set; }

        [Column("severity")]
        public string Severity { get; set; } = "INFO"; // Automatically calculated by database trigger, but we can set default

        [Column("scan_time")]
        public DateTime ScanTime { get; set; }

        [Column("synced")]
        public bool Synced { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }

        [Column("project_name")]
        public string? ProjectName { get; set; }

        [Column("hardware_id")]
        public string? HardwareId { get; set; }

        [Column("machine_name")]
        public string? MachineName { get; set; }

        [Column("username")]
        public string? Username { get; set; }

        [Column("user_id")]
        public Guid? UserId { get; set; }

        // Local SQLite only field (not in Supabase schema)
        [JsonIgnore]
        [IgnoreDataMember]
        public DateTime? SyncedAt { get; set; }
        
        // Local SQLite only - for compatibility with existing code
        [JsonIgnore]
        [IgnoreDataMember]
        public string HostIp { get; set; } = string.Empty;
        
        // Backward compatibility - maps to HostId
        [JsonIgnore]
        [IgnoreDataMember]
        public long AssetId 
        { 
            get => HostId; 
            set => HostId = value; 
        }
    }
}



