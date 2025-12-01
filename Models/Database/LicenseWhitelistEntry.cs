using System;
using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace Dorothy.Models.Database
{
    /// <summary>
    /// Represents a license whitelist entry in Supabase.
    /// Links hardware IDs to authenticated users.
    /// </summary>
    [Table("whitelisted_hardware")]
    public class LicenseWhitelistEntry : BaseModel
    {
        [PrimaryKey("id")]
        public Guid Id { get; set; }

        [Column("user_id")]
        public Guid? UserId { get; set; }

        [Column("user_email")]
        public string? UserEmail { get; set; }

        [Column("hardware_id")]
        public string HardwareId { get; set; } = string.Empty;

        [Column("machine_name")]
        public string? MachineName { get; set; }

        [Column("device_name")]
        public string? DeviceName { get; set; }

        [Column("is_active")]
        public bool IsActive { get; set; } = true;

        [Column("approved_by")]
        public Guid? ApprovedBy { get; set; }

        [Column("approved_at")]
        public DateTime? ApprovedAt { get; set; }

        [Column("last_seen_at")]
        public DateTime? LastSeenAt { get; set; }

        [Column("last_seen_ip")]
        public string? LastSeenIp { get; set; }

        [Column("notes")]
        public string? Notes { get; set; }
    }
}

