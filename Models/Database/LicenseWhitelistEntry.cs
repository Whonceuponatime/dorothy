using System;

namespace Dorothy.Models.Database
{
    public class LicenseWhitelistEntry
    {
        public Guid Id { get; set; }
        public Guid? UserId { get; set; }
        public string? UserEmail { get; set; }
        public string HardwareId { get; set; } = string.Empty;
        public string? MachineName { get; set; }
        public string? DeviceName { get; set; }
        public bool IsActive { get; set; } = true;
        public Guid? ApprovedBy { get; set; }
        public DateTime? ApprovedAt { get; set; }
        public DateTime? LastSeenAt { get; set; }
        public string? LastSeenIp { get; set; }
        public string? Notes { get; set; }
    }
}
