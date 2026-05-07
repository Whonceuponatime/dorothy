using System;

namespace Dorothy.Models.Database
{
    public class AssetEntry
    {
        public long Id { get; set; }
        public int EngagementId { get; set; }
        public string HostIp { get; set; } = string.Empty;
        public string? HostName { get; set; }
        public string? MacAddress { get; set; }
        public string? Vendor { get; set; }
        public bool IsOnline { get; set; }
        public int? PingTime { get; set; }
        public DateTime ScanTime { get; set; }
        public DateTime CreatedAt { get; set; }
        public string? HardwareId { get; set; }
        public string? MachineName { get; set; }
        public string? Username { get; set; }
        public Guid? UserId { get; set; }
        public string? Ports { get; set; }

        // Round 1 industrial-identity persistence (Q1 resolution: flat columns).
        public string? IndustrialVendor { get; set; }
        public string? IndustrialCategory { get; set; }
        public string? IndustrialProtocols { get; set; }
    }
}
