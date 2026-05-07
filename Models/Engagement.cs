using System;

namespace Dorothy.Models
{
    public enum EngagementStatus
    {
        Active = 0,
        Submitted = 1,
        Archived = 2
    }

    public class Engagement
    {
        public int Id { get; set; }
        public string? RemoteId { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? ClientName { get; set; }
        public string? Scope { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? EndedAt { get; set; }
        public EngagementStatus Status { get; set; } = EngagementStatus.Active;
        public string SurveyorHardwareId { get; set; } = string.Empty;
        public string? SurveyorEmail { get; set; }
        public string? Notes { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? SubmittedAt { get; set; }
    }
}
