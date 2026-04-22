using System;

namespace Dorothy.Models
{
    public class ReachabilityRun
    {
        public long Id { get; set; }
        public DateTime StartedAt { get; set; }
        public DateTime? CompletedAt { get; set; }
        public string? Label { get; set; }
        public string? SourceIp { get; set; }
        public string? SourceNic { get; set; }
        public string? TargetRaw { get; set; }
        public string? ResultsJson { get; set; }

        public int HostsTested { get; set; }
        public int HostsReachable { get; set; }
        public int HostsPartial { get; set; }
        public int HostsUnreachable { get; set; }
        public int HostsNoRoute { get; set; }
    }
}
