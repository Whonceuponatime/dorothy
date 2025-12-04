using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Supabase.Postgrest.Attributes;
using Supabase.Postgrest.Models;

namespace Dorothy.Models.Database
{
    [Table("reachability_tests")]
    public class ReachabilityTestEntry : BaseModel, ICloneable
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("project_name")]
        public string? ProjectName { get; set; }

        [Column("analysis_mode")]
        public string AnalysisMode { get; set; } = string.Empty; // "RemoteNetworkKnown" or "BoundaryOnly"

        [Column("vantage_point_name")]
        public string VantagePointName { get; set; } = string.Empty;

        [Column("source_nic_id")]
        public string SourceNicId { get; set; } = string.Empty;

        [Column("source_ip")]
        public string SourceIp { get; set; } = string.Empty;

        [Column("target_network_name")]
        public string? TargetNetworkName { get; set; }

        [Column("target_cidr")]
        public string? TargetCidr { get; set; }

        [Column("boundary_gateway_ip")]
        public string? BoundaryGatewayIp { get; set; }

        [Column("boundary_vendor")]
        public string? BoundaryVendor { get; set; }

        [Column("external_test_ip")]
        public string? ExternalTestIp { get; set; }

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

        // Local SQLite only fields (not in Supabase)
        [JsonIgnore]
        [IgnoreDataMember]
        public DateTime? SyncedAt { get; set; }

        [JsonIgnore]
        [IgnoreDataMember]
        public bool IsSynced { get; set; } // Local SQLite field - use 'Synced' for Supabase

        public object Clone()
        {
            return new ReachabilityTestEntry
            {
                ProjectName = ProjectName,
                AnalysisMode = AnalysisMode,
                VantagePointName = VantagePointName,
                SourceNicId = SourceNicId,
                SourceIp = SourceIp,
                TargetNetworkName = TargetNetworkName,
                TargetCidr = TargetCidr,
                BoundaryGatewayIp = BoundaryGatewayIp,
                BoundaryVendor = BoundaryVendor,
                ExternalTestIp = ExternalTestIp,
                Synced = Synced,
                CreatedAt = CreatedAt,
                HardwareId = HardwareId,
                MachineName = MachineName,
                Username = Username,
                UserId = UserId,
                IsSynced = IsSynced,
                SyncedAt = SyncedAt
            };
        }
    }

    [Table("reachability_icmp_results")]
    public class ReachabilityIcmpResultEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("test_id")]
        public long TestId { get; set; }

        [Column("target_ip")]
        public string TargetIp { get; set; } = string.Empty;

        [Column("role")]
        public string Role { get; set; } = string.Empty; // "Boundary device", "Gateway candidate", "Known asset", "External test target"

        [Column("reachable")]
        public bool Reachable { get; set; }

        [Column("sent")]
        public int Sent { get; set; }

        [Column("received")]
        public int Received { get; set; }

        [Column("avg_rtt_ms")]
        public long? AvgRttMs { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }
    }

    [Table("reachability_tcp_results")]
    public class ReachabilityTcpResultEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("test_id")]
        public long TestId { get; set; }

        [Column("target_ip")]
        public string TargetIp { get; set; } = string.Empty;

        [Column("port")]
        public int Port { get; set; }

        [Column("state")]
        public string State { get; set; } = string.Empty; // "Open", "Closed", "Filtered"

        [Column("rtt_ms")]
        public long RttMs { get; set; }

        [Column("error_message")]
        public string? ErrorMessage { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }
    }

    [Table("reachability_path_hops")]
    public class ReachabilityPathHopEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("test_id")]
        public long TestId { get; set; }

        [Column("target_ip")]
        public string TargetIp { get; set; } = string.Empty;

        [Column("hop_number")]
        public int HopNumber { get; set; }

        [Column("hop_ip")]
        public string? HopIp { get; set; }

        [Column("rtt_ms")]
        public long? RttMs { get; set; }

        [Column("hostname")]
        public string? Hostname { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }
    }

    [Table("reachability_deeper_scans")]
    public class ReachabilityDeeperScanEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("test_id")]
        public long TestId { get; set; }

        [Column("target_ip")]
        public string TargetIp { get; set; } = string.Empty;

        [Column("port_states")]
        public string PortStates { get; set; } = string.Empty; // JSON: {"22": "Open", "80": "Closed", ...}

        [Column("summary")]
        public string? Summary { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }
    }

    [Table("reachability_snmp_walks")]
    public class ReachabilitySnmpWalkEntry : BaseModel
    {
        [PrimaryKey("id")]
        public long Id { get; set; }

        [Column("test_id")]
        public long TestId { get; set; }

        [Column("target_ip")]
        public string TargetIp { get; set; } = string.Empty;

        [Column("port")]
        public int Port { get; set; }

        [Column("success")]
        public bool Success { get; set; }

        [Column("successful_community")]
        public string? SuccessfulCommunity { get; set; }

        [Column("successful_oids")]
        public string SuccessfulOids { get; set; } = string.Empty; // JSON array of OID strings

        [Column("attempts")]
        public int Attempts { get; set; }

        [Column("duration_ms")]
        public long DurationMs { get; set; }

        [Column("created_at")]
        public DateTime CreatedAt { get; set; }
    }
}

