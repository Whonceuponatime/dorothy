using System;

namespace Dorothy.Models
{
    /// <summary>
    /// Modbus presence-on-host result. Survey-tier identification only
    /// confirms whether TCP/502 is open; protocol-specific identification
    /// (FC 43 / MEI 14 Read Device ID) is intentionally out of scope per
    /// the simplified Round 1 direction.
    /// </summary>
    public record ModbusInfo
    {
        public bool PortOpen { get; init; }
        public DateTime ProbedAt { get; init; }
    }
}
