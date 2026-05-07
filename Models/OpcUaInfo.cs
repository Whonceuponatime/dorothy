using System;

namespace Dorothy.Models
{
    /// <summary>
    /// OPC UA presence-on-host result. Survey-tier identification only
    /// confirms whether TCP/4840 is open; the OPC UA Hello/OPN/GetEndpoints
    /// binary handshake and security-policy analysis are intentionally
    /// out of scope per the simplified Round 1 direction.
    /// </summary>
    public record OpcUaInfo
    {
        public bool PortOpen { get; init; }
        public DateTime ProbedAt { get; init; }
    }
}
