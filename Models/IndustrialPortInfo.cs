namespace Dorothy.Models
{
    /// <summary>
    /// One open industrial-protocol port observed on a host during Survey.
    /// Populated by the Survey-tier port-open sweep — TCP connect-and-close
    /// (or UDP send-and-listen for BACnet). No protocol-level interrogation.
    ///
    /// ProtocolName is the canonical name for the well-known port:
    ///   502 → "Modbus TCP", 102 → "S7Comm", 4840 → "OPC UA", etc.
    /// </summary>
    public record IndustrialPortInfo(int Port, string ProtocolName);
}
