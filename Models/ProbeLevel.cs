namespace Dorothy.Models
{
    /// <summary>
    /// Two-tier probe selection exposed via the NI canvas right-click menu
    /// and the detail-panel buttons.
    ///
    /// Simple   — fast analyst pass: ICMP + top-100 TCP + DNS/NetBIOS/SNMP +
    ///            banner grab + OS fingerprint. ~15s, 30s hard cap.
    /// Advanced — Simple plus top-1000 TCP, UDP top-20, TLS cert extraction,
    ///            HTTP path discovery, and SMB enumeration. ~3min, 5min hard cap.
    /// </summary>
    public enum ProbeLevel
    {
        Simple   = 0,
        Advanced = 1
    }
}
