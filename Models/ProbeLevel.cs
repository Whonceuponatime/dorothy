namespace Dorothy.Models
{
    /// <summary>
    /// Three-tier probe selection exposed via the NI toolbar mode toggle,
    /// the canvas right-click menu, and the detail-panel buttons.
    ///
    /// Survey   — vendor-blessed identification only. Zero unsolicited TCP
    ///            scans. SNMP sysObjectID GET + protocol-specific
    ///            identification queries (Modbus FC 43, OPC UA GetEndpoints,
    ///            etc.) gated by Stage-2 SNMP hint or open-port confirmation.
    ///            Safe for production ICS networks. Default tier for fresh
    ///            installs.
    /// Simple   — fast analyst pass: ICMP + top-100 TCP + DNS/NetBIOS/SNMP +
    ///            banner grab + OS fingerprint. ~15s, 30s hard cap.
    ///            CAUTION on industrial networks — port scan can crash some PLCs.
    /// Advanced — Simple plus top-1000 TCP, UDP top-20, TLS cert extraction,
    ///            HTTP path discovery, and SMB enumeration. ~3min, 5min hard cap.
    ///            PENTEST ONLY — explicit warning prompts on industrial hosts.
    /// </summary>
    public enum ProbeLevel
    {
        Survey   = 0,
        Simple   = 1,
        Advanced = 2
    }
}
