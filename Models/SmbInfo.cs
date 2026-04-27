namespace Dorothy.Models
{
    /// <summary>
    /// SMB negotiation result from SmbEnumerationService. The minimum-viable
    /// implementation populates SmbVersion + SigningRequired + SigningEnabled
    /// from an SMB1 NEGOTIATE exchange. Native OS / NetBIOS / DNS fields
    /// require a full SESSION_SETUP NTLM exchange and may be null.
    /// </summary>
    public record SmbInfo(
        string? SmbVersion,
        bool SigningRequired,
        bool SigningEnabled,
        string? NativeOs,
        string? NativeLanManager,
        string? NetBiosComputerName,
        string? NetBiosDomain,
        string? DnsComputerName,
        string? DnsDomain);
}
