using System;

namespace Dorothy.Models
{
    /// <summary>
    /// Server certificate + handshake details captured during a TLS probe.
    /// Populated by TlsInspectorService for ports that complete a TLS
    /// handshake (443, 8443, 465, 993, 995, 636, 5061, etc.).
    /// </summary>
    public record TlsInfo(
        string? SubjectCN,
        string? IssuerCN,
        DateTime NotBefore,
        DateTime NotAfter,
        string[] SubjectAlternativeNames,
        string? TlsVersion,
        string? CipherSuite,
        bool SelfSigned,
        // Expired ⇔ NotAfter is in the past (UTC).
        // ExpiresWithin30Days ⇔ cert is currently valid AND NotAfter is
        // within the next 30 days. The two are mutually exclusive.
        bool Expired,
        bool ExpiresWithin30Days);
}
