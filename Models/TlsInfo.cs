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
        bool SelfSigned);
}
