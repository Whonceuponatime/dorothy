using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// Performs a TLS handshake against an open port and captures the server
    /// certificate plus negotiated TLS version + cipher. Used by Full and
    /// Deep probe tiers on ports identified as TLS-bearing.
    /// </summary>
    public class TlsInspectorService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int ConnectTimeoutMs = 5000;
        private const int HandshakeTimeoutMs = 5000;

        private static readonly HashSet<int> TlsPortsHint = new()
        {
            443, 8443, 465, 993, 995, 636, 5061, 989, 990, 6443
        };

        public static bool IsLikelyTlsPort(int port) => TlsPortsHint.Contains(port);

        public async Task<TlsInfo?> InspectTlsAsync(string host, int port, CancellationToken ct)
        {
            X509Certificate2? capturedCert = null;

            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(ConnectTimeoutMs);
                try
                {
                    await tcp.ConnectAsync(host, port, connectCts.Token).ConfigureAwait(false);
                }
                catch { return null; }

                using var ssl = new SslStream(
                    tcp.GetStream(),
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: (_, cert, _, _) =>
                    {
                        // Accept whatever the server sent — we want to inspect
                        // even invalid / self-signed / expired certs, not gate on them.
                        if (cert is X509Certificate2 c2) capturedCert = c2;
                        else if (cert != null) capturedCert = new X509Certificate2(cert);
                        return true;
                    });

                using var hsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                hsCts.CancelAfter(HandshakeTimeoutMs);

                try
                {
                    await ssl.AuthenticateAsClientAsync(
                        new SslClientAuthenticationOptions
                        {
                            TargetHost = host,
                            EnabledSslProtocols = System.Security.Authentication.SslProtocols.None
                        },
                        hsCts.Token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Logger.Debug(ex, $"TLS handshake to {host}:{port} failed");
                    if (capturedCert == null) return null;
                    // We may still have the cert from the validation callback even
                    // when the handshake itself failed (e.g. cipher negotiation issue).
                }

                string? subjectCn = ExtractCommonName(capturedCert?.Subject);
                string? issuerCn  = ExtractCommonName(capturedCert?.Issuer);
                string[] sans     = ExtractSubjectAlternativeNames(capturedCert);
                bool selfSigned   = capturedCert != null
                    && string.Equals(capturedCert.Subject, capturedCert.Issuer, StringComparison.OrdinalIgnoreCase);

                string? tlsVersion = ssl.SslProtocol switch
                {
                    System.Security.Authentication.SslProtocols.Tls => "TLS 1.0",
                    System.Security.Authentication.SslProtocols.Tls11 => "TLS 1.1",
                    System.Security.Authentication.SslProtocols.Tls12 => "TLS 1.2",
                    System.Security.Authentication.SslProtocols.Tls13 => "TLS 1.3",
                    _ => null
                };

                string? cipherSuite = null;
                try { cipherSuite = ssl.NegotiatedCipherSuite.ToString(); }
                catch { /* OS may not expose */ }

                return new TlsInfo(
                    SubjectCN: subjectCn,
                    IssuerCN: issuerCn,
                    NotBefore: capturedCert?.NotBefore ?? DateTime.MinValue,
                    NotAfter:  capturedCert?.NotAfter  ?? DateTime.MinValue,
                    SubjectAlternativeNames: sans,
                    TlsVersion: tlsVersion,
                    CipherSuite: cipherSuite,
                    SelfSigned: selfSigned);
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"TLS inspect {host}:{port} failed");
                return null;
            }
        }

        private static string? ExtractCommonName(string? distinguishedName)
        {
            if (string.IsNullOrEmpty(distinguishedName)) return null;
            // DistinguishedName format: "CN=example.com, O=..., L=..."
            const string cnTag = "CN=";
            int idx = distinguishedName.IndexOf(cnTag, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;
            int start = idx + cnTag.Length;
            int end = distinguishedName.IndexOf(',', start);
            if (end < 0) end = distinguishedName.Length;
            return distinguishedName.Substring(start, end - start).Trim();
        }

        private static string[] ExtractSubjectAlternativeNames(X509Certificate2? cert)
        {
            if (cert == null) return Array.Empty<string>();
            try
            {
                foreach (var ext in cert.Extensions)
                {
                    if (ext.Oid?.Value != "2.5.29.17") continue; // Subject Alternative Name
                    var asnData = new System.Security.Cryptography.AsnEncodedData(ext.Oid, ext.RawData);
                    var raw = asnData.Format(true);
                    if (string.IsNullOrEmpty(raw)) return Array.Empty<string>();

                    var lines = raw.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                    var sans = new List<string>();
                    foreach (var line in lines)
                    {
                        // Lines look like "DNS Name=example.com" or "IP Address=10.0.0.1"
                        var eq = line.IndexOf('=');
                        if (eq < 0) continue;
                        var value = line.Substring(eq + 1).Trim();
                        if (!string.IsNullOrEmpty(value)) sans.Add(value);
                    }
                    return sans.ToArray();
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "SAN extraction failed");
            }
            return Array.Empty<string>();
        }
    }
}
