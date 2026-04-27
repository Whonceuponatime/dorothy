using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// Minimum-viable SMB enumeration. Connects to TCP/445 and sends an
    /// SMB1 NEGOTIATE PROTOCOL request advertising SMB1 + SMB2 dialects.
    /// Parses the response's DialectIndex to determine the highest dialect
    /// the server supports, plus signing flags from the SecurityMode byte.
    ///
    /// Native OS / NetBIOS / DNS fields require a full SESSION_SETUP NTLM
    /// exchange (LDAP-style ASN.1 inside SPNEGO) which is intentionally
    /// deferred — those fields are returned as null.
    /// </summary>
    public class SmbEnumerationService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int ConnectTimeoutMs = 5000;
        private const int IoTimeoutMs = 5000;
        private const int SmbPort = 445;

        // Dialect strings advertised in the NEGOTIATE request.
        // Order matters — the response's DialectIndex points into this list.
        private static readonly string[] Dialects =
        {
            "PC NETWORK PROGRAM 1.0",
            "LANMAN1.0",
            "Windows for Workgroups 3.1a",
            "LM1.2X002",
            "LANMAN2.1",
            "NT LM 0.12",
            "SMB 2.002",
            "SMB 2.???"
        };

        public async Task<SmbInfo?> EnumerateAsync(string host, CancellationToken ct)
        {
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(ConnectTimeoutMs);
                try
                {
                    await tcp.ConnectAsync(host, SmbPort, connectCts.Token).ConfigureAwait(false);
                }
                catch { return null; }

                var stream = tcp.GetStream();
                stream.ReadTimeout = IoTimeoutMs;
                stream.WriteTimeout = IoTimeoutMs;

                var request = BuildSmb1NegotiateRequest();
                await stream.WriteAsync(request, 0, request.Length, ct).ConfigureAwait(false);

                // NetBIOS Session Service header is 4 bytes:
                //   byte 0: message type (0x00 = session message)
                //   bytes 1-3: 24-bit big-endian length of payload
                var nbHeader = new byte[4];
                if (!await ReadFullyAsync(stream, nbHeader, 4, ct).ConfigureAwait(false))
                    return null;

                int payloadLen = (nbHeader[1] << 16) | (nbHeader[2] << 8) | nbHeader[3];
                if (payloadLen <= 0 || payloadLen > 65536) return null;

                var payload = new byte[payloadLen];
                if (!await ReadFullyAsync(stream, payload, payloadLen, ct).ConfigureAwait(false))
                    return null;

                return ParseNegotiateResponse(payload);
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"SMB enumerate {host}:{SmbPort} failed");
                return null;
            }
        }

        private static SmbInfo? ParseNegotiateResponse(byte[] payload)
        {
            if (payload.Length < 36) return null;

            // SMB1 header is 32 bytes starting with the protocol id 0xFF "SMB".
            // SMB2 header starts with 0xFE "SMB". We branch on byte 0.
            byte protoId = payload[0];

            if (protoId == 0xFF && payload[1] == (byte)'S' && payload[2] == (byte)'M' && payload[3] == (byte)'B')
            {
                // SMB1 NEGOTIATE response body starts at offset 32:
                //   [32]    WordCount (1 byte)
                //   [33+]   Words[]   (WordCount * 2 bytes)
                //   ...     ByteCount (2 bytes), Bytes[]
                // For NT LM 0.12 the first word (2 bytes) is DialectIndex.
                if (payload.Length < 36) return null;
                byte wordCount = payload[32];
                ushort dialectIndex = (ushort)(payload[33] | (payload[34] << 8));
                string? version = dialectIndex < Dialects.Length
                    ? MapDialectToVersion(Dialects[dialectIndex])
                    : "SMB1";

                // For NT LM 0.12 dialect (WordCount = 17) SecurityMode is at Words[1] low byte
                // = offset 35. Bit 0 = signing enabled, Bit 1 = signing required.
                bool signingEnabled = false;
                bool signingRequired = false;
                if (wordCount >= 17 && payload.Length > 35)
                {
                    byte secMode = payload[35];
                    signingEnabled = (secMode & 0x04) != 0;   // SECURITY_SIGNATURES_ENABLED
                    signingRequired = (secMode & 0x08) != 0;  // SECURITY_SIGNATURES_REQUIRED
                }

                return new SmbInfo(
                    SmbVersion: version,
                    SigningRequired: signingRequired,
                    SigningEnabled: signingEnabled,
                    NativeOs: null,
                    NativeLanManager: null,
                    NetBiosComputerName: null,
                    NetBiosDomain: null,
                    DnsComputerName: null,
                    DnsDomain: null);
            }

            if (protoId == 0xFE && payload[1] == (byte)'S' && payload[2] == (byte)'M' && payload[3] == (byte)'B')
            {
                // SMB2 header is 64 bytes. NEGOTIATE response body starts at offset 64:
                //   [64]    StructureSize (2 bytes, expected 65)
                //   [66]    SecurityMode (2 bytes)
                //   [68]    DialectRevision (2 bytes)
                if (payload.Length < 72) return null;
                ushort dialectRev = (ushort)(payload[68] | (payload[69] << 8));
                ushort secMode = (ushort)(payload[66] | (payload[67] << 8));
                bool signingEnabled = (secMode & 0x0001) != 0;
                bool signingRequired = (secMode & 0x0002) != 0;
                string version = dialectRev switch
                {
                    0x0202 => "SMB 2.0.2",
                    0x0210 => "SMB 2.1",
                    0x0300 => "SMB 3.0",
                    0x0302 => "SMB 3.0.2",
                    0x0311 => "SMB 3.1.1",
                    0x02FF => "SMB 2.x (multi-protocol)",
                    _      => $"SMB2 (0x{dialectRev:X4})"
                };
                return new SmbInfo(
                    SmbVersion: version,
                    SigningRequired: signingRequired,
                    SigningEnabled: signingEnabled,
                    NativeOs: null,
                    NativeLanManager: null,
                    NetBiosComputerName: null,
                    NetBiosDomain: null,
                    DnsComputerName: null,
                    DnsDomain: null);
            }

            return null;
        }

        private static string MapDialectToVersion(string dialect) => dialect switch
        {
            "PC NETWORK PROGRAM 1.0"      => "SMB1 (PC NET 1.0)",
            "LANMAN1.0"                   => "SMB1 (LANMAN 1.0)",
            "Windows for Workgroups 3.1a" => "SMB1 (WfW 3.1a)",
            "LM1.2X002"                   => "SMB1 (LM 1.2)",
            "LANMAN2.1"                   => "SMB1 (LANMAN 2.1)",
            "NT LM 0.12"                  => "SMB1 (NT LM 0.12)",
            "SMB 2.002"                   => "SMB 2.002",
            "SMB 2.???"                   => "SMB 2.x",
            _                             => "SMB1"
        };

        private static byte[] BuildSmb1NegotiateRequest()
        {
            // Build dialect block: each dialect = 0x02 + ASCII string + 0x00
            var dialectBlock = new System.IO.MemoryStream();
            foreach (var d in Dialects)
            {
                dialectBlock.WriteByte(0x02);
                var bytes = Encoding.ASCII.GetBytes(d);
                dialectBlock.Write(bytes, 0, bytes.Length);
                dialectBlock.WriteByte(0x00);
            }
            var dialectBytes = dialectBlock.ToArray();

            // SMB1 header (32 bytes)
            var smb = new byte[32];
            smb[0] = 0xFF; smb[1] = (byte)'S'; smb[2] = (byte)'M'; smb[3] = (byte)'B';
            smb[4] = 0x72; // SMB_COM_NEGOTIATE
            // Status (4 bytes) = 0
            // Flags (1 byte)
            smb[9] = 0x18;
            // Flags2 (2 bytes) — 0x4001 = NT status + Unicode
            smb[10] = 0x53; smb[11] = 0xC8;
            // PIDHigh + Signature + Reserved + TID + PIDLow + UID + MID = leave zero
            smb[30] = 0x00; smb[31] = 0x00; // MID = 0

            // SMB body: WordCount=0, ByteCount=len, Bytes=dialect block
            var body = new byte[3 + dialectBytes.Length];
            body[0] = 0x00; // WordCount
            body[1] = (byte)(dialectBytes.Length & 0xFF);
            body[2] = (byte)((dialectBytes.Length >> 8) & 0xFF);
            Buffer.BlockCopy(dialectBytes, 0, body, 3, dialectBytes.Length);

            int smbPayloadLen = smb.Length + body.Length;

            // NetBIOS Session Service header (4 bytes): type=0x00, 24-bit BE length
            var nb = new byte[4];
            nb[0] = 0x00;
            nb[1] = (byte)((smbPayloadLen >> 16) & 0xFF);
            nb[2] = (byte)((smbPayloadLen >> 8) & 0xFF);
            nb[3] = (byte)(smbPayloadLen & 0xFF);

            var packet = new byte[nb.Length + smbPayloadLen];
            Buffer.BlockCopy(nb, 0, packet, 0, 4);
            Buffer.BlockCopy(smb, 0, packet, 4, smb.Length);
            Buffer.BlockCopy(body, 0, packet, 4 + smb.Length, body.Length);
            return packet;
        }

        private static async Task<bool> ReadFullyAsync(NetworkStream stream, byte[] buf, int count, CancellationToken ct)
        {
            int read = 0;
            while (read < count)
            {
                int n = await stream.ReadAsync(buf, read, count - read, ct).ConfigureAwait(false);
                if (n <= 0) return false;
                read += n;
            }
            return true;
        }
    }
}
