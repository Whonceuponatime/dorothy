using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services.Probes
{
    public class BannerGrabberService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int ConnectTimeoutMs = 2000;
        private const int ReadTimeoutMs = 2000;
        private const int BannerBytes = 256;
        private const int MaxConcurrent = 5;

        public async Task<List<BannerInfo>> GrabBannersAsync(
            string ipAddress,
            IEnumerable<int> openPorts,
            CancellationToken ct)
        {
            var ports = openPorts?.Distinct().ToList() ?? new List<int>();
            var results = new List<BannerInfo>(ports.Count);
            if (ports.Count == 0) return results;

            using var gate = new SemaphoreSlim(MaxConcurrent, MaxConcurrent);
            var tasks = ports.Select(port => GrabOneAsync(ipAddress, port, gate, ct)).ToList();

            BannerInfo?[] collected;
            try
            {
                collected = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return results;
            }

            foreach (var b in collected)
            {
                if (b != null) results.Add(b);
            }
            return results;
        }

        private static async Task<BannerInfo?> GrabOneAsync(
            string ipAddress,
            int port,
            SemaphoreSlim gate,
            CancellationToken ct)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(ConnectTimeoutMs);

                try
                {
                    await tcp.ConnectAsync(ipAddress, port, connectCts.Token).ConfigureAwait(false);
                }
                catch { return null; }

                using var stream = tcp.GetStream();
                stream.ReadTimeout = ReadTimeoutMs;
                stream.WriteTimeout = ReadTimeoutMs;

                byte[]? probe = port switch
                {
                    80 or 8080 or 8000 or 8888 or 8081 or 8089 or 8181 or 3128 =>
                        Encoding.ASCII.GetBytes(
                            "GET / HTTP/1.0\r\nHost: " + ipAddress + "\r\nUser-Agent: SEACURE\r\n\r\n"),
                    _ => null
                };

                if (probe != null)
                {
                    try { await stream.WriteAsync(probe, 0, probe.Length, ct).ConfigureAwait(false); }
                    catch { return PortOnlyBanner(port); }
                }

                var buffer = new byte[BannerBytes];
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                readCts.CancelAfter(ReadTimeoutMs);

                int bytesRead;
                try
                {
                    bytesRead = await stream.ReadAsync(buffer, 0, BannerBytes, readCts.Token).ConfigureAwait(false);
                }
                catch { return PortOnlyBanner(port); }

                if (bytesRead <= 0) return PortOnlyBanner(port);

                var raw = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                var (svc, ver) = IdentifyService(port, raw);
                return new BannerInfo(port, raw, svc, ver);
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"Banner grab failed for {ipAddress}:{port}");
                return null;
            }
            finally
            {
                gate.Release();
            }
        }

        private static BannerInfo PortOnlyBanner(int port)
        {
            var (svc, ver) = IdentifyService(port, string.Empty);
            if (svc == null) return new BannerInfo(port, null, null, null);
            return new BannerInfo(port, null, svc, ver);
        }

        private static (string? Service, string? Version) IdentifyService(int port, string raw)
        {
            if (!string.IsNullOrEmpty(raw))
            {
                if (raw.StartsWith("SSH-", StringComparison.Ordinal))
                {
                    var line = raw.Split('\n', 2)[0].TrimEnd('\r');
                    return ("SSH", line);
                }
                if (raw.StartsWith("HTTP/", StringComparison.Ordinal))
                {
                    var m = Regex.Match(raw, @"Server:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
                    var server = m.Success ? m.Groups[1].Value.Trim() : null;
                    return ("HTTP", server);
                }
                if (raw.StartsWith("220 ", StringComparison.Ordinal) || raw.StartsWith("220-", StringComparison.Ordinal))
                {
                    var line = raw.Split('\n', 2)[0].TrimEnd('\r');
                    var isEsmtp = raw.IndexOf("ESMTP", StringComparison.OrdinalIgnoreCase) >= 0
                                || raw.IndexOf("SMTP", StringComparison.OrdinalIgnoreCase) >= 0;
                    return (isEsmtp ? "SMTP" : "FTP", line);
                }
                if (raw.StartsWith("+OK", StringComparison.Ordinal))
                {
                    return ("POP3", raw.Split('\n', 2)[0].TrimEnd('\r'));
                }
                if (raw.StartsWith("* OK", StringComparison.Ordinal))
                {
                    return ("IMAP", raw.Split('\n', 2)[0].TrimEnd('\r'));
                }
                if (raw.IndexOf("SMB", StringComparison.Ordinal) >= 0)
                {
                    return ("SMB", null);
                }
                if (raw.StartsWith("RDP", StringComparison.Ordinal))
                {
                    return ("RDP", null);
                }
                if (raw.StartsWith("RFB ", StringComparison.Ordinal))
                {
                    return ("VNC", raw.Split('\n', 2)[0].TrimEnd('\r'));
                }
            }

            return port switch
            {
                22 => ("SSH", "filtered"),
                25 or 587 or 465 => ("SMTP", null),
                53 => ("DNS", null),
                80 or 8080 or 8000 or 8888 or 8081 or 8089 or 8181 => ("HTTP", null),
                110 => ("POP3", null),
                143 => ("IMAP", null),
                161 => ("SNMP", null),
                389 => ("LDAP", null),
                443 or 8443 => ("HTTPS", null),
                445 => ("SMB", null),
                631 => ("IPP", null),
                636 => ("LDAPS", null),
                1433 => ("MSSQL", null),
                1521 => ("Oracle", null),
                1883 => ("MQTT", null),
                1900 => ("SSDP", null),
                2049 => ("NFS", null),
                2375 or 2376 => ("Docker", null),
                3306 => ("MySQL", null),
                3389 => ("RDP", null),
                5060 or 5061 => ("SIP", null),
                5432 => ("PostgreSQL", null),
                5900 or 5901 => ("VNC", null),
                5984 => ("CouchDB", null),
                6379 => ("Redis", null),
                6443 => ("Kubernetes", null),
                8009 => ("AJP13", null),
                9100 => ("JetDirect", null),
                9200 => ("Elasticsearch", null),
                11211 => ("Memcached", null),
                _ => (null, null)
            };
        }
    }
}
