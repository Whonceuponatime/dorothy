using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// After identifying an HTTP/HTTPS port, probe a curated list of
    /// "interesting" paths and report status/title for non-404 hits.
    /// Used by Full and Deep tiers to surface admin consoles / leaks.
    /// </summary>
    public class HttpPathDiscoveryService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int PerRequestTimeoutMs = 2000;
        private const int MaxConcurrent = 4;

        private static readonly string[] InterestingPaths =
        {
            "/robots.txt",
            "/.git/config",
            "/server-status",
            "/admin",
            "/manager/html",
            "/phpmyadmin",
            "/wp-login.php",
            "/login",
            "/api",
            "/.env"
        };

        private static readonly HashSet<int> HttpPortsHint = new()
        {
            80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000
        };

        public static bool IsLikelyHttpPort(int port) => HttpPortsHint.Contains(port);

        public async Task<List<HttpPathFinding>> ProbeAsync(
            string host, int port, bool useTls, CancellationToken ct)
        {
            var findings = new List<HttpPathFinding>();

            // Use a per-call HttpClient that ignores cert problems —
            // we're probing arbitrary internal hosts, not relying on PKI.
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var http = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(PerRequestTimeoutMs)
            };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("SEACURE/2.5.1");

            string scheme = useTls ? "https" : "http";
            string baseUrl = $"{scheme}://{host}:{port}";

            using var gate = new SemaphoreSlim(MaxConcurrent, MaxConcurrent);
            var tasks = InterestingPaths.Select(p => ProbeOneAsync(http, baseUrl, p, gate, ct)).ToList();

            HttpPathFinding?[] results;
            try
            {
                results = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return findings; }

            foreach (var r in results)
            {
                if (r != null) findings.Add(r);
            }
            return findings;
        }

        private static async Task<HttpPathFinding?> ProbeOneAsync(
            HttpClient http, string baseUrl, string path, SemaphoreSlim gate, CancellationToken ct)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                var url = baseUrl + path;

                // HEAD first — many endpoints reject HEAD with 405; fall back to GET.
                using var headReq = new HttpRequestMessage(HttpMethod.Head, url);
                HttpResponseMessage? resp;
                try
                {
                    resp = await http.SendAsync(headReq, HttpCompletionOption.ResponseHeadersRead, ct)
                        .ConfigureAwait(false);
                }
                catch { return null; }

                int status = (int)resp.StatusCode;
                long contentLen = resp.Content.Headers.ContentLength ?? -1;
                string? title = null;

                bool needsGet = status == 405 || resp.Content.Headers.ContentLength == null;
                if (needsGet)
                {
                    resp.Dispose();
                    using var getReq = new HttpRequestMessage(HttpMethod.Get, url);
                    try
                    {
                        resp = await http.SendAsync(getReq, HttpCompletionOption.ResponseContentRead, ct)
                            .ConfigureAwait(false);
                    }
                    catch { return null; }

                    status = (int)resp.StatusCode;
                    var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                    contentLen = body.Length;
                    title = ExtractTitle(body);
                }

                using (resp) { /* dispose */ }

                // 404 → not interesting. Skip.
                if (status == 404) return null;

                // 200/301/302/401/403 → surface
                return new HttpPathFinding(path, status, title, contentLen);
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"HTTP probe {path} on {baseUrl} failed");
                return null;
            }
            finally
            {
                gate.Release();
            }
        }

        private static string? ExtractTitle(string body)
        {
            if (string.IsNullOrEmpty(body)) return null;
            try
            {
                var m = Regex.Match(body, @"<title[^>]*>([^<]{0,200})</title>",
                    RegexOptions.IgnoreCase | RegexOptions.Singleline);
                if (!m.Success) return null;
                return System.Net.WebUtility.HtmlDecode(m.Groups[1].Value).Trim();
            }
            catch { return null; }
        }
    }
}
