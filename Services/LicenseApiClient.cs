using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NLog;

namespace Dorothy.Services
{
    /// <summary>
    /// HTTP transport for SEACUREDB. As of the no-JWT rework, the only call
    /// site is engagement submit; surveyor identity is asserted by the
    /// <c>surveyor_hardware_id</c> in the request body, validated server-side
    /// against <c>whitelisted_hardware</c>. License validation lives in
    /// <see cref="LicenseService"/> and is unrelated to this client.
    /// </summary>
    public sealed class LicenseApiClient : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly HttpClient _http;
        public string BaseUrl { get; }

        public LicenseApiClient(string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
                throw new ArgumentException(null, nameof(baseUrl));

            BaseUrl = baseUrl.TrimEnd('/');
            _http = new HttpClient
            {
                BaseAddress = new Uri(BaseUrl + "/"),
                // Per-request deadline. EngagementSubmitService also wraps the
                // whole call in a 30s CancellationTokenSource so the user never
                // sees an indefinite hang on a wedged TLS handshake.
                Timeout = TimeSpan.FromSeconds(15)
            };
        }

        public async Task<HttpResponseMessage> PostEngagementAsync(
            string jsonPayload, CancellationToken ct)
        {
            Logger.Info($"[ENGAGEMENT-SUBMIT] POST {BaseUrl}/api/engagements");
            var sw = Stopwatch.StartNew();

            using var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync("api/engagements", content, ct).ConfigureAwait(false);

            Logger.Info(
                $"[ENGAGEMENT-SUBMIT] Response status={(int)response.StatusCode} " +
                $"in {sw.ElapsedMilliseconds}ms");
            return response;
        }

        public void Dispose() => _http.Dispose();
    }
}
