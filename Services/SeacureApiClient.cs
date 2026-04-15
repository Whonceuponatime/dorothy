using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NLog;

namespace Dorothy.Services
{

    public sealed class SeacureApiClient : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            PropertyNameCaseInsensitive = true
        };

        private readonly HttpClient _http;
        private readonly string _email;
        private readonly string _password;
        private readonly SemaphoreSlim _authLock = new(1, 1);

        private string? _accessToken;
        private string? _refreshToken;

        public string BaseUrl { get; }

        public SeacureApiClient(string baseUrl, string email, string password)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))   throw new ArgumentException(null, nameof(baseUrl));
            if (string.IsNullOrWhiteSpace(email))     throw new ArgumentException(null, nameof(email));
            if (string.IsNullOrWhiteSpace(password))  throw new ArgumentException(null, nameof(password));

            BaseUrl = baseUrl.TrimEnd('/');
            _email = email;
            _password = password;
            _http = new HttpClient
            {
                BaseAddress = new Uri(BaseUrl + "/"),
                Timeout = TimeSpan.FromSeconds(8)
            };
        }

        public async Task LoginAsync()
        {
            await _authLock.WaitAsync().ConfigureAwait(false);
            try
            {
                using var resp = await _http.PostAsJsonAsync(
                    "api/auth/login",
                    new { email = _email, password = _password }).ConfigureAwait(false);

                var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode)
                    throw new HttpRequestException(
                        $"Seacure login failed ({(int)resp.StatusCode} {resp.StatusCode}): {body}");

                using var doc = JsonDocument.Parse(body);
                _accessToken  = doc.RootElement.GetProperty("access_token").GetString();
                _refreshToken = doc.RootElement.GetProperty("refresh_token").GetString();
                Logger.Info($"Seacure API login OK ({_email})");
                Logger.Info($"[API DEBUG] Logged in as: {_email}, token sub: {ExtractSubFromJwt(_accessToken ?? "")}");
            }
            finally { _authLock.Release(); }
        }

        private static string ExtractSubFromJwt(string jwt)
        {
            try
            {
                var payload = jwt.Split('.')[1];
                var padded = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
                return json;
            }
            catch { return "(failed to decode)"; }
        }

        private async Task<bool> TryRefreshAsync()
        {
            if (string.IsNullOrEmpty(_refreshToken)) return false;
            await _authLock.WaitAsync().ConfigureAwait(false);
            try
            {
                using var resp = await _http.PostAsJsonAsync(
                    "api/auth/refresh",
                    new { refresh_token = _refreshToken }).ConfigureAwait(false);

                if (!resp.IsSuccessStatusCode) return false;

                var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);
                _accessToken  = doc.RootElement.GetProperty("access_token").GetString();
                _refreshToken = doc.RootElement.GetProperty("refresh_token").GetString();
                return true;
            }
            catch { return false; }
            finally { _authLock.Release(); }
        }

        private async Task<HttpResponseMessage> SendWithAuthAsync(
            HttpMethod method,
            string path,
            Func<HttpContent>? contentFactory = null)
        {
            if (string.IsNullOrEmpty(_accessToken))
                await LoginAsync().ConfigureAwait(false);

            HttpResponseMessage DoSend()
            {
                var req = new HttpRequestMessage(method, path);
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);

                if (contentFactory != null) req.Content = contentFactory();
                return _http.SendAsync(req).GetAwaiter().GetResult();
            }

            var resp = await Task.Run(DoSend).ConfigureAwait(false);

            if (resp.StatusCode == HttpStatusCode.Unauthorized)
            {
                var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                resp.Dispose();

                if (body.IndexOf("expired", StringComparison.OrdinalIgnoreCase) >= 0
                    && await TryRefreshAsync().ConfigureAwait(false))
                {
                    resp = await Task.Run(DoSend).ConfigureAwait(false);
                }
                else if (await TryRefreshAsync().ConfigureAwait(false))
                {

                    resp = await Task.Run(DoSend).ConfigureAwait(false);
                }
            }

            return resp;
        }

        public async Task<(bool IsLicensed, string? ApprovedAt)> ValidateHardwareAsync(string hardwareId)
        {
            var url = $"{BaseUrl}/api/license/validate?hardware_id={Uri.EscapeDataString(hardwareId)}";
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

            var response = await client.GetAsync(url).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
            var isLicensed = json.RootElement.GetProperty("is_licensed").GetBoolean();
            string? approvedAt = null;
            if (json.RootElement.TryGetProperty("approved_at", out var ap) && ap.ValueKind != JsonValueKind.Null)
                approvedAt = ap.GetString();

            return (isLicensed, approvedAt);
        }

        public async Task<string> RequestLicensePublicAsync(string hardwareId, string machineName, string deviceName)
        {
            var url = $"{BaseUrl}/api/license/request-public";
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

            var payload = new { hardware_id = hardwareId, machine_name = machineName, device_name = deviceName };
            using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await client.PostAsync(url, content).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync().ConfigureAwait(false));
            return json.RootElement.TryGetProperty("status", out var s)
                ? (s.GetString() ?? "unknown")
                : "unknown";
        }

        public async Task<(bool IsLicensed, JsonElement? Entry)> CheckLicenseAsync(string hardwareId)
        {
            var path = $"api/license/check?hardware_id={Uri.EscapeDataString(hardwareId)}";

            Logger.Info($"[API DEBUG] GET {_http.BaseAddress}{path}");
            Logger.Info($"[API DEBUG] Auth token present: {!string.IsNullOrEmpty(_accessToken)}");
            Logger.Info($"[API DEBUG] Auth email: {_email}");

            using var resp = await SendWithAuthAsync(HttpMethod.Get, path).ConfigureAwait(false);
            var bodyText = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            Logger.Info($"[API DEBUG] Response: {resp.StatusCode} — {bodyText}");

            if (!resp.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Seacure license check failed ({(int)resp.StatusCode}): {bodyText}");
            }

            var body = bodyText;
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            var isLicensed = root.TryGetProperty("is_licensed", out var lic) && lic.GetBoolean();
            JsonElement? entry = root.TryGetProperty("entry", out var e) && e.ValueKind != JsonValueKind.Null
                ? e.Clone()
                : null;
            return (isLicensed, entry);
        }

        public async Task<string> RequestLicenseAsync(string hardwareId, string machineName, string deviceName)
        {
            var payload = new { hardware_id = hardwareId, machine_name = machineName, device_name = deviceName };
            var json = JsonSerializer.Serialize(payload);

            using var resp = await SendWithAuthAsync(
                HttpMethod.Post,
                "api/license/request",
                () => new StringContent(json, Encoding.UTF8, "application/json")).ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
            {
                var errBody = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                throw new HttpRequestException(
                    $"Seacure license request failed ({(int)resp.StatusCode}): {errBody}");
            }

            var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("status", out var s)
                ? (s.GetString() ?? "unknown")
                : "unknown";
        }

        public void Dispose()
        {
            _authLock.Dispose();
            _http.Dispose();
        }
    }
}
