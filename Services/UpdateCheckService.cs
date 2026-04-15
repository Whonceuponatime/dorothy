using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services
{

    public class UpdateCheckService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };

        private readonly string _currentVersion;
        private readonly AttackLogger? _attackLogger;

        public UpdateCheckService(AttackLogger? attackLogger = null)
        {
            _attackLogger = attackLogger;

            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            _currentVersion = version != null
                ? $"{version.Major}.{version.Minor}.{version.Build}"
                : "0.0.0";

            Logger.Info($"UpdateCheckService initialized: CurrentVersion={_currentVersion}, Endpoint={SeacureConfig.ApiUrl}/api/releases/latest");
        }

        public string CurrentVersion => _currentVersion;

        public async Task<UpdateCheckResult> CheckForUpdatesAsync()
        {
            var endpoint = $"{SeacureConfig.ApiUrl.TrimEnd('/')}/api/releases/latest";

            try
            {
                _attackLogger?.LogInfo($"🔍 Checking for updates... Current version: {_currentVersion}");

                using var resp = await Http.GetAsync(endpoint).ConfigureAwait(false);

                if (resp.StatusCode == HttpStatusCode.NotFound || !resp.IsSuccessStatusCode)
                {
                    Logger.Info("Update check skipped — endpoint unavailable");
                    return Skipped();
                }

                var payload = await resp.Content.ReadFromJsonAsync<ReleaseDto>().ConfigureAwait(false);
                var latestVersion = payload?.Version?.Trim();

                if (string.IsNullOrEmpty(latestVersion))
                {
                    Logger.Info("Update check skipped — endpoint unavailable");
                    return Skipped();
                }

                var isUpdateAvailable = CompareVersions(_currentVersion, latestVersion) < 0;
                if (isUpdateAvailable)
                    _attackLogger?.LogInfo($"✅ Update available! Latest version: {latestVersion} (Current: {_currentVersion})");
                else
                    _attackLogger?.LogInfo($"✅ You are running the latest version: {_currentVersion}");

                return new UpdateCheckResult
                {
                    IsOnline = true,
                    IsUpdateAvailable = isUpdateAvailable,
                    CurrentVersion = _currentVersion,
                    LatestVersion = latestVersion,
                    Message = isUpdateAvailable
                        ? $"Update available: {latestVersion}"
                        : "You are running the latest version"
                };
            }
            catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
            {
                Logger.Info("Update check skipped — endpoint unavailable");
                return Skipped();
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Update check failed unexpectedly");
                return Skipped();
            }
        }

        private UpdateCheckResult Skipped() => new()
        {
            IsOnline = false,
            IsUpdateAvailable = false,
            CurrentVersion = _currentVersion,
            LatestVersion = null,
            Message = "Update check skipped — endpoint unavailable"
        };

        private static int CompareVersions(string version1, string version2)
        {
            try
            {
                version1 = version1?.Trim() ?? "0.0.0";
                version2 = version2?.Trim() ?? "0.0.0";

                var v1Parts = version1.Split('.').Select(s => int.TryParse(s.Trim(), out int val) ? val : 0).ToArray();
                var v2Parts = version2.Split('.').Select(s => int.TryParse(s.Trim(), out int val) ? val : 0).ToArray();

                int maxLength = Math.Max(v1Parts.Length, v2Parts.Length);
                for (int i = 0; i < maxLength; i++)
                {
                    int v1Part = i < v1Parts.Length ? v1Parts[i] : 0;
                    int v2Part = i < v2Parts.Length ? v2Parts[i] : 0;
                    if (v1Part < v2Part) return -1;
                    if (v1Part > v2Part) return 1;
                }
                return 0;
            }
            catch
            {
                return string.Compare(version1, version2, StringComparison.OrdinalIgnoreCase);
            }
        }

        private sealed class ReleaseDto
        {
            [JsonPropertyName("version")] public string? Version { get; set; }
            [JsonPropertyName("url")]     public string? Url     { get; set; }
            [JsonPropertyName("notes")]   public string? Notes   { get; set; }
        }
    }

    public class UpdateCheckResult
    {
        public bool IsOnline { get; set; }
        public bool IsUpdateAvailable { get; set; }
        public string CurrentVersion { get; set; } = string.Empty;
        public string? LatestVersion { get; set; }
        public string Message { get; set; } = string.Empty;
    }
}
