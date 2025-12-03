using System;
using System.Linq;
using System.Threading.Tasks;
using Dorothy.Models.Database;
using NLog;
using Supabase;

namespace Dorothy.Services
{
    public class UpdateCheckService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly Client? _supabaseClient;
        private readonly string _currentVersion;

        public UpdateCheckService(Client? supabaseClient)
        {
            _supabaseClient = supabaseClient;
            
            // Get current version from assembly
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            _currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "0.0.0";
        }

        public string CurrentVersion => _currentVersion;

        public async Task<UpdateCheckResult> CheckForUpdatesAsync()
        {
            if (_supabaseClient == null)
            {
                return new UpdateCheckResult
                {
                    IsOnline = false,
                    IsUpdateAvailable = false,
                    CurrentVersion = _currentVersion,
                    LatestVersion = null,
                    Message = "Supabase not configured"
                };
            }

            try
            {
                // Check if online
                bool isOnline = await IsOnlineAsync();
                if (!isOnline)
                {
                    return new UpdateCheckResult
                    {
                        IsOnline = false,
                        IsUpdateAvailable = false,
                        CurrentVersion = _currentVersion,
                        LatestVersion = null,
                        Message = "No internet connection"
                    };
                }

                // Get latest release from database (order by created_at descending, then take first)
                var allReleases = await _supabaseClient
                    .From<ReleaseEntry>()
                    .Get();
                
                var latestRelease = allReleases?.Models?
                    .OrderByDescending(r => r.CreatedAt)
                    .FirstOrDefault();

                if (latestRelease == null)
                {
                    return new UpdateCheckResult
                    {
                        IsOnline = true,
                        IsUpdateAvailable = false,
                        CurrentVersion = _currentVersion,
                        LatestVersion = null,
                        Message = "No releases found in database"
                    };
                }

                string latestVersion = latestRelease.Version;

                // Compare versions
                bool isUpdateAvailable = CompareVersions(_currentVersion, latestVersion) < 0;

                Logger.Info($"Update check: Current={_currentVersion}, Latest={latestVersion}, UpdateAvailable={isUpdateAvailable}");

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
            catch (Exception ex)
            {
                Logger.Error(ex, "Error checking for updates");
                return new UpdateCheckResult
                {
                    IsOnline = true,
                    IsUpdateAvailable = false,
                    CurrentVersion = _currentVersion,
                    LatestVersion = null,
                    Message = $"Error checking for updates: {ex.Message}"
                };
            }
        }

        private async Task<bool> IsOnlineAsync()
        {
            try
            {
                using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                var response = await client.GetAsync("https://www.google.com");
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private int CompareVersions(string version1, string version2)
        {
            try
            {
                var v1Parts = version1.Split('.').Select(int.Parse).ToArray();
                var v2Parts = version2.Split('.').Select(int.Parse).ToArray();

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
                // If version parsing fails, do string comparison
                return string.Compare(version1, version2, StringComparison.OrdinalIgnoreCase);
            }
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
