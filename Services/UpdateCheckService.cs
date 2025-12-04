using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dorothy.Models;
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
        private readonly AttackLogger? _attackLogger;

        public UpdateCheckService(Client? supabaseClient, AttackLogger? attackLogger = null)
        {
            _supabaseClient = supabaseClient;
            _attackLogger = attackLogger;
            
            // Get current version from assembly
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            _currentVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "0.0.0";
            
            Logger.Info($"UpdateCheckService initialized: CurrentVersion={_currentVersion}, SupabaseConfigured={supabaseClient != null}");
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
                _attackLogger?.LogInfo($"🔍 Checking for updates... Current version: {_currentVersion}");
                
                // Check if online
                bool isOnline = await IsOnlineAsync();
                if (!isOnline)
                {
                    _attackLogger?.LogWarning("⚠️ No internet connection - cannot check for updates");
                    return new UpdateCheckResult
                    {
                        IsOnline = false,
                        IsUpdateAvailable = false,
                        CurrentVersion = _currentVersion,
                        LatestVersion = null,
                        Message = "No internet connection"
                    };
                }

                // Get latest release from database
                List<ReleaseEntry> releases;
                try
                {
                    // Get all releases and find the one with the highest version number
                    var allReleases = await _supabaseClient
                        .From<ReleaseEntry>()
                        .Order("created_at", Supabase.Postgrest.Constants.Ordering.Descending)
                        .Get();
                    
                    releases = allReleases?.Models?.ToList() ?? new List<ReleaseEntry>();
                    
                    if (releases.Count == 0)
                    {
                        _attackLogger?.LogWarning("⚠️ No releases found in database (query returned empty)");
                        Logger.Warn("Update check: Query returned 0 releases. This might indicate RLS policy blocking access or empty table.");
                        return new UpdateCheckResult
                        {
                            IsOnline = true,
                            IsUpdateAvailable = false,
                            CurrentVersion = _currentVersion,
                            LatestVersion = null,
                            Message = "No releases found in database"
                        };
                    }
                }
                catch (Exception ex)
                {
                    _attackLogger?.LogError($"❌ Error querying release database: {ex.Message}");
                    Logger.Error(ex, "Failed to query releases from Supabase");
                    
                    // Check for RLS policy violation
                    string errorMessage = ex.Message;
                    if (ex.Message.Contains("row-level security policy", StringComparison.OrdinalIgnoreCase) ||
                        ex.Message.Contains("42501", StringComparison.OrdinalIgnoreCase) ||
                        ex.Message.Contains("permission denied", StringComparison.OrdinalIgnoreCase))
                    {
                        errorMessage = "RLS policy violation - Check Supabase RLS policies allow SELECT queries on releases table with anon key";
                        _attackLogger?.LogWarning($"⚠️ RLS Policy Issue: The releases table may have Row Level Security enabled that blocks anonymous reads. Please check your Supabase RLS policies.");
                    }
                    
                    return new UpdateCheckResult
                    {
                        IsOnline = true,
                        IsUpdateAvailable = false,
                        CurrentVersion = _currentVersion,
                        LatestVersion = null,
                        Message = $"Error querying database: {errorMessage}"
                    };
                }
                
                // Find the release with the highest version by comparing all versions
                ReleaseEntry? latestRelease = null;
                string? highestVersion = null;
                
                foreach (var release in releases)
                {
                    string? releaseVersion = release.Version?.Trim();
                    if (string.IsNullOrEmpty(releaseVersion))
                        continue;
                    
                    if (latestRelease == null)
                    {
                        latestRelease = release;
                        highestVersion = releaseVersion;
                    }
                    else if (highestVersion != null)
                    {
                        // Compare versions to find the highest
                        int versionComparison = CompareVersions(highestVersion, releaseVersion);
                        if (versionComparison < 0) // releaseVersion is newer
                        {
                            latestRelease = release;
                            highestVersion = releaseVersion;
                        }
                    }
                }
                
                if (latestRelease == null || highestVersion == null)
                {
                    _attackLogger?.LogWarning("⚠️ No valid releases found (all releases have empty or invalid versions)");
                    return new UpdateCheckResult
                    {
                        IsOnline = true,
                        IsUpdateAvailable = false,
                        CurrentVersion = _currentVersion,
                        LatestVersion = null,
                        Message = "No releases found in database"
                    };
                }

                // Use the calculated highestVersion instead of latestRelease.Version to ensure we have the correct one
                string latestVersion = highestVersion.Trim();

                if (string.IsNullOrEmpty(latestVersion))
                {
                    _attackLogger?.LogWarning("⚠️ Latest release version is invalid");
                    return new UpdateCheckResult
                    {
                        IsOnline = true,
                        IsUpdateAvailable = false,
                        CurrentVersion = _currentVersion,
                        LatestVersion = null,
                        Message = "Latest release version is invalid"
                    };
                }

                // Compare versions - returns -1 if version1 < version2, 0 if equal, 1 if version1 > version2
                int comparison = CompareVersions(_currentVersion, latestVersion);
                bool isUpdateAvailable = comparison < 0;

                if (isUpdateAvailable)
                {
                    _attackLogger?.LogInfo($"✅ Update available! Latest version: {latestVersion} (Current: {_currentVersion})");
                }
                else
                {
                    _attackLogger?.LogInfo($"✅ You are running the latest version: {_currentVersion}");
                }

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
                // Trim and normalize versions
                version1 = version1?.Trim() ?? "0.0.0";
                version2 = version2?.Trim() ?? "0.0.0";
                
                var v1Parts = version1.Split('.').Select(s => int.TryParse(s.Trim(), out int val) ? val : 0).ToArray();
                var v2Parts = version2.Split('.').Select(s => int.TryParse(s.Trim(), out int val) ? val : 0).ToArray();

                int maxLength = Math.Max(v1Parts.Length, v2Parts.Length);
                
                for (int i = 0; i < maxLength; i++)
                {
                    int v1Part = i < v1Parts.Length ? v1Parts[i] : 0;
                    int v2Part = i < v2Parts.Length ? v2Parts[i] : 0;
                    
                    if (v1Part < v2Part)
                        return -1;
                    if (v1Part > v2Part)
                        return 1;
                }

                return 0;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Error comparing versions '{version1}' vs '{version2}', falling back to string comparison");
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
