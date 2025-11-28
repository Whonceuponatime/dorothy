using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Dorothy.Models.Database;
using NLog;
using Supabase;

namespace Dorothy.Services
{
    public class SupabaseSyncService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly DatabaseService _databaseService;
        private Client? _supabaseClient;

        public SupabaseSyncService(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public bool IsConfigured => _supabaseClient != null;

        public void Initialize(string supabaseUrl, string supabaseAnonKey)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(supabaseUrl) || string.IsNullOrWhiteSpace(supabaseAnonKey))
                {
                    Logger.Warn("Supabase URL or Anon Key is empty");
                    _supabaseClient = null;
                    return;
                }

                var options = new SupabaseOptions
                {
                    AutoConnectRealtime = false,
                    AutoRefreshToken = false
                };

                _supabaseClient = new Client(supabaseUrl, supabaseAnonKey, options);
                Logger.Info("Supabase client initialized");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to initialize Supabase client");
                _supabaseClient = null;
            }
        }

        public async Task<SyncResult> SyncAsync(string? projectName = null, List<long>? selectedIds = null)
        {
            if (_supabaseClient == null)
            {
                return new SyncResult
                {
                    Success = false,
                    Message = "Supabase is not configured. Please configure it in Settings.",
                    SyncedCount = 0
                };
            }

            try
            {
                var unsyncedLogs = await _databaseService.GetUnsyncedLogsAsync(selectedIds);
                if (unsyncedLogs.Count == 0)
                {
                    return new SyncResult
                    {
                        Success = true,
                        Message = "No pending logs to sync.",
                        SyncedCount = 0
                    };
                }

                int syncedCount = 0;
                var errors = new List<string>();
                var syncedIds = new List<long>();

                foreach (var log in unsyncedLogs)
                {
                    try
                    {
                        // Calculate duration in seconds
                        var duration = (log.StopTime - log.StartTime).TotalSeconds;

                        // Create a new entry for Supabase (without the local SQLite Id)
                        // Important: Do NOT set Id (Supabase auto-generates it) or IsSynced/Note/LogContent/SyncedAt (not in schema)
                        var supabaseEntry = new AttackLogEntry
                        {
                            // Id is not set - Supabase will auto-generate it
                            ProjectName = projectName ?? log.ProjectName,
                            AttackType = log.AttackType,
                            Protocol = log.Protocol,
                            SourceIp = log.SourceIp,
                            SourceMac = log.SourceMac,
                            TargetIp = log.TargetIp,
                            TargetMac = log.TargetMac,
                            TargetPort = log.TargetPort,
                            TargetRateMbps = log.TargetRateMbps,
                            PacketsSent = log.PacketsSent,
                            DurationSeconds = log.DurationSeconds > 0 ? log.DurationSeconds : (int)duration,
                            StartTime = log.StartTime,
                            StopTime = log.StopTime,
                            Synced = true, // This maps to the 'synced' column in Supabase (NOT IsSynced)
                            CreatedAt = log.CreatedAt
                            // Note: IsSynced, Note, LogContent, and SyncedAt are NOT set - they don't exist in Supabase schema
                        };

                        // Explicitly clear any local-only properties to prevent serialization
                        supabaseEntry.Note = null;
                        supabaseEntry.LogContent = string.Empty;
                        supabaseEntry.SyncedAt = null;
                        supabaseEntry.IsSynced = false;

                        var response = await _supabaseClient
                            .From<AttackLogEntry>()
                            .Insert(supabaseEntry);

                        if (response != null && response.Models != null && response.Models.Count > 0)
                        {
                            syncedIds.Add(log.Id);
                            syncedCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, $"Failed to sync log {log.Id}");
                        errors.Add($"Log {log.Id}: {ex.Message}");
                    }
                }

                // Mark all successfully synced logs
                if (syncedIds.Count > 0)
                {
                    await _databaseService.MarkAsSyncedAsync(syncedIds, DateTime.UtcNow);
                }

                var message = syncedCount == unsyncedLogs.Count
                    ? $"Successfully synced {syncedCount} log(s)."
                    : $"Synced {syncedCount} of {unsyncedLogs.Count} log(s). {(errors.Count > 0 ? string.Join("; ", errors.Take(3)) : "")}";

                return new SyncResult
                {
                    Success = syncedCount > 0,
                    Message = message,
                    SyncedCount = syncedCount,
                    Errors = errors
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to sync with Supabase");
                return new SyncResult
                {
                    Success = false,
                    Message = $"Sync failed: {ex.Message}",
                    SyncedCount = 0
                };
            }
        }

        public async Task<int> GetPendingSyncCountAsync()
        {
            return await _databaseService.GetUnsyncedCountAsync();
        }

        public async Task<SyncResult> SyncAssetsAsync(string? projectName = null, List<long>? selectedIds = null)
        {
            if (_supabaseClient == null)
            {
                return new SyncResult
                {
                    Success = false,
                    Message = "Supabase is not configured. Please configure it in Settings.",
                    SyncedCount = 0
                };
            }

            try
            {
                var unsyncedAssets = await _databaseService.GetUnsyncedAssetsAsync(selectedIds);
                if (unsyncedAssets.Count == 0)
                {
                    return new SyncResult
                    {
                        Success = true,
                        Message = "No pending assets to sync.",
                        SyncedCount = 0
                    };
                }

                int syncedCount = 0;
                var errors = new List<string>();
                var syncedIds = new List<long>();

                foreach (var asset in unsyncedAssets)
                {
                    try
                    {
                        var supabaseAsset = new AssetEntry
                        {
                            HostIp = asset.HostIp,
                            HostName = asset.HostName,
                            MacAddress = asset.MacAddress,
                            Vendor = asset.Vendor,
                            IsOnline = asset.IsOnline,
                            PingTime = asset.PingTime,
                            ScanTime = asset.ScanTime,
                            ProjectName = projectName ?? asset.ProjectName,
                            Synced = true,
                            CreatedAt = asset.CreatedAt
                        };

                        // Explicitly clear local-only property to prevent serialization
                        supabaseAsset.SyncedAt = null;

                        var response = await _supabaseClient
                            .From<AssetEntry>()
                            .Insert(supabaseAsset);

                        if (response != null && response.Models != null && response.Models.Count > 0)
                        {
                            syncedIds.Add(asset.Id);
                            syncedCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, $"Failed to sync asset {asset.Id}");
                        errors.Add($"Asset {asset.Id}: {ex.Message}");
                    }
                }

                // Mark all successfully synced assets
                if (syncedIds.Count > 0)
                {
                    await _databaseService.MarkAssetsAsSyncedAsync(syncedIds, DateTime.UtcNow);
                }

                var message = syncedCount == unsyncedAssets.Count
                    ? $"Successfully synced {syncedCount} asset(s)."
                    : $"Synced {syncedCount} of {unsyncedAssets.Count} asset(s). {(errors.Count > 0 ? string.Join("; ", errors.Take(3)) : "")}";

                return new SyncResult
                {
                    Success = syncedCount > 0,
                    Message = message,
                    SyncedCount = syncedCount,
                    Errors = errors
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to sync assets with Supabase");
                return new SyncResult
                {
                    Success = false,
                    Message = $"Asset sync failed: {ex.Message}",
                    SyncedCount = 0
                };
            }
        }

        public async Task<int> GetPendingAssetsCountAsync()
        {
            return await _databaseService.GetUnsyncedAssetsCountAsync();
        }
    }

    public class SyncResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public int SyncedCount { get; set; }
        public List<string> Errors { get; set; } = new();
    }
}

