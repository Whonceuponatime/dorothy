using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
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
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

        public event Action<string>? ProgressChanged;

        public SupabaseSyncService(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public bool IsConfigured => _supabaseClient != null;

        private void ReportProgress(string message)
        {
            Logger.Info(message);
            ProgressChanged?.Invoke(message);
        }

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
                            CreatedAt = log.CreatedAt,
                            HardwareId = log.HardwareId?.ToUpperInvariant(),
                            MachineName = log.MachineName,
                            Username = log.Username,
                            UserId = log.UserId
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

        public async Task<SyncResult> SyncAssetsAsync(string? projectName = null, List<long>? selectedIds = null, bool enhanceData = true)
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

                for (int i = 0; i < unsyncedAssets.Count; i++)
                {
                    var asset = unsyncedAssets[i];
                    try
                    {
                        ReportProgress($"Syncing asset {i + 1}/{unsyncedAssets.Count}: {asset.HostIp}");
                        
                        // Enhance asset data with online lookups during sync (if enabled)
                        string hostname = asset.HostName;
                        string vendor = asset.Vendor;

                        if (enhanceData)
                        {
                            ReportProgress($"Enhancing data for {asset.HostIp}...");
                            
                            // Do DNS lookup ONLY if hostname is unknown
                            if (string.IsNullOrEmpty(hostname) || hostname == "Unknown")
                            {
                                ReportProgress($"Looking up hostname for {asset.HostIp}...");
                                hostname = await ResolveHostnameAsync(asset.HostIp);
                            }

                            // For vendor: Check local OUI first, then online API if still unknown
                            if ((string.IsNullOrEmpty(vendor) || vendor == "Unknown") && 
                                !string.IsNullOrEmpty(asset.MacAddress) && 
                                asset.MacAddress != "Unknown")
                            {
                                // Try local OUI database first (fast, free)
                                vendor = GetVendorFromLocalDatabase(asset.MacAddress);
                                
                                // If still unknown, try online API
                                if (vendor == "Unknown")
                                {
                                    ReportProgress($"Looking up vendor for {asset.MacAddress}...");
                                    vendor = await LookupVendorOnlineAsync(asset.MacAddress);
                                }
                            }
                        }

                        var supabaseAsset = new AssetEntry
                        {
                            HostIp = asset.HostIp,
                            HostName = hostname, // Enhanced hostname
                            MacAddress = asset.MacAddress,
                            Vendor = vendor, // Enhanced vendor
                            IsOnline = asset.IsOnline,
                            PingTime = asset.PingTime,
                            ScanTime = asset.ScanTime,
                            ProjectName = projectName ?? asset.ProjectName,
                            Synced = true,
                            CreatedAt = asset.CreatedAt,
                            HardwareId = asset.HardwareId?.ToUpperInvariant(),
                            MachineName = asset.MachineName,
                            Username = asset.Username,
                            UserId = asset.UserId
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

        /// <summary>
        /// Resolves hostname from IP address using DNS lookup (online).
        /// Returns original value or "Unknown" if lookup fails.
        /// </summary>
        private async Task<string> ResolveHostnameAsync(string ipAddress)
        {
            try
            {
                var dnsTask = System.Net.Dns.GetHostEntryAsync(ipAddress);
                var timeoutTask = Task.Delay(5000); // 5 second timeout
                var completed = await Task.WhenAny(dnsTask, timeoutTask);
                
                if (completed == dnsTask)
                {
                    var hostEntry = await dnsTask;
                    if (hostEntry != null && !string.IsNullOrEmpty(hostEntry.HostName))
                    {
                        Logger.Info($"Hostname resolved: {hostEntry.HostName}");
                        return hostEntry.HostName;
                    }
                }
            }
            catch
            {
                // DNS failed, stay as unknown
            }
            
            return "Unknown";
        }

        /// <summary>
        /// Looks up vendor from MAC address using ONLINE API only (macvendors.com).
        /// This is called during sync only for vendors that are still "Unknown" after local OUI check.
        /// </summary>
        private async Task<string> LookupVendorOnlineAsync(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress) || macAddress == "Unknown")
            {
                return "Unknown";
            }

            try
            {
                // Try online API (macvendors.com - free, no API key required)
                var url = $"https://api.macvendors.com/{macAddress}";
                var responseTask = _httpClient.GetStringAsync(url);
                var timeoutTask = Task.Delay(3000);
                var completed = await Task.WhenAny(responseTask, timeoutTask);
                
                if (completed == responseTask)
                {
                    var response = await responseTask;
                    if (!string.IsNullOrWhiteSpace(response) && 
                        !response.Contains("error", StringComparison.OrdinalIgnoreCase) && 
                        !response.Contains("Not Found", StringComparison.OrdinalIgnoreCase))
                    {
                        Logger.Info($"Vendor found via API: {response}");
                        return response.Trim();
                    }
                }
            }
            catch
            {
                // API failed, stay as unknown
            }

            // If online API fails, stay as "Unknown" (local OUI was already checked during scan)
            return "Unknown";
        }

        /// <summary>
        /// Gets vendor from local OUI database (not used in SupabaseSyncService).
        /// This is here for reference - the actual local lookup happens during scan.
        /// </summary>
        private string GetVendorFromLocalDatabase(string macAddress)
        {
            // Clean MAC address and extract OUI (first 6 characters)
            string cleanMac = macAddress.Replace(":", "").Replace("-", "").ToUpper();
            if (cleanMac.Length < 6)
            {
                return "Unknown";
            }

            string oui = cleanMac.Substring(0, 6);

            // Common OUI database
            var ouiDatabase = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // Major vendors
                { "005056", "VMware" }, { "000C29", "VMware" }, { "080027", "VirtualBox" },
                { "00155D", "Hyper-V" }, { "001DD8", "Microsoft" },
                { "A4C361", "Apple" }, { "BC9FEF", "Apple" }, { "64B9E8", "Apple" },
                { "1CBDB9", "Samsung" }, { "E4121D", "Samsung" }, { "DC7144", "Samsung" },
                { "00AA00", "Intel" }, { "00AA01", "Intel" }, { "7085C2", "Intel" },
                { "00E04C", "Realtek" }, { "525400", "Realtek" }, { "74DA38", "Realtek" },
                { "001C23", "Dell" }, { "002170", "Dell" }, { "78F7BE", "Dell" },
                { "001438", "HP" }, { "9C8E99", "HP" }, { "C08995", "HP" },
                { "F4EC38", "TP-Link" }, { "D82686", "TP-Link" }, { "C46E1F", "TP-Link" },
                { "2CF05D", "ASUS" }, { "AC220B", "ASUS" }, { "7054D5", "ASUS" },
                { "00000C", "Cisco" }, { "68BDAB", "Cisco" }, { "001D71", "Cisco" },
                { "0024B2", "Netgear" }, { "A021B7", "Netgear" }, { "4C9EFF", "Netgear" },
                { "000D88", "D-Link" }, { "B8A386", "D-Link" }, { "1C7EE5", "D-Link" },
                { "00E00C", "Huawei" }, { "C0A0BB", "Huawei" }, { "4C549F", "Huawei" },
                { "64B473", "Xiaomi" }, { "F8A45F", "Xiaomi" }, { "34CE00", "Xiaomi" },
                { "54C0EB", "Google" }, { "3C5AB4", "Google" }, { "F4F5D8", "Google" },
            };

            return ouiDatabase.TryGetValue(oui, out var vendor) ? vendor : "Unknown";
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

