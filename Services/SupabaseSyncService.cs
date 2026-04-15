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
        private static readonly HttpClient _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

        public event Action<string>? ProgressChanged;

        public SupabaseSyncService(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public bool IsConfigured => _supabaseClient != null;

        public Client? GetSupabaseClient() => _supabaseClient;

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

                        var duration = (log.StopTime - log.StartTime).TotalSeconds;

                        var supabaseEntry = new AttackLogEntry
                        {

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
                            Synced = true,
                            CreatedAt = log.CreatedAt,
                            HardwareId = log.HardwareId?.ToUpperInvariant(),
                            MachineName = log.MachineName,
                            Username = log.Username,
                            UserId = log.UserId

                        };

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

                        string errorMessage = ex.Message;
                        if (ex.Message.Contains("row-level security policy", StringComparison.OrdinalIgnoreCase) ||
                            ex.Message.Contains("42501", StringComparison.OrdinalIgnoreCase))
                        {
                            errorMessage = "RLS policy violation - Check Supabase RLS policies allow inserts with anon key, or configure authentication";
                        }

                        errors.Add($"Log {log.Id}: {errorMessage}");
                    }
                }

                if (syncedIds.Count > 0)
                {
                    await _databaseService.MarkAsSyncedAsync(syncedIds, DateTime.UtcNow);
                }

                var rlsErrors = errors.Where(e => e.Contains("RLS policy violation", StringComparison.OrdinalIgnoreCase)).ToList();
                var otherErrors = errors.Where(e => !e.Contains("RLS policy violation", StringComparison.OrdinalIgnoreCase)).ToList();

                string message;
                if (syncedCount == unsyncedLogs.Count)
                {
                    message = $"Successfully synced {syncedCount} log(s).";
                }
                else
                {
                    var errorSummary = new List<string>();
                    if (rlsErrors.Count > 0)
                    {
                        errorSummary.Add($"{rlsErrors.Count} RLS policy violation(s) - Check Supabase RLS policies to allow inserts");
                    }
                    if (otherErrors.Count > 0)
                    {
                        errorSummary.Add(string.Join("; ", otherErrors.Take(3)));
                    }
                    message = $"Synced {syncedCount} of {unsyncedLogs.Count} log(s). {(errorSummary.Count > 0 ? string.Join(". ", errorSummary) : "")}";
                }

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

                if (enhanceData)
                {
                    ReportProgress($"Enhancing {unsyncedAssets.Count} asset(s) in parallel...");

                    int batchSize = 10;
                    var semaphore = new System.Threading.SemaphoreSlim(batchSize);
                    var enhancementTasks = unsyncedAssets.Select(async (asset, index) =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {

                            var hostnameTask = Task.FromResult(asset.HostName);
                            var vendorTask = Task.FromResult(asset.Vendor);

                            if (string.IsNullOrEmpty(asset.HostName) || asset.HostName == "Unknown")
                            {
                                hostnameTask = ResolveHostnameAsync(asset.HostIp);
                            }

                            if ((string.IsNullOrEmpty(asset.Vendor) || asset.Vendor == "Unknown") &&
                                !string.IsNullOrEmpty(asset.MacAddress) &&
                                asset.MacAddress != "Unknown")
                            {

                                var localVendor = GetVendorFromLocalDatabase(asset.MacAddress);
                                vendorTask = Task.FromResult(localVendor);
                            }
                            else
                            {
                            }

                            await Task.WhenAll(hostnameTask, vendorTask);

                            asset.HostName = await hostnameTask;
                            asset.Vendor = await vendorTask;

                            if ((index + 1) % 10 == 0)
                            {
                                ReportProgress($"Enhanced {index + 1}/{unsyncedAssets.Count} asset(s)...");
                            }
                        }
                        catch
                        {

                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    });

                    await Task.WhenAll(enhancementTasks);

                    ReportProgress($"Saving enhanced data to local database...");
                    var updateTasks = unsyncedAssets.Where(asset =>
                        (!string.IsNullOrEmpty(asset.Vendor) && asset.Vendor != "Unknown") ||
                        (!string.IsNullOrEmpty(asset.HostName) && asset.HostName != "Unknown"))
                        .Select(async asset =>
                        {
                            try
                            {
                                await _databaseService.UpdateAssetVendorAndHostnameAsync(
                                    asset.Id,
                                    asset.Vendor,
                                    asset.HostName);
                            }
                            catch
                            {

                            }
                        });
                    await Task.WhenAll(updateTasks);

                    ReportProgress($"Enhancement complete. Syncing to cloud...");
                }

                ReportProgress($"Syncing {unsyncedAssets.Count} asset(s) to cloud...");

                int syncBatchSize = 5;
                var syncSemaphore = new System.Threading.SemaphoreSlim(syncBatchSize);
                var syncLock = new object();

                var syncTasks = unsyncedAssets.Select(async (asset, index) =>
                {
                    await syncSemaphore.WaitAsync();
                    try
                    {
                        if ((index + 1) % 10 == 0)
                        {
                            ReportProgress($"Syncing {index + 1}/{unsyncedAssets.Count} asset(s)...");
                        }

                        var hostName = asset.HostName;
                        if (string.IsNullOrWhiteSpace(hostName) || hostName == "Unknown")
                        {
                            hostName = null;
                        }

                        var vendor = asset.Vendor;
                        if (string.IsNullOrWhiteSpace(vendor) || vendor == "Unknown")
                        {
                            vendor = null;
                        }

                        var macAddress = asset.MacAddress;
                        if (string.IsNullOrWhiteSpace(macAddress) || macAddress == "Unknown")
                        {
                            macAddress = null;
                        }

                        long supabaseAssetId = 0;
                        try
                        {
                            var existingAsset = await _supabaseClient
                                .From<AssetEntry>()
                                .Select("id")
                                .Where(x => x.HostIp == asset.HostIp)
                                .Limit(1)
                                .Get();

                            if (existingAsset != null && existingAsset.Models != null && existingAsset.Models.Count > 0)
                            {

                                supabaseAssetId = existingAsset.Models[0].Id;

                                await _supabaseClient
                                    .From<AssetEntry>()
                                    .Where(x => x.Id == supabaseAssetId)
                                    .Set(x => x.HostName, hostName)
                                    .Set(x => x.MacAddress, macAddress)
                                    .Set(x => x.Vendor, vendor)
                                    .Set(x => x.IsOnline, asset.IsOnline)
                                    .Set(x => x.PingTime, asset.PingTime)
                                    .Set(x => x.ScanTime, asset.ScanTime)
                                    .Set(x => x.ProjectName, projectName ?? asset.ProjectName)
                                    .Update();
                            }
                        }
                        catch
                        {

                        }

                        if (supabaseAssetId == 0)
                        {

                        var supabaseAsset = new AssetEntry
                        {
                            HostIp = asset.HostIp,
                                HostName = hostName,
                                MacAddress = macAddress,
                                Vendor = vendor,
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

                        supabaseAsset.SyncedAt = null;

                        var response = await _supabaseClient
                            .From<AssetEntry>()
                            .Insert(supabaseAsset);

                        if (response != null && response.Models != null && response.Models.Count > 0)
                            {
                                supabaseAssetId = response.Models[0].Id;
                            }
                        }

                        if (supabaseAssetId > 0)
                        {

                            try
                            {
                                var allPorts = await _databaseService.GetPortsByHostIpAsync(asset.HostIp);
                                if (allPorts.Count > 0)
                                {
                                    var portSyncedIds = new List<long>();
                                    foreach (var port in allPorts)
                                    {
                                        try
                                        {
                                            var supabasePort = new PortEntry
                                            {
                                                HostId = supabaseAssetId,
                                                Port = port.Port,
                                                Protocol = port.Protocol,
                                                Service = port.Service,
                                                Banner = port.Banner,
                                                Severity = "INFO",
                                                ScanTime = port.ScanTime,
                                                ProjectName = projectName ?? port.ProjectName,
                                                Synced = true,
                                                CreatedAt = port.CreatedAt,
                                                HardwareId = port.HardwareId?.ToUpperInvariant(),
                                                MachineName = port.MachineName,
                                                Username = port.Username,
                                                UserId = port.UserId
                                            };

                                            supabasePort.SyncedAt = null;

                                            try
                                            {
                                                var existingPort = await _supabaseClient
                                                    .From<PortEntry>()
                                                    .Select("id")
                                                    .Where(x => x.HostId == supabaseAssetId && x.Port == port.Port && x.Protocol == port.Protocol)
                                                    .Limit(1)
                                                    .Get();

                                                if (existingPort != null && existingPort.Models != null && existingPort.Models.Count > 0)
                                                {

                                                    await _supabaseClient
                                                        .From<PortEntry>()
                                                        .Where(x => x.Id == existingPort.Models[0].Id)
                                                        .Set(x => x.HostId, supabaseAssetId)
                                                        .Set(x => x.Service, port.Service)
                                                        .Set(x => x.Banner, port.Banner)
                                                        .Set(x => x.ScanTime, port.ScanTime)
                                                        .Set(x => x.ProjectName, projectName ?? port.ProjectName)
                                                        .Update();

                                                    portSyncedIds.Add(port.Id);
                                                }
                                                else
                                                {

                                                    var portResponse = await _supabaseClient
                                                        .From<PortEntry>()
                                                        .Insert(supabasePort);

                                                    if (portResponse != null && portResponse.Models != null && portResponse.Models.Count > 0)
                                                    {
                                                        portSyncedIds.Add(port.Id);
                                                    }
                                                }
                                            }
                                            catch
                                            {

                                                try
                                                {
                                                    var portResponse = await _supabaseClient
                                                        .From<PortEntry>()
                                                        .Insert(supabasePort);

                                                    if (portResponse != null && portResponse.Models != null && portResponse.Models.Count > 0)
                                                    {
                                                        portSyncedIds.Add(port.Id);
                                                    }
                                                }
                                                catch
                                                {

                                                    Logger.Warn($"Port {port.Port}/{port.Protocol} for {port.HostIp} might already exist in Supabase");
                                                }
                                            }
                                        }
                                        catch (Exception portEx)
                                        {
                                            Logger.Error(portEx, $"Failed to sync port {port.Port} for asset {asset.HostIp}");

                                        }
                                    }

                                    if (portSyncedIds.Count > 0)
                                    {
                                        await _databaseService.MarkPortsAsSyncedAsync(portSyncedIds, DateTime.UtcNow);
                                        Logger.Info($"Synced {portSyncedIds.Count} port(s) for asset {asset.HostIp} to Supabase ports table (separate from assets table)");
                                    }

                                    var allPortIds = allPorts.Select(p => p.Id).ToList();
                                    if (allPortIds.Count > portSyncedIds.Count)
                                    {
                                        var alreadySyncedIds = allPortIds.Except(portSyncedIds).ToList();
                                        if (alreadySyncedIds.Count > 0)
                                        {
                                            await _databaseService.MarkPortsAsSyncedAsync(alreadySyncedIds, DateTime.UtcNow);
                                            Logger.Info($"Marked {alreadySyncedIds.Count} existing port(s) as synced for asset {asset.HostIp}");
                                        }
                                    }

                                    try
                                    {
                                        var portsOnly = string.Join(", ", allPorts.OrderBy(p => p.Port).Select(p => $"{p.Port}/{p.Protocol}"));

                                        await _supabaseClient
                                            .From<AssetEntry>()
                                            .Where(x => x.Id == supabaseAssetId)
                                            .Set(x => x.Ports, portsOnly)
                                            .Update();

                                        Logger.Info($"Updated assets.ports column for {asset.HostIp} with port numbers only (no banners): {portsOnly}");
                                    }
                                    catch (Exception portsUpdateEx)
                                    {
                                        Logger.Error(portsUpdateEx, $"Failed to update assets.ports column for {asset.HostIp}");

                                    }
                                }
                            }
                            catch (Exception portSyncEx)
                            {
                                Logger.Error(portSyncEx, $"Failed to sync ports for asset {asset.HostIp}");

                            }

                            lock (syncLock)
                        {
                            syncedIds.Add(asset.Id);
                            syncedCount++;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, $"Failed to sync asset {asset.Id}");

                        string errorMessage = ex.Message;
                        if (ex.Message.Contains("row-level security policy", StringComparison.OrdinalIgnoreCase) ||
                            ex.Message.Contains("42501", StringComparison.OrdinalIgnoreCase))
                        {
                            errorMessage = "RLS policy violation - Check Supabase RLS policies allow inserts with anon key, or configure authentication";
                        }

                        lock (syncLock)
                        {
                            errors.Add($"Asset {asset.Id}: {errorMessage}");
                        }
                    }
                    finally
                    {
                        syncSemaphore.Release();
                    }
                });

                await Task.WhenAll(syncTasks);

                if (syncedIds.Count > 0)
                {
                    await _databaseService.MarkAssetsAsSyncedAsync(syncedIds, DateTime.UtcNow);
                }

                var rlsErrors = errors.Where(e => e.Contains("RLS policy violation", StringComparison.OrdinalIgnoreCase)).ToList();
                var otherErrors = errors.Where(e => !e.Contains("RLS policy violation", StringComparison.OrdinalIgnoreCase)).ToList();

                string message;
                if (syncedCount == unsyncedAssets.Count)
                {
                    message = $"Successfully synced {syncedCount} asset(s).";
                }
                else
                {
                    var errorSummary = new List<string>();
                    if (rlsErrors.Count > 0)
                    {
                        errorSummary.Add($"{rlsErrors.Count} RLS policy violation(s) - Check Supabase RLS policies to allow inserts");
                    }
                    if (otherErrors.Count > 0)
                    {
                        errorSummary.Add(string.Join("; ", otherErrors.Take(3)));
                    }
                    message = $"Synced {syncedCount} of {unsyncedAssets.Count} asset(s). {(errorSummary.Count > 0 ? string.Join(". ", errorSummary) : "")}";
                }

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

        public async Task<int> GetPendingReachabilityTestsCountAsync()
        {
            return await _databaseService.GetUnsyncedReachabilityTestsCountAsync();
        }

        private async Task<string> ResolveHostnameAsync(string ipAddress)
        {

            try
            {
                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "nbtstat",
                        Arguments = $"-A {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var timeoutTask = Task.Delay(3000);
                var completed = await Task.WhenAny(outputTask, timeoutTask);

                if (completed == outputTask)
                {
                    var output = await outputTask;
                    await process.WaitForExitAsync();

                    var lines = output.Split('\n');
                    string? bestName = null;

                    foreach (var line in lines)
                    {

                        if (line.Contains("<00>") || line.Contains("<20>") || line.Contains("<03>"))
                        {
                            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 1)
                            {
                                var name = parts[0].Trim();
                                if (!string.IsNullOrWhiteSpace(name) &&
                                    !name.Equals("Name", StringComparison.OrdinalIgnoreCase) &&
                                    !name.Equals("---", StringComparison.OrdinalIgnoreCase) &&
                                    !name.StartsWith("_", StringComparison.OrdinalIgnoreCase))
                                {

                                    if (line.Contains("<00>") && bestName == null)
                                    {
                                        bestName = name;
                                    }

                                    else if (line.Contains("<20>") && bestName == null)
                                    {
                                        bestName = name;
                                    }

                                    else if (line.Contains("<03>") && bestName == null)
                                    {
                                        bestName = name;
                                    }
                                }
                            }
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(bestName))
                    {

                        bestName = bestName.Trim();

                        while (bestName.Length > 0 && (bestName[bestName.Length - 1] == ' ' ||
                               bestName[bestName.Length - 1] < 32))
                        {
                            bestName = bestName.Substring(0, bestName.Length - 1);
                        }
                        if (!string.IsNullOrWhiteSpace(bestName))
                        {
                            return bestName;
                        }
                    }
                }
                else
                {
                    try { process.Kill(); } catch { }
                }
            }
            catch
            {

            }

            return "Unknown";
        }

        private string GetVendorFromLocalDatabase(string macAddress)
        {

            string cleanMac = macAddress.Replace(":", "").Replace("-", "").ToUpper();
            if (cleanMac.Length < 6)
            {
                return "Unknown";
            }

            string oui = cleanMac.Substring(0, 6);

            var ouiDatabase = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {

                { "005056", "VMware" },
                { "000C29", "VMware" },
                { "000569", "VMware" },
                { "080027", "VirtualBox" },
                { "0A0027", "VirtualBox" },
                { "00155D", "Hyper-V" },
                { "001DD8", "Microsoft" },

                { "0010F3", "Nexans" },
                { "F8A2CF", "Unknown" },
                { "98E7F4", "Wistron Neweb" },
                { "04D9F5", "MSI" },
                { "3C7C3F", "LG Electronics" },
                { "F8E43B", "Hon Hai Precision" },
                { "305A3A", "AzureWave Technology" },
                { "50EBF6", "Lite-On Technology" },
                { "B0383B", "Hon Hai Precision" },
                { "C8B223", "D-Link" },
                { "E86A64", "TP-Link" },

                { "A4C361", "Apple" },
                { "BC9FEF", "Apple" },
                { "64B9E8", "Apple" },
                { "DCBF54", "Apple" },
                { "787B8A", "Apple" },
                { "10DD01", "Apple" },
                { "F4F15A", "Apple" },
                { "6C4D73", "Apple" },
                { "9027E4", "Apple" },
                { "CCF9E8", "Apple" },
                { "F02475", "Apple" },
                { "ACBC32", "Apple" },
                { "3C2EF9", "Apple" },
                { "AC7F3E", "Apple" },
                { "F81EDF", "Apple" },
                { "04489A", "Apple" },
                { "DC2B2A", "Apple" },
                { "3451C9", "Apple" },

                { "1CBDB9", "Samsung" },
                { "E4121D", "Samsung" },
                { "DC7144", "Samsung" },
                { "A81B5A", "Samsung" },
                { "F4099B", "Samsung" },
                { "48DB50", "Samsung" },
                { "BC8385", "Samsung" },
                { "3C7A8A", "Samsung" },
                { "086698", "Samsung" },
                { "30F769", "Samsung" },
                { "001632", "Samsung" },
                { "0000F0", "Samsung" },
                { "002399", "Samsung" },
                { "002566", "Samsung" },
                { "C89E43", "Samsung" },
                { "588694", "Samsung" },
                { "58869C", "Samsung" },
                { "B0386C", "Samsung" },
                { "30CDA7", "Samsung" },
                { "988389", "Samsung" },

                { "00AA00", "Intel" },
                { "00AA01", "Intel" },
                { "00AA02", "Intel" },
                { "00D0B7", "Intel" },
                { "7085C2", "Intel" },
                { "A4D1D2", "Intel" },
                { "DC53D4", "Intel" },
                { "84A9C4", "Intel" },
                { "48F17F", "Intel" },
                { "00C2C6", "Intel" },
                { "001B21", "Intel" },
                { "F0DEEF", "Intel" },
                { "941882", "Intel" },
                { "685D43", "Intel" },
                { "B4FCC4", "Intel" },

                { "00E04C", "Realtek" },
                { "525400", "Realtek" },
                { "74DA38", "Realtek" },
                { "1C39BB", "Realtek" },
                { "10C37B", "Realtek" },
                { "98DED0", "Realtek" },
                { "801F02", "Realtek" },
                { "30F9ED", "Realtek" },

                { "001C23", "Dell" },
                { "002170", "Dell" },
                { "00215D", "Dell" },
                { "001E4F", "Dell" },
                { "78F7BE", "Dell" },
                { "D4BED9", "Dell" },
                { "182033", "Dell" },
                { "F04DA2", "Dell" },
                { "609C9F", "Dell" },
                { "D89695", "Dell" },
                { "241DD5", "Dell" },
                { "4CD717", "Dell" },
                { "B07B25", "Dell" },

                { "001438", "HP" },
                { "002324", "HP" },
                { "C08995", "HP" },
                { "9C8E99", "HP" },
                { "106FD0", "HP" },
                { "2C768A", "HP" },
                { "6C3BE6", "HP" },
                { "489A8A", "HP" },
                { "009C02", "HP" },
                { "001E0B", "HP" },
                { "5C60BA", "HP" },
                { "E4E749", "HP" },

                { "60F677", "Lenovo" },
                { "5065F3", "Lenovo" },
                { "1C69A5", "Lenovo" },
                { "74E543", "Lenovo" },
                { "C82A14", "Lenovo" },
                { "40F2E9", "Lenovo" },
                { "30C9AB", "Lenovo" },
                { "9CBC36", "Lenovo" },
                { "A01D48", "Lenovo" },

                { "F4EC38", "TP-Link" },
                { "D82686", "TP-Link" },
                { "C46E1F", "TP-Link" },
                { "A42BB0", "TP-Link" },
                { "0CE150", "TP-Link" },
                { "50D4F7", "TP-Link" },
                { "ECF196", "TP-Link" },
                { "10FEED", "TP-Link" },
                { "A04606", "TP-Link" },
                { "1C3BF3", "TP-Link" },

                { "2CF05D", "ASUS" },
                { "1C87EC", "ASUS" },
                { "AC220B", "ASUS" },
                { "04927A", "ASUS" },
                { "7054D5", "ASUS" },
                { "38D547", "ASUS" },
                { "F46D04", "ASUS" },
                { "F832E4", "ASUS" },
                { "D45D64", "ASUS" },
                { "581122", "ASUS" },
                { "7C10C9", "ASUS" },
                { "6045CB", "ASUS" },
                { "BCFCE7", "ASUS" },
                { "FC3497", "ASUS" },
                { "74D02B", "ASUS" },
                { "B06EBF", "ASUS" },
                { "A85E45", "ASUS" },

                { "00000C", "Cisco" },
                { "00000D", "Cisco" },
                { "00000E", "Cisco" },
                { "00000F", "Cisco" },
                { "000102", "Cisco" },
                { "0001C7", "Cisco" },
                { "0001C9", "Cisco" },
                { "0001CB", "Cisco" },
                { "68BDAB", "Cisco" },
                { "001D71", "Cisco" },
                { "0021A0", "Cisco" },

                { "0024B2", "Netgear" },
                { "000FB5", "Netgear" },
                { "001B2F", "Netgear" },
                { "001E2A", "Netgear" },
                { "A021B7", "Netgear" },
                { "4C9EFF", "Netgear" },
                { "E091F5", "Netgear" },
                { "3490EA", "Netgear" },
                { "288088", "Netgear" },

                { "000D88", "D-Link" },
                { "001195", "D-Link" },
                { "001346", "D-Link" },
                { "0015E9", "D-Link" },
                { "001CF0", "D-Link" },
                { "0022B0", "D-Link" },
                { "B8A386", "D-Link" },
                { "1C7EE5", "D-Link" },
                { "CCB255", "D-Link" },

                { "00E00C", "Huawei" },
                { "0018E7", "Huawei" },
                { "00259E", "Huawei" },
                { "002692", "Huawei" },
                { "C0A0BB", "Huawei" },
                { "4C549F", "Huawei" },
                { "D4A9E8", "Huawei" },
                { "30D1DC", "Huawei" },
                { "786EB8", "Huawei" },

                { "64B473", "Xiaomi" },
                { "F8A45F", "Xiaomi" },
                { "783A84", "Xiaomi" },
                { "50EC50", "Xiaomi" },
                { "F0B429", "Xiaomi" },
                { "34CE00", "Xiaomi" },
                { "D4619D", "Xiaomi" },
                { "B0E235", "Xiaomi" },
                { "5C63BF", "Xiaomi" },

                { "54C0EB", "Google" },
                { "54EAA8", "Google" },
                { "3C5AB4", "Google" },
                { "94EB2C", "Google" },
                { "C058EC", "Google" },
                { "F4F5D8", "Google" },

                { "74C246", "Amazon" },
                { "ACF85C", "Amazon" },
                { "84D6D0", "Amazon" },
                { "74C630", "Amazon" },
                { "6854FD", "Amazon" },
                { "0C47C9", "Amazon" },

                { "001018", "Broadcom" },
                { "002618", "Broadcom" },
                { "00D0C0", "Broadcom" },
                { "0090F8", "Broadcom" },
                { "B49691", "Broadcom" },
                { "E8B2AC", "Broadcom" },

                { "009065", "Qualcomm" },
                { "B0702D", "Qualcomm" },
                { "C47C8D", "Qualcomm" },
                { "2C5491", "Qualcomm" },
                { "8C15C7", "Qualcomm" },
                { "001DA2", "Qualcomm" },

                { "001D0D", "Sony" },
                { "002076", "Sony" },
                { "00247E", "Sony" },
                { "7C669E", "Sony" },
                { "18F46A", "Sony" },
                { "F8321A", "Sony" },

                { "001C62", "LG" },
                { "001E75", "LG" },
                { "B4B3CF", "LG" },
                { "9C97DC", "LG" },
                { "789ED0", "LG" },
                { "50685D", "LG" },

                { "00139D", "Motorola" },
                { "001ADB", "Motorola" },
                { "9C5CF9", "Motorola" },
                { "0060A1", "Motorola" },
                { "0004E2", "Motorola" },

                { "002129", "Linksys" },
                { "00131A", "Linksys" },
                { "001217", "Linksys" },
                { "000625", "Linksys" },
                { "002275", "Linksys" },

                { "04185A", "Ubiquiti" },
                { "18E829", "Ubiquiti" },
                { "687251", "Ubiquiti" },
                { "24A43C", "Ubiquiti" },
                { "FC0CAB", "Ubiquiti" },

                { "B827EB", "Raspberry Pi" },
                { "DCA632", "Raspberry Pi" },
                { "E45F01", "Raspberry Pi" },

                { "70856F", "ASRock" },

                { "1C697A", "GIGABYTE" },
                { "9C6B00", "GIGABYTE" },

                { "00241D", "MSI" },
                { "448A5B", "MSI" },

                { "705DCC", "EFM Networks" },
                { "6C2408", "LCFC(Hefei) Electronics" },
                { "84BA3B", "Canon" },
                { "00E04D", "INTERNET INITIATIVE JAPAN" },
                { "3498B5", "S1 Corporation" },
                { "00089B", "S1 Corporation" },
                { "9009D0", "Synology" },
                { "D4CA6D", "MikroTik" },
                { "1853E0", "Hanyang Digitech" },

                { "0009E5", "Unknown" },
                { "A0CEC8", "Unknown" },
                { "245EBE", "Unknown" },
                { "000159", "Unknown" },
                { "107B44", "Unknown" },
                { "F8A26D", "Unknown" },
            };

            return ouiDatabase.TryGetValue(oui, out var vendor) ? vendor : "Unknown";
        }

        public async Task<SyncResult> SyncReachabilityTestsAsync(string? projectName = null, List<long>? selectedIds = null)
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
                var unsyncedTests = await _databaseService.GetUnsyncedReachabilityTestsAsync(selectedIds);
                if (unsyncedTests.Count == 0)
                {
                    return new SyncResult
                    {
                        Success = true,
                        Message = "No pending reachability tests to sync.",
                        SyncedCount = 0
                    };
                }

                int syncedCount = 0;
                var errors = new List<string>();
                var syncedIds = new List<long>();

                ReportProgress($"Syncing {unsyncedTests.Count} reachability test(s)...");

                foreach (var test in unsyncedTests)
                {
                    try
                    {

                        var supabaseTest = new ReachabilityTestEntry
                        {
                            ProjectName = projectName ?? test.ProjectName,
                            AnalysisMode = test.AnalysisMode,
                            VantagePointName = test.VantagePointName,
                            SourceNicId = test.SourceNicId,
                            SourceIp = test.SourceIp,
                            TargetNetworkName = test.TargetNetworkName,
                            TargetCidr = test.TargetCidr,
                            BoundaryGatewayIp = test.BoundaryGatewayIp,
                            BoundaryVendor = test.BoundaryVendor,
                            ExternalTestIp = test.ExternalTestIp,
                            Synced = true,
                            CreatedAt = test.CreatedAt,
                            HardwareId = test.HardwareId?.ToUpperInvariant(),
                            MachineName = test.MachineName,
                            Username = test.Username,
                            UserId = test.UserId
                        };

                        supabaseTest.SyncedAt = null;
                        supabaseTest.IsSynced = false;

                        var testResponse = await _supabaseClient
                            .From<ReachabilityTestEntry>()
                            .Insert(supabaseTest);

                        if (testResponse != null && testResponse.Models != null && testResponse.Models.Count > 0)
                        {
                            var supabaseTestId = testResponse.Models[0].Id;

                            try
                            {

                                var icmpResults = await _databaseService.GetReachabilityIcmpResultsAsync(test.Id);
                                if (icmpResults.Count > 0)
                                {
                                    var supabaseIcmpResults = icmpResults.Select(r => new ReachabilityIcmpResultEntry
                                    {
                                        TestId = supabaseTestId,
                                        TargetIp = r.TargetIp,
                                        Role = r.Role,
                                        Reachable = r.Reachable,
                                        Sent = r.Sent,
                                        Received = r.Received,
                                        AvgRttMs = r.AvgRttMs,
                                        CreatedAt = r.CreatedAt
                                    }).ToList();

                                    await _supabaseClient
                                        .From<ReachabilityIcmpResultEntry>()
                                        .Insert(supabaseIcmpResults);
                                }

                                var tcpResults = await _databaseService.GetReachabilityTcpResultsAsync(test.Id);
                                if (tcpResults.Count > 0)
                                {
                                    var supabaseTcpResults = tcpResults.Select(r => new ReachabilityTcpResultEntry
                                    {
                                        TestId = supabaseTestId,
                                        TargetIp = r.TargetIp,
                                        Port = r.Port,
                                        State = r.State,
                                        RttMs = r.RttMs,
                                        ErrorMessage = r.ErrorMessage,
                                        CreatedAt = r.CreatedAt
                                    }).ToList();

                                    await _supabaseClient
                                        .From<ReachabilityTcpResultEntry>()
                                        .Insert(supabaseTcpResults);
                                }

                                var pathHops = await _databaseService.GetReachabilityPathHopsAsync(test.Id);
                                if (pathHops.Count > 0)
                                {
                                    var supabasePathHops = pathHops.Select(r => new ReachabilityPathHopEntry
                                    {
                                        TestId = supabaseTestId,
                                        TargetIp = r.TargetIp,
                                        HopNumber = r.HopNumber,
                                        HopIp = r.HopIp,
                                        RttMs = r.RttMs,
                                        Hostname = r.Hostname,
                                        CreatedAt = r.CreatedAt
                                    }).ToList();

                                    await _supabaseClient
                                        .From<ReachabilityPathHopEntry>()
                                        .Insert(supabasePathHops);
                                }

                                var deeperScans = await _databaseService.GetReachabilityDeeperScansAsync(test.Id);
                                if (deeperScans.Count > 0)
                                {
                                    var supabaseDeeperScans = deeperScans.Select(r => new ReachabilityDeeperScanEntry
                                    {
                                        TestId = supabaseTestId,
                                        TargetIp = r.TargetIp,
                                        PortStates = r.PortStates,
                                        Summary = r.Summary,
                                        CreatedAt = r.CreatedAt
                                    }).ToList();

                                    await _supabaseClient
                                        .From<ReachabilityDeeperScanEntry>()
                                        .Insert(supabaseDeeperScans);
                                }

                                var snmpWalks = await _databaseService.GetReachabilitySnmpWalksAsync(test.Id);
                                if (snmpWalks.Count > 0)
                                {
                                    var supabaseSnmpWalks = snmpWalks.Select(r => new ReachabilitySnmpWalkEntry
                                    {
                                        TestId = supabaseTestId,
                                        TargetIp = r.TargetIp,
                                        Port = r.Port,
                                        Success = r.Success,
                                        SuccessfulCommunity = r.SuccessfulCommunity,
                                        SuccessfulOids = r.SuccessfulOids,
                                        Attempts = r.Attempts,
                                        DurationMs = r.DurationMs,
                                        CreatedAt = r.CreatedAt
                                    }).ToList();

                                    await _supabaseClient
                                        .From<ReachabilitySnmpWalkEntry>()
                                        .Insert(supabaseSnmpWalks);
                                }

                                Logger.Info($"Synced test {test.Id} with {icmpResults.Count} ICMP, {tcpResults.Count} TCP, {pathHops.Count} path hops, {deeperScans.Count} deeper scans, {snmpWalks.Count} SNMP walks");
                            }
                            catch (Exception childEx)
                            {
                                Logger.Error(childEx, $"Failed to sync child records for test {test.Id}");

                            }

                            syncedIds.Add(test.Id);
                            syncedCount++;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, $"Failed to sync reachability test {test.Id}");

                        string errorMessage = ex.Message;
                        if (ex.Message.Contains("row-level security policy", StringComparison.OrdinalIgnoreCase) ||
                            ex.Message.Contains("42501", StringComparison.OrdinalIgnoreCase))
                        {
                            errorMessage = "RLS policy violation - Check Supabase RLS policies allow inserts with anon key";
                        }

                        errors.Add($"Test {test.Id}: {errorMessage}");
                    }
                }

                if (syncedIds.Count > 0)
                {
                    await _databaseService.MarkReachabilityTestsAsSyncedAsync(syncedIds, DateTime.UtcNow);
                }

                var rlsErrors = errors.Where(e => e.Contains("RLS policy violation", StringComparison.OrdinalIgnoreCase)).ToList();
                var otherErrors = errors.Where(e => !e.Contains("RLS policy violation", StringComparison.OrdinalIgnoreCase)).ToList();

                string message;
                if (syncedCount == unsyncedTests.Count)
                {
                    message = $"Successfully synced {syncedCount} reachability test(s).";
                }
                else
                {
                    var errorSummary = new List<string>();
                    if (rlsErrors.Count > 0)
                    {
                        errorSummary.Add($"{rlsErrors.Count} RLS policy violation(s) - Check Supabase RLS policies");
                    }
                    if (otherErrors.Count > 0)
                    {
                        errorSummary.Add(string.Join("; ", otherErrors.Take(3)));
                    }
                    message = $"Synced {syncedCount} of {unsyncedTests.Count} test(s). {(errorSummary.Count > 0 ? string.Join(". ", errorSummary) : "")}";
                }

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
                Logger.Error(ex, "Failed to sync reachability tests with Supabase");
                return new SyncResult
                {
                    Success = false,
                    Message = $"Sync failed: {ex.Message}",
                    SyncedCount = 0
                };
            }
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

