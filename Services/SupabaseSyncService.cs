using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models.Database;
using NLog;

namespace Dorothy.Services
{
    public class SupabaseSyncService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly DatabaseService _databaseService;
        private readonly SemaphoreSlim _clientLock = new(1, 1);
        private SeacureApiClient? _apiClient;

        public event Action<string>? ProgressChanged;

        public SupabaseSyncService(DatabaseService databaseService)
        {
            _databaseService = databaseService;
        }

        public bool IsConfigured => SeacureConfig.IsConfigured;

        public void Initialize(string? _unusedUrl = null, string? _unusedKey = null)
        {
        }

        private void ReportProgress(string message)
        {
            Logger.Info(message);
            ProgressChanged?.Invoke(message);
        }

        private async Task<SeacureApiClient?> GetOrCreateClientAsync()
        {
            if (!SeacureConfig.IsConfigured) return null;

            if (_apiClient != null) return _apiClient;

            await _clientLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_apiClient != null) return _apiClient;
                try
                {
                    var client = new SeacureApiClient(
                        SeacureConfig.ApiUrl,
                        SeacureConfig.Email!,
                        SeacureConfig.Password!);
                    await client.LoginAsync().ConfigureAwait(false);
                    _apiClient = client;
                    return _apiClient;
                }
                catch (Exception ex)
                {
                    Logger.Info($"Sync skipped — endpoint unavailable ({ex.GetType().Name})");
                    return null;
                }
            }
            finally
            {
                _clientLock.Release();
            }
        }

        public async Task<SyncResult> SyncAsync(string? projectName = null, List<long>? selectedIds = null)
        {
            if (!SeacureConfig.IsConfigured)
            {
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
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

                var client = await GetOrCreateClientAsync().ConfigureAwait(false);
                if (client == null)
                {
                    return new SyncResult
                    {
                        Success = false,
                        Message = "Sync skipped — endpoint unavailable",
                        SyncedCount = 0
                    };
                }

                var payload = new
                {
                    logs = unsyncedLogs.Select(log => new
                    {
                        project_name = projectName ?? log.ProjectName,
                        attack_type = log.AttackType,
                        protocol = log.Protocol,
                        source_ip = log.SourceIp,
                        source_mac = log.SourceMac,
                        target_ip = log.TargetIp,
                        target_mac = log.TargetMac,
                        target_port = log.TargetPort,
                        target_rate_mbps = log.TargetRateMbps,
                        packets_sent = log.PacketsSent,
                        duration_seconds = log.DurationSeconds > 0
                            ? log.DurationSeconds
                            : (int)(log.StopTime - log.StartTime).TotalSeconds,
                        start_time = log.StartTime,
                        stop_time = log.StopTime,
                        created_at = log.CreatedAt,
                        hardware_id = log.HardwareId?.ToUpperInvariant(),
                        machine_name = log.MachineName,
                        username = log.Username,
                        user_id = log.UserId,
                        local_id = log.Id
                    }).ToArray()
                };

                using var resp = await client.PostJsonAsync("api/sync/attack-logs", payload).ConfigureAwait(false);

                if (!resp.IsSuccessStatusCode)
                {
                    Logger.Info($"Sync skipped — endpoint unavailable ({(int)resp.StatusCode})");
                    return new SyncResult
                    {
                        Success = false,
                        Message = "Sync skipped — endpoint unavailable",
                        SyncedCount = 0
                    };
                }

                var syncedIds = unsyncedLogs.Select(l => l.Id).ToList();
                await _databaseService.MarkAsSyncedAsync(syncedIds, DateTime.UtcNow);

                return new SyncResult
                {
                    Success = true,
                    Message = $"Successfully synced {syncedIds.Count} log(s).",
                    SyncedCount = syncedIds.Count
                };
            }
            catch (HttpRequestException ex)
            {
                Logger.Info($"Sync skipped — endpoint unavailable ({ex.GetType().Name})");
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
                    SyncedCount = 0
                };
            }
            catch (TaskCanceledException)
            {
                Logger.Info("Sync skipped — endpoint unavailable (timeout)");
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
                    SyncedCount = 0
                };
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Attack-log sync failed unexpectedly");
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
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
            if (!SeacureConfig.IsConfigured)
            {
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
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

                if (enhanceData)
                {
                    ReportProgress($"Enhancing {unsyncedAssets.Count} asset(s) in parallel...");

                    int batchSize = 10;
                    var semaphore = new SemaphoreSlim(batchSize);
                    var enhancementTasks = unsyncedAssets.Select(async (asset, index) =>
                    {
                        await semaphore.WaitAsync();
                        try
                        {
                            if (string.IsNullOrEmpty(asset.HostName) || asset.HostName == "Unknown")
                            {
                                asset.HostName = await ResolveHostnameAsync(asset.HostIp);
                            }

                            if ((string.IsNullOrEmpty(asset.Vendor) || asset.Vendor == "Unknown") &&
                                !string.IsNullOrEmpty(asset.MacAddress) &&
                                asset.MacAddress != "Unknown")
                            {
                                asset.Vendor = GetVendorFromLocalDatabase(asset.MacAddress);
                            }

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

                var client = await GetOrCreateClientAsync().ConfigureAwait(false);
                if (client == null)
                {
                    return new SyncResult
                    {
                        Success = false,
                        Message = "Sync skipped — endpoint unavailable",
                        SyncedCount = 0
                    };
                }

                ReportProgress($"Syncing {unsyncedAssets.Count} asset(s) to cloud...");

                var assetPayloads = new List<object>(unsyncedAssets.Count);
                var allPortIdsByAsset = new Dictionary<long, List<long>>();

                foreach (var asset in unsyncedAssets)
                {
                    var hostName = string.IsNullOrWhiteSpace(asset.HostName) || asset.HostName == "Unknown"
                        ? null : asset.HostName;
                    var vendor = string.IsNullOrWhiteSpace(asset.Vendor) || asset.Vendor == "Unknown"
                        ? null : asset.Vendor;
                    var macAddress = string.IsNullOrWhiteSpace(asset.MacAddress) || asset.MacAddress == "Unknown"
                        ? null : asset.MacAddress;

                    var allPorts = await _databaseService.GetPortsByHostIpAsync(asset.HostIp);
                    allPortIdsByAsset[asset.Id] = allPorts.Select(p => p.Id).ToList();

                    var portsSummary = allPorts.Count > 0
                        ? string.Join(", ", allPorts.OrderBy(p => p.Port).Select(p => $"{p.Port}/{p.Protocol}"))
                        : null;

                    var portPayloads = allPorts.Select(port => new
                    {
                        port = port.Port,
                        protocol = port.Protocol,
                        service = port.Service,
                        banner = port.Banner,
                        severity = "INFO",
                        scan_time = port.ScanTime,
                        project_name = projectName ?? port.ProjectName,
                        created_at = port.CreatedAt,
                        hardware_id = port.HardwareId?.ToUpperInvariant(),
                        machine_name = port.MachineName,
                        username = port.Username,
                        user_id = port.UserId,
                        local_id = port.Id
                    }).ToArray();

                    assetPayloads.Add(new
                    {
                        local_id = asset.Id,
                        host_ip = asset.HostIp,
                        host_name = hostName,
                        mac_address = macAddress,
                        vendor = vendor,
                        is_online = asset.IsOnline,
                        ping_time = asset.PingTime,
                        scan_time = asset.ScanTime,
                        project_name = projectName ?? asset.ProjectName,
                        created_at = asset.CreatedAt,
                        hardware_id = asset.HardwareId?.ToUpperInvariant(),
                        machine_name = asset.MachineName,
                        username = asset.Username,
                        user_id = asset.UserId,
                        ports = portsSummary,
                        port_entries = portPayloads
                    });
                }

                using var resp = await client.PostJsonAsync("api/sync/assets", new { assets = assetPayloads }).ConfigureAwait(false);

                if (!resp.IsSuccessStatusCode)
                {
                    Logger.Info($"Sync skipped — endpoint unavailable ({(int)resp.StatusCode})");
                    return new SyncResult
                    {
                        Success = false,
                        Message = "Sync skipped — endpoint unavailable",
                        SyncedCount = 0
                    };
                }

                var syncedAssetIds = unsyncedAssets.Select(a => a.Id).ToList();
                await _databaseService.MarkAssetsAsSyncedAsync(syncedAssetIds, DateTime.UtcNow);

                var allSyncedPortIds = allPortIdsByAsset.Values.SelectMany(ids => ids).Distinct().ToList();
                if (allSyncedPortIds.Count > 0)
                {
                    await _databaseService.MarkPortsAsSyncedAsync(allSyncedPortIds, DateTime.UtcNow);
                }

                return new SyncResult
                {
                    Success = true,
                    Message = $"Successfully synced {syncedAssetIds.Count} asset(s).",
                    SyncedCount = syncedAssetIds.Count
                };
            }
            catch (HttpRequestException ex)
            {
                Logger.Info($"Sync skipped — endpoint unavailable ({ex.GetType().Name})");
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
                    SyncedCount = 0
                };
            }
            catch (TaskCanceledException)
            {
                Logger.Info("Sync skipped — endpoint unavailable (timeout)");
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
                    SyncedCount = 0
                };
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Asset sync failed unexpectedly");
                return new SyncResult
                {
                    Success = false,
                    Message = "Sync skipped — endpoint unavailable",
                    SyncedCount = 0
                };
            }
        }

        public async Task<int> GetPendingAssetsCountAsync()
        {
            return await _databaseService.GetUnsyncedAssetsCountAsync();
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
                                    if (line.Contains("<00>") && bestName == null) bestName = name;
                                    else if (line.Contains("<20>") && bestName == null) bestName = name;
                                    else if (line.Contains("<03>") && bestName == null) bestName = name;
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
    }

    public class SyncResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public int SyncedCount { get; set; }
        public List<string> Errors { get; set; } = new();
    }
}
