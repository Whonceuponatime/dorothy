using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using NLog;

namespace Dorothy.Services
{

    public class LicenseService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HttpClient PublicHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

        private readonly string _hardwareId;
        private readonly string _whitelistFilePath;
        private readonly string _licenseCacheFilePath;

        public LicenseService()
        {
            _hardwareId = GenerateHardwareId();

            var appDataPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SEACURE(TOOL)");

            if (!System.IO.Directory.Exists(appDataPath))
            {
                System.IO.Directory.CreateDirectory(appDataPath);
            }

            _whitelistFilePath = System.IO.Path.Combine(appDataPath, "license.whitelist");
            _licenseCacheFilePath = System.IO.Path.Combine(appDataPath, "license.cache.json");

            Logger.Info($"Hardware ID: {_hardwareId}");
        }

        public string HardwareId => _hardwareId;

        public async Task<LicenseValidationResult> ValidateLicenseAsync()
        {
            try
            {
                Logger.Info($"[LICENSE] Validating hardware: {_hardwareId}");
                Logger.Info($"[LICENSE] API URL: {SeacureConfig.ApiUrl}");

                try
                {
                    var url = $"{SeacureConfig.ApiUrl.TrimEnd('/')}/api/license/validate?hardware_id={Uri.EscapeDataString(_hardwareId)}";
                    Logger.Info($"[LICENSE] Calling: {url}");

                    var response = await PublicHttp.GetAsync(url).ConfigureAwait(false);
                    var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    Logger.Info($"[LICENSE] Response: {response.StatusCode} — {body}");

                    response.EnsureSuccessStatusCode();
                    using var json = JsonDocument.Parse(body);
                    var isLicensed = json.RootElement.GetProperty("is_licensed").GetBoolean();

                    if (isLicensed)
                    {
                        Logger.Info("[LICENSE] Hardware is licensed — approved");
                        SaveLicenseToCache();
                        return new LicenseValidationResult
                        {
                            IsValid = true,
                            Message = "License validated",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    Logger.Warn("[LICENSE] Hardware not licensed");
                    ClearLicenseCache();
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "Hardware not licensed. Please request a license.",
                        CachedHardwareId = _hardwareId
                    };
                }
                catch (Exception ex) when (ex is HttpRequestException || ex is TaskCanceledException)
                {
                    Logger.Warn($"[LICENSE] Network error, falling back to cache: {ex.Message}");
                    return ValidateLocalCache();
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "[LICENSE] Validation failed");
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"License check failed: {ex.Message}"
                };
            }
        }

        internal LicenseValidationResult ValidateLocalLicense()
        {
            try
            {
                if (!System.IO.File.Exists(_whitelistFilePath))
                {
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "No license whitelist found. Please contact administrator."
                    };
                }

                var whitelistLines = System.IO.File.ReadAllLines(_whitelistFilePath)
                    .Where(line => !string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith("#"))
                    .Select(line => line.Trim())
                    .ToList();

                if (whitelistLines.Count == 0)
                {
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "License whitelist is empty."
                    };
                }

                var isAuthorized = whitelistLines.Contains(_hardwareId, StringComparer.OrdinalIgnoreCase);

                return new LicenseValidationResult
                {
                    IsValid = isAuthorized,
                    Message = isAuthorized
                        ? "License validated successfully"
                        : $"Hardware ID not found in whitelist. Your ID: {_hardwareId}"
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Local license validation error");
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"License file error: {ex.Message}"
                };
                }
        }

        private LicenseValidationResult ValidateLocalCache()
        {
            try
            {
                Logger.Info($"Checking license cache at: {_licenseCacheFilePath}");

                if (!System.IO.File.Exists(_licenseCacheFilePath))
                {
                    Logger.Info("License cache file does not exist");
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "No license cache found. Online validation required for first approval."
                    };
                }

                var jsonContent = System.IO.File.ReadAllText(_licenseCacheFilePath);
                Logger.Debug($"License cache file exists, size: {jsonContent.Length} bytes");

                var cache = JsonSerializer.Deserialize<LicenseCache>(jsonContent);

                if (cache == null)
                {
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "Invalid license cache file."
                    };
                }

                Logger.Debug($"Comparing hardware IDs - Cached: {cache.HardwareId}, Current: {_hardwareId}");
                if (!string.Equals(cache.HardwareId, _hardwareId, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.Warn($"License cache hardware ID mismatch. Cached: {cache.HardwareId}, Current: {_hardwareId}");

                }

                if (string.IsNullOrEmpty(cache.Signature))
                {
                    Logger.Warn("License cache missing signature - may be tampered with");
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "License cache is invalid or tampered with. Online validation required."
                    };
                }

                var signatureData = $"{cache.HardwareId}|{cache.ApprovedAt:O}|SEACURE_LICENSE_SALT_2024";
                string expectedSignature;
                using (var sha256 = SHA256.Create())
                {
                    var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(signatureData));
                    expectedSignature = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();
                }

                if (!string.Equals(cache.Signature, expectedSignature, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.Warn("License cache signature mismatch - cache may be tampered with");
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "License cache signature invalid. Online validation required."
                    };
                }

                Logger.Info($"License validated from cache. Approved: {cache.ApprovedAt:yyyy-MM-dd HH:mm:ss}, Cached Hardware ID: {cache.HardwareId}");
                return new LicenseValidationResult
                {
                    IsValid = true,
                    Message = $"✅ Authorized (cached approval from {cache.ApprovedAt:yyyy-MM-dd})",
                    CachedHardwareId = cache.HardwareId
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error reading license cache");
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"License cache error: {ex.Message}"
                };
            }
        }

        private void SaveLicenseToCache()
        {
            try
            {
                var cache = new LicenseCache
                {
                    HardwareId = _hardwareId,
                    ApprovedAt = DateTime.UtcNow,
                    LastValidatedAt = DateTime.UtcNow
                };

                var signatureData = $"{_hardwareId}|{cache.ApprovedAt:O}|SEACURE_LICENSE_SALT_2024";
                using (var sha256 = SHA256.Create())
                {
                    var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(signatureData));
                    cache.Signature = BitConverter.ToString(hashBytes).Replace("-", "").ToUpperInvariant();
                }

                var jsonContent = JsonSerializer.Serialize(cache, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                System.IO.File.WriteAllText(_licenseCacheFilePath, jsonContent);
                Logger.Info($"License approval saved to local cache: {_licenseCacheFilePath}");
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Failed to save license to cache (non-critical)");

            }
        }

        private void ClearLicenseCache()
        {
            try
            {
                if (System.IO.File.Exists(_licenseCacheFilePath))
                {
                    System.IO.File.Delete(_licenseCacheFilePath);
                    Logger.Info("License cache cleared (server denied authorisation)");
                }
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Failed to clear license cache (non-critical)");
            }
        }

        public bool AddToWhitelist(string? notes = null)
        {
            try
            {
                var lines = new List<string>();

                if (System.IO.File.Exists(_whitelistFilePath))
                {
                    lines = System.IO.File.ReadAllLines(_whitelistFilePath).ToList();
                }

                if (lines.Any(line => line.Trim().Equals(_hardwareId, StringComparison.OrdinalIgnoreCase)))
                {
                    Logger.Info("Hardware ID already in whitelist");
                    return true;
                }

                var entry = string.IsNullOrWhiteSpace(notes)
                    ? _hardwareId
                    : $"{_hardwareId} # {notes}";

                lines.Add(entry);
                System.IO.File.WriteAllLines(_whitelistFilePath, lines);

                Logger.Info($"Hardware ID added to whitelist: {_hardwareId}");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error adding hardware ID to whitelist");
                return false;
            }
        }

        private string GenerateHardwareId()
        {
            var components = new List<string>();

            try
            {

                using (var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var processorId = obj["ProcessorId"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(processorId) && processorId != "To Be Filled By O.E.M.")
                        {
                            components.Add($"CPU:{processorId}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve CPU Processor ID");
            }

            try
            {

                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var serialNumber = obj["SerialNumber"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(serialNumber) && serialNumber != "To Be Filled By O.E.M.")
                        {
                            components.Add($"MB:{serialNumber}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve motherboard serial number");
            }

            try
            {

                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber, MediaType, InterfaceType FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media' OR InterfaceType='IDE' OR InterfaceType='SATA' OR InterfaceType='SCSI' OR InterfaceType='NVMe'"))
                {
                    var diskSerials = new List<string>();
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var serialNumber = obj["SerialNumber"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(serialNumber) &&
                            serialNumber.Trim() != "" &&
                            !serialNumber.Contains("0000") &&
                            serialNumber.Length > 5)
                        {
                            diskSerials.Add(serialNumber.Trim());
                        }
                    }

                    foreach (var serial in diskSerials.OrderBy(s => s))
                    {
                        components.Add($"HDD:{serial}");
                    }

                    if (diskSerials.Count > 0)
                    {
                        Logger.Debug($"Found {diskSerials.Count} hard drive serial(s) for hardware ID generation");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve hard drive serial numbers");
            }

            try
            {

                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var biosSerial = obj["SerialNumber"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(biosSerial) &&
                            biosSerial != "To Be Filled By O.E.M." &&
                            biosSerial.Trim().Length > 3)
                        {
                            components.Add($"BIOS:{biosSerial.Trim()}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve BIOS serial number");
            }

            if (components.Count == 0)
            {
                components.Add(Environment.MachineName);
                components.Add(Environment.UserName);
            }

            var combined = string.Join("|", components);
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToUpper();

                return hashString.Substring(0, Math.Min(32, hashString.Length));
            }
        }
    }

    public class LicenseValidationResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; } = string.Empty;

        public string? CachedHardwareId { get; set; }
    }

    internal class LicenseCache
    {
        public string HardwareId { get; set; } = string.Empty;
        public DateTime ApprovedAt { get; set; }
        public DateTime LastValidatedAt { get; set; }
        public string Signature { get; set; } = string.Empty;
    }
}

