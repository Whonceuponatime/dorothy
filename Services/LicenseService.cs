using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using NLog;

namespace Dorothy.Services
{

    public class LicenseService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HttpClient PublicHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

        // Periodic revalidation: check server every 10 minutes while running.
        // If server reports revoked → fail closed, fire LicenseRevoked.
        private const int RevalidationIntervalMinutes = 10;
        // Offline grace: if server unreachable, trust the cache for up to 24h
        // since last successful validation. Beyond that, fail closed.
        private static readonly TimeSpan OfflineGracePeriod = TimeSpan.FromHours(24);

        private readonly string _hardwareId;
        private readonly string _whitelistFilePath;
        private readonly string _licenseCacheFilePath;

        private DateTime? _lastSuccessfulCheck;
        private DispatcherTimer? _revalidationTimer;
        private int _revalidationInFlight;

        public bool IsLicensed { get; private set; }

        /// <summary>
        /// Fires when the server explicitly revokes (is_licensed=false) OR
        /// when the offline grace period is exceeded. Subscribers should
        /// show a modal and shut the app down.
        /// </summary>
        public event EventHandler? LicenseRevoked;

        // SEACUREDB license server public key. Safe to embed — cannot be
        // used to forge signatures, only verify them. RSA-SHA256 PKCS#1 v1.5.
        private const string LicenseServerPublicKeyPem = @"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5BLYQUX+Ry897qbJNH4f
jRZOYFHwiNJrI6XIHof1W2vEezJzoiAQEmBIoGga88yzn59F0u7N0IVlERXrlBs6
jT8X9YE2ko+Ycp9T6ZvrD3yc7ACL8vUQ8LGSwkTNqUolkJ0DcStoqy6kIMurJyxZ
BALf+Z2hU0RlzDlUL/ip12NxmGNWA8kzq/OchReRWyTMXhrGlUytvPJiF2McoUSc
DKs2yAPET+fgiJXBEttSUso3qkrBJOn7zq2zdFYx9jW2G3REMqoMOOlQQa7JFWOS
GJsRMiRQkcOx73r4+/auzzKfkM29C6oRmojRb1WShAbinZFkAKGfxp7jtsCu8rC/
EwIDAQAB
-----END PUBLIC KEY-----";

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

                    ValidateResponse? resp;
                    try
                    {
                        resp = JsonSerializer.Deserialize<ValidateResponse>(body);
                    }
                    catch (JsonException ex)
                    {
                        Logger.Warn(ex, "[LICENSE] Failed to parse validation response");
                        IsLicensed = false;
                        return new LicenseValidationResult
                        {
                            IsValid = false,
                            Message = "Malformed license response",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    if (resp == null)
                    {
                        Logger.Warn("[LICENSE] Empty response body");
                        IsLicensed = false;
                        return new LicenseValidationResult
                        {
                            IsValid = false,
                            Message = "Empty license response",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Verify RSA-SHA256 signature BEFORE trusting any field.
                    if (!VerifySignature(resp))
                    {
                        Logger.Warn("[LICENSE] Response rejected — invalid signature. Treating as not licensed.");
                        IsLicensed = false;
                        ClearLicenseCache();
                        RaiseLicenseRevoked();
                        return new LicenseValidationResult
                        {
                            IsValid = false,
                            Message = "License response signature invalid",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Response must describe THIS machine.
                    if (!string.Equals(resp.hardware_id, _hardwareId, StringComparison.OrdinalIgnoreCase))
                    {
                        Logger.Warn($"[LICENSE] Hardware ID mismatch: response={resp.hardware_id} local={_hardwareId}");
                        IsLicensed = false;
                        ClearLicenseCache();
                        return new LicenseValidationResult
                        {
                            IsValid = false,
                            Message = "Hardware ID mismatch",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Reject stale responses (replay defense): ±5 minute window.
                    var timestampSkew = DateTime.UtcNow - resp.validated_at.ToUniversalTime();
                    if (timestampSkew > TimeSpan.FromMinutes(5) || timestampSkew < TimeSpan.FromMinutes(-5))
                    {
                        Logger.Warn($"[LICENSE] Response timestamp out of range: {timestampSkew.TotalSeconds:F0}s from now");
                        IsLicensed = false;
                        ClearLicenseCache();
                        return new LicenseValidationResult
                        {
                            IsValid = false,
                            Message = "License response timestamp stale",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    if (resp.is_licensed)
                    {
                        Logger.Info("[LICENSE] Server validated. OK.");
                        IsLicensed = true;
                        _lastSuccessfulCheck = DateTime.UtcNow;
                        SaveLicenseToCache(resp);
                        StartPeriodicRevalidation();
                        return new LicenseValidationResult
                        {
                            IsValid = true,
                            Message = "License validated",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Explicit revocation — fail closed, clear cache, fire event.
                    Logger.Warn("[LICENSE] Server reports license NOT valid. Failing closed.");
                    IsLicensed = false;
                    ClearLicenseCache();
                    RaiseLicenseRevoked();
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "Hardware not licensed. Please request a license.",
                        CachedHardwareId = _hardwareId
                    };
                }
                catch (HttpRequestException ex)
                {
                    Logger.Warn($"[LICENSE] Network error during validation: {ex.Message}");
                    return HandleUnreachableWithGrace();
                }
                catch (TaskCanceledException)
                {
                    Logger.Warn("[LICENSE] Validation timed out");
                    return HandleUnreachableWithGrace();
                }
            }
            catch (Exception ex)
            {
                // Unexpected exceptions must NOT fail open — treat as unreachable + grace check.
                Logger.Error(ex, "[LICENSE] Unexpected validation error");
                return HandleUnreachableWithGrace();
            }
        }

        private LicenseValidationResult HandleUnreachableWithGrace()
        {
            // Cache's own RSA signature is re-verified by TryLoadAndVerifyCache.
            // Old 2.5.0 caches (unsigned by server) fail signature check here and
            // are silently rejected — forcing an online re-validation on first
            // 2.5.1 launch, which is the desired upgrade behavior.
            if (!TryLoadAndVerifyCache(out var cache) || cache == null)
            {
                Logger.Warn("[LICENSE] Server unreachable and no valid signed cache on file. Failing closed.");
                IsLicensed = false;
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = "Server unreachable and no prior approval on file. Please connect to the internet and retry.",
                    CachedHardwareId = _hardwareId
                };
            }

            if (!cache.IsLicensed)
            {
                Logger.Warn("[LICENSE] Cache records a prior revocation. Failing closed.");
                IsLicensed = false;
                ClearLicenseCache();
                RaiseLicenseRevoked();
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = "License previously revoked by the server. Contact support to restore access.",
                    CachedHardwareId = _hardwareId
                };
            }

            var age = DateTime.UtcNow - cache.ValidatedAt.ToUniversalTime();
            if (age > OfflineGracePeriod)
            {
                Logger.Warn($"[LICENSE] Offline for {age.TotalHours:F1} hours — exceeds {OfflineGracePeriod.TotalHours}h grace. Failing closed.");
                IsLicensed = false;
                RaiseLicenseRevoked();
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"Offline for {age.TotalHours:F0} hours — exceeds {OfflineGracePeriod.TotalHours:F0}h grace period. Reconnect to restore access.",
                    CachedHardwareId = _hardwareId
                };
            }

            Logger.Info($"[LICENSE] Server unreachable but signed cache last validated {age.TotalHours:F1}h ago — within grace period, allowing use.");
            IsLicensed = true;
            _lastSuccessfulCheck = cache.ValidatedAt.ToUniversalTime();
            StartPeriodicRevalidation();
            return new LicenseValidationResult
            {
                IsValid = true,
                Message = $"Offline mode — last validated {age.TotalHours:F1}h ago (grace {OfflineGracePeriod.TotalHours:F0}h).",
                CachedHardwareId = _hardwareId
            };
        }

        private void RaiseLicenseRevoked()
        {
            try { LicenseRevoked?.Invoke(this, EventArgs.Empty); }
            catch (Exception ex) { Logger.Debug(ex, "LicenseRevoked listener failed"); }
        }

        private void StartPeriodicRevalidation()
        {
            if (_revalidationTimer != null) return;

            try
            {
                _revalidationTimer = new DispatcherTimer
                {
                    Interval = TimeSpan.FromMinutes(RevalidationIntervalMinutes)
                };
                _revalidationTimer.Tick += async (_, _) =>
                {
                    if (Interlocked.CompareExchange(ref _revalidationInFlight, 1, 0) != 0) return;
                    try
                    {
                        var result = await ValidateLicenseAsync().ConfigureAwait(true);
                        if (!result.IsValid)
                        {
                            _revalidationTimer?.Stop();
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "[LICENSE] Periodic revalidation threw");
                    }
                    finally
                    {
                        Interlocked.Exchange(ref _revalidationInFlight, 0);
                    }
                };
                _revalidationTimer.Start();
                Logger.Info($"[LICENSE] Periodic revalidation started ({RevalidationIntervalMinutes}min interval)");
            }
            catch (Exception ex)
            {
                // DispatcherTimer requires a Dispatcher; if we're on a non-UI thread (e.g.
                // background task calling ValidateLicenseAsync), skip the timer silently.
                Logger.Debug(ex, "[LICENSE] Could not start DispatcherTimer — periodic revalidation skipped");
            }
        }

        public void StopPeriodicRevalidation()
        {
            try
            {
                _revalidationTimer?.Stop();
                _revalidationTimer = null;
            }
            catch { }
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

        // Server signs this exact canonical string with RSA-SHA256.
        // The format mirrors JavaScript toISOString() output — millisecond
        // precision, literal Z suffix, pipe separators, lowercase bool.
        // DO NOT use C# "o" format here: that emits 7-digit ticks and offsets.
        private static string BuildCanonicalForm(ValidateResponse resp)
        {
            const string timestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
            var invariant = System.Globalization.CultureInfo.InvariantCulture;

            return string.Join("|", new[]
            {
                resp.hardware_id,
                resp.approved_at.ToUniversalTime().ToString(timestampFormat, invariant),
                resp.validated_at.ToUniversalTime().ToString(timestampFormat, invariant),
                resp.expires_at.ToUniversalTime().ToString(timestampFormat, invariant),
                resp.is_licensed ? "true" : "false"
            });
        }

        private static bool VerifySignature(ValidateResponse resp)
        {
            if (string.IsNullOrEmpty(resp.signature))
            {
                Logger.Warn("[LICENSE] Response missing signature field");
                return false;
            }

            try
            {
                var canonical = BuildCanonicalForm(resp);
                var dataBytes = Encoding.UTF8.GetBytes(canonical);
                var signatureBytes = Convert.FromBase64String(resp.signature);

                using var rsa = RSA.Create();
                rsa.ImportFromPem(LicenseServerPublicKeyPem);

                var valid = rsa.VerifyData(
                    dataBytes,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                if (!valid)
                {
                    Logger.Warn($"[LICENSE] Signature verification failed. " +
                        $"Canonical length={canonical.Length} sig length={resp.signature.Length}");
                }
                return valid;
            }
            catch (FormatException ex)
            {
                Logger.Warn(ex, "[LICENSE] Signature base64 decode failed");
                return false;
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[LICENSE] Signature verification threw unexpected exception");
                return false;
            }
        }

        private bool TryLoadAndVerifyCache(out LicenseCache? cache)
        {
            cache = null;
            try
            {
                if (!System.IO.File.Exists(_licenseCacheFilePath)) return false;

                cache = JsonSerializer.Deserialize<LicenseCache>(
                    System.IO.File.ReadAllText(_licenseCacheFilePath));
                if (cache == null) return false;

                // Reconstruct the server response so signature verification
                // runs against the same canonical form the server signed.
                var reconstructed = new ValidateResponse
                {
                    hardware_id = cache.HardwareId,
                    approved_at = cache.ApprovedAt,
                    validated_at = cache.ValidatedAt,
                    expires_at = cache.ExpiresAt,
                    is_licensed = cache.IsLicensed,
                    signature = cache.Signature
                };

                if (!VerifySignature(reconstructed))
                {
                    Logger.Warn("[LICENSE] Cache signature invalid — cache tampered, corrupt, or from an older schema. Rejecting.");
                    cache = null;
                    return false;
                }

                if (!string.Equals(cache.HardwareId, _hardwareId, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.Warn($"[LICENSE] Cache hardware ID mismatch: cache={cache.HardwareId} local={_hardwareId}");
                    cache = null;
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[LICENSE] Cache load failed");
                cache = null;
                return false;
            }
        }

        /// <summary>
        /// Persist the signed server response verbatim. Signature and
        /// timestamps round-trip exactly so offline re-verification will
        /// match the server's original signing input.
        /// </summary>
        private void SaveLicenseToCache(ValidateResponse resp)
        {
            try
            {
                var cache = new LicenseCache
                {
                    HardwareId   = resp.hardware_id,
                    ApprovedAt   = resp.approved_at.ToUniversalTime(),
                    ValidatedAt  = resp.validated_at.ToUniversalTime(),
                    ExpiresAt    = resp.expires_at.ToUniversalTime(),
                    IsLicensed   = resp.is_licensed,
                    Signature    = resp.signature ?? string.Empty
                };

                var jsonContent = JsonSerializer.Serialize(cache, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                System.IO.File.WriteAllText(_licenseCacheFilePath, jsonContent);
                Logger.Info($"[LICENSE] Cache updated (approvedAt={cache.ApprovedAt:O}, validatedAt={cache.ValidatedAt:O}, expiresAt={cache.ExpiresAt:O})");
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[LICENSE] Failed to save cache (non-critical)");
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

    /// <summary>
    /// Cached server response, written verbatim from a validated
    /// ValidateResponse so the RSA signature remains verifiable offline.
    /// </summary>
    internal class LicenseCache
    {
        public string HardwareId { get; set; } = string.Empty;
        public DateTime ApprovedAt { get; set; }
        public DateTime ValidatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsLicensed { get; set; }
        public string Signature { get; set; } = string.Empty;
    }

    /// <summary>
    /// /api/license/validate response. Server signs a canonical projection
    /// of these fields with RSA-SHA256; see BuildCanonicalForm in LicenseService.
    /// </summary>
    public class ValidateResponse
    {
        [JsonPropertyName("is_licensed")]
        public bool is_licensed { get; set; }

        [JsonPropertyName("hardware_id")]
        public string hardware_id { get; set; } = string.Empty;

        [JsonPropertyName("approved_at")]
        public DateTime approved_at { get; set; }

        [JsonPropertyName("validated_at")]
        public DateTime validated_at { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTime expires_at { get; set; }

        [JsonPropertyName("signature")]
        public string? signature { get; set; }
    }
}

