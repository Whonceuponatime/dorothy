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
using Dorothy.Models;
using NLog;

namespace Dorothy.Services
{

    public class LicenseService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private static readonly HttpClient PublicHttp = new() { Timeout = TimeSpan.FromSeconds(10) };

        // Periodic revalidation: check server every 10 minutes while running.
        // If server reports revoked → fail closed, fire LicenseStateChanged.
        private const int RevalidationIntervalMinutes = 10;

        private readonly string _hardwareId;
        private readonly string _whitelistFilePath;
        private readonly string _licenseCacheFilePath;

        private DateTime? _lastSuccessfulCheck;
        private DispatcherTimer? _revalidationTimer;
        private int _revalidationInFlight;

        // Tri-state license status. Default Expired so a fresh, never-validated
        // service is "not yet licensed" until ValidateLicenseAsync proves otherwise.
        private LicenseState _state = LicenseState.Expired;
        public LicenseState State => _state;

        /// <summary>
        /// Back-compat boolean for any external readers — true when the
        /// license is Active OR Stale (both states allow continued use).
        /// New code should switch on State directly.
        /// </summary>
        public bool IsLicensed => _state != LicenseState.Expired;

        /// <summary>
        /// Fires on every state TRANSITION (not on no-op same-state writes).
        /// Carries the new state plus optional reason / validityDays / age
        /// so the banner UI can render specifics without re-querying.
        /// </summary>
        public event EventHandler<LicenseStateChangedEventArgs>? LicenseStateChanged;

        // Centralized state mutation. Always set state through this so
        // transitions are logged consistently and the event fires once.
        private void SetState(
            LicenseState newState,
            string? reason = null,
            int? validityDays = null,
            TimeSpan? age = null)
        {
            if (_state == newState) return;
            var oldState = _state;
            _state = newState;
            Logger.Info($"[LICENSE] State {oldState} → {newState}: {reason ?? "(no reason)"}");
            try
            {
                LicenseStateChanged?.Invoke(this, new LicenseStateChangedEventArgs
                {
                    NewState = newState,
                    Reason = reason,
                    ValidityPeriodDays = validityDays,
                    AgeSinceValidation = age
                });
            }
            catch (Exception ex) { Logger.Debug(ex, "[LICENSE] LicenseStateChanged listener failed"); }
        }

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
            var appDataPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SEACURE(TOOL)");

            if (!System.IO.Directory.Exists(appDataPath))
            {
                System.IO.Directory.CreateDirectory(appDataPath);
            }

            _whitelistFilePath = System.IO.Path.Combine(appDataPath, "license.whitelist");
            _licenseCacheFilePath = System.IO.Path.Combine(appDataPath, "license.cache.json");

            // hwid is loaded from %APPDATA%\SEACURE(TOOL)\hwid.cache when present.
            // Cache is the source of truth across reinstalls; WMI is the seed.
            _hardwareId = LoadOrGenerateHardwareId();

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
                    var url = $"{SeacureConfig.ApiUrl.TrimEnd('/')}/api/license/validate?hardware_id={Uri.EscapeDataString(_hardwareId)}&api_version=2";
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
                        SetState(LicenseState.Expired, "Malformed license response");
                        return new LicenseValidationResult
                        {
                            State = LicenseState.Expired,
                            Message = "Malformed license response",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    if (resp == null)
                    {
                        Logger.Warn("[LICENSE] Empty response body");
                        SetState(LicenseState.Expired, "Empty license response");
                        return new LicenseValidationResult
                        {
                            State = LicenseState.Expired,
                            Message = "Empty license response",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Verify RSA-SHA256 signature BEFORE trusting any field.
                    if (!VerifySignature(resp))
                    {
                        Logger.Warn("[LICENSE] Response rejected — invalid signature. Treating as not licensed.");
                        ClearLicenseCache();
                        SetState(LicenseState.Expired, "License response signature invalid");
                        return new LicenseValidationResult
                        {
                            State = LicenseState.Expired,
                            Message = "License response signature invalid",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Response must describe THIS machine.
                    if (!string.Equals(resp.hardware_id, _hardwareId, StringComparison.OrdinalIgnoreCase))
                    {
                        Logger.Warn($"[LICENSE] Hardware ID mismatch: response={resp.hardware_id} local={_hardwareId}");
                        ClearLicenseCache();
                        SetState(LicenseState.Expired, "Hardware ID mismatch");
                        return new LicenseValidationResult
                        {
                            State = LicenseState.Expired,
                            Message = "Hardware ID mismatch",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Reject stale responses (replay defense): ±5 minute window.
                    var timestampSkew = DateTime.UtcNow - resp.validated_at.ToUniversalTime();
                    if (timestampSkew > TimeSpan.FromMinutes(5) || timestampSkew < TimeSpan.FromMinutes(-5))
                    {
                        Logger.Warn($"[LICENSE] Response timestamp out of range: {timestampSkew.TotalSeconds:F0}s from now");
                        ClearLicenseCache();
                        SetState(LicenseState.Expired, "License response timestamp stale");
                        return new LicenseValidationResult
                        {
                            State = LicenseState.Expired,
                            Message = "License response timestamp stale",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    if (resp.is_licensed)
                    {
                        Logger.Info("[LICENSE] Server validated. OK.");
                        _lastSuccessfulCheck = DateTime.UtcNow;
                        SaveLicenseToCache(resp);
                        StartPeriodicRevalidation();
                        SetState(LicenseState.Active, "Server validated");
                        return new LicenseValidationResult
                        {
                            State = LicenseState.Active,
                            Message = "License validated",
                            CachedHardwareId = _hardwareId
                        };
                    }

                    // Explicit revocation — fail closed, clear cache, fire event.
                    Logger.Warn("[LICENSE] Server reports license NOT valid. Failing closed.");
                    ClearLicenseCache();
                    SetState(LicenseState.Expired, "Server reports license is no longer valid");
                    return new LicenseValidationResult
                    {
                        State = LicenseState.Expired,
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
            // Old caches (unsigned by server, or signed without ValidityPeriodDays
            // in the canonical form) fail signature check here and are silently
            // rejected — forcing an online re-validation on first launch after
            // upgrade, which is the desired upgrade behavior.
            if (!TryLoadAndVerifyCache(out var cache) || cache == null)
            {
                Logger.Warn("[LICENSE] Server unreachable and no valid signed cache on file. Failing closed.");
                SetState(LicenseState.Expired,
                    "Server unreachable and no prior approval on file");
                return new LicenseValidationResult
                {
                    State = LicenseState.Expired,
                    Message = "Server unreachable and no prior approval on file. Please connect to the internet and retry.",
                    CachedHardwareId = _hardwareId
                };
            }

            if (!cache.IsLicensed)
            {
                Logger.Warn("[LICENSE] Cache records a prior revocation. Failing closed.");
                ClearLicenseCache();
                SetState(LicenseState.Expired,
                    "License previously revoked by the server");
                return new LicenseValidationResult
                {
                    State = LicenseState.Expired,
                    Message = "License previously revoked by the server. Contact support to restore access.",
                    CachedHardwareId = _hardwareId
                };
            }

            // Tri-split offline-grace logic, driven by per-license validity_period_days.
            //   null or 0  → unlimited (Active forever offline)
            //   age < N    → Active
            //   age < 2N   → Stale (banner, app continues)
            //   else       → Expired (block)
            var validityDays = cache.ValidityPeriodDays ?? 0;
            var age = DateTime.UtcNow - cache.ValidatedAt.ToUniversalTime();
            _lastSuccessfulCheck = cache.ValidatedAt.ToUniversalTime();

            if (validityDays == 0)
            {
                Logger.Info($"[LICENSE] Unlimited validity — cache age {age.TotalHours:F1}h, staying Active.");
                StartPeriodicRevalidation();
                SetState(LicenseState.Active, "Unlimited validity");
                return new LicenseValidationResult
                {
                    State = LicenseState.Active,
                    Message = $"Offline mode — unlimited validity (last validated {age.TotalHours:F1}h ago).",
                    CachedHardwareId = _hardwareId
                };
            }

            if (age.TotalDays < validityDays)
            {
                Logger.Info($"[LICENSE] Within validity — {age.TotalDays:F1}d / {validityDays}d.");
                StartPeriodicRevalidation();
                SetState(LicenseState.Active, "Within validity period");
                return new LicenseValidationResult
                {
                    State = LicenseState.Active,
                    Message = $"Offline mode — last validated {age.TotalDays:F1}d ago (validity {validityDays}d).",
                    CachedHardwareId = _hardwareId
                };
            }

            if (age.TotalDays < validityDays * 2)
            {
                Logger.Warn($"[LICENSE] Stale — {age.TotalDays:F1}d offline, validity={validityDays}d. App continues.");
                StartPeriodicRevalidation();
                SetState(LicenseState.Stale,
                    $"License unchecked for {age.TotalDays:F0} days",
                    validityDays, age);
                return new LicenseValidationResult
                {
                    State = LicenseState.Stale,
                    Message = $"License unchecked for {age.TotalDays:F0} days (limit: {validityDays} days). Connect to internet to refresh.",
                    CachedHardwareId = _hardwareId
                };
            }

            // Beyond 2× validity — hard fail, block UI.
            Logger.Warn($"[LICENSE] Expired — {age.TotalDays:F1}d offline, exceeds 2× validity ({validityDays * 2}d).");
            SetState(LicenseState.Expired,
                $"License unchecked for {age.TotalDays:F0} days, exceeds {validityDays * 2}-day hard limit",
                validityDays, age);
            return new LicenseValidationResult
            {
                State = LicenseState.Expired,
                Message = $"Offline for {age.TotalDays:F0} days — exceeds {validityDays * 2}-day hard limit. Reconnect to restore access.",
                CachedHardwareId = _hardwareId
            };
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
                        // Only Expired stops the periodic timer. Stale should keep
                        // polling so a restored network connection can transition
                        // the state back to Active and clear the banner.
                        if (result.State == LicenseState.Expired)
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
                        State = LicenseState.Expired,
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
                        State = LicenseState.Expired,
                        Message = "License whitelist is empty."
                    };
                }

                var isAuthorized = whitelistLines.Contains(_hardwareId, StringComparer.OrdinalIgnoreCase);

                return new LicenseValidationResult
                {
                    State = isAuthorized ? LicenseState.Active : LicenseState.Expired,
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
                    State = LicenseState.Expired,
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

            // validity_period_days encoded as the literal integer or the
            // string "null". Old servers (pre-this-version) didn't include
            // the field; this token's presence is what makes the canonical
            // form back-incompatible with old responses, which is intentional.
            string validityToken = resp.validity_period_days.HasValue
                ? resp.validity_period_days.Value.ToString(invariant)
                : "null";

            return string.Join("|", new[]
            {
                resp.hardware_id,
                resp.approved_at.ToUniversalTime().ToString(timestampFormat, invariant),
                resp.validated_at.ToUniversalTime().ToString(timestampFormat, invariant),
                resp.expires_at.ToUniversalTime().ToString(timestampFormat, invariant),
                resp.is_licensed ? "true" : "false",
                validityToken
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
                    validity_period_days = cache.ValidityPeriodDays,
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
                    HardwareId          = resp.hardware_id,
                    ApprovedAt          = resp.approved_at.ToUniversalTime(),
                    ValidatedAt         = resp.validated_at.ToUniversalTime(),
                    ExpiresAt           = resp.expires_at.ToUniversalTime(),
                    IsLicensed          = resp.is_licensed,
                    ValidityPeriodDays  = resp.validity_period_days,
                    Signature           = resp.signature ?? string.Empty
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

        // ─── Hardware ID surface ───────────────────────────────────────
        // The hwid is the licensing fingerprint that identifies a physical
        // machine across Windows reinstalls. Three rules:
        //   1. Inputs come from STABLE SMBIOS fields only — no disk drives,
        //      no MachineGuid, no MachineName, no UserName. Disk drive
        //      enumeration was the source of the historical drift bug.
        //   2. The first computed value is cached at
        //      %APPDATA%\SEACURE(TOOL)\hwid.cache. Subsequent launches
        //      prefer the cache; if a fresh recomputation diverges, the
        //      cache wins and a warning is logged.
        //   3. The user's escape hatch is to delete the cache file. There
        //      is no auto-overwrite.

        /// <summary>
        /// True when this launch's freshly-computed hwid did NOT match the
        /// value loaded from <c>hwid.cache</c>. The cached value is still
        /// being used; this flag is purely informational for the UI.
        /// </summary>
        public bool HardwareIdMismatch { get; private set; }

        /// <summary>
        /// When <see cref="HardwareIdMismatch"/> is true, the freshly-computed
        /// value that would have been used had no cache existed. Useful for
        /// support diagnostics: "your hardware fingerprint changed from X to Y."
        /// </summary>
        public string? HardwareIdFreshValue { get; private set; }

        private string LoadOrGenerateHardwareId()
        {
            var cacheDir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SEACURE(TOOL)");
            try { System.IO.Directory.CreateDirectory(cacheDir); } catch { /* best effort */ }
            var cachePath = System.IO.Path.Combine(cacheDir, "hwid.cache");

            Logger.Info($"[HWID] Cache directory: {cacheDir}");
            Logger.Info($"[HWID] Cache path: {cachePath}");
            Logger.Info($"[HWID] Cache exists: {System.IO.File.Exists(cachePath)}");

            string? cached = null;
            if (System.IO.File.Exists(cachePath))
            {
                try
                {
                    cached = System.IO.File.ReadAllText(cachePath).Trim();
                    if (cached.Length != 32 ||
                        !cached.All(c => "0123456789ABCDEF".Contains(c)))
                    {
                        Logger.Warn($"[HWID] Cache file is malformed; ignoring (raw='{cached}')");
                        cached = null;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "[HWID] Could not read cache file");
                }
            }

            Logger.Info($"[HWID] Cache read result: {cached ?? "(null)"}");

            var fresh = GenerateHardwareIdRaw();

            Logger.Info($"[HWID] Fresh computed value: {fresh}");

            if (cached == null)
            {
                // First run on this machine, or the cache file was lost / corrupt.
                try
                {
                    System.IO.File.WriteAllText(cachePath, fresh);
                    Logger.Info($"[HWID] First-run cache write: {fresh}");
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "[HWID] Could not write cache file");
                }
                Logger.Info($"[HWID] Final returned value: {fresh}");
                return fresh;
            }

            if (cached == fresh)
            {
                Logger.Info($"[HWID] Cache and fresh match: {cached}");
                Logger.Info($"[HWID] Final returned value: {cached}");
                return cached;
            }

            // Mismatch — cached value wins. Log loudly so support can diagnose
            // and surface a flag for the UI to optionally render.
            Logger.Warn(
                $"[HWID] Mismatch: cached={cached} fresh={fresh}. " +
                $"Using cached value. " +
                $"If hardware was replaced, delete {cachePath} to regenerate.");

            HardwareIdMismatch = true;
            HardwareIdFreshValue = fresh;
            Logger.Info($"[HWID] Final returned value: {cached}");
            return cached;
        }

        /// <summary>
        /// Compute a 32-char uppercase hex hwid from stable SMBIOS sources:
        /// CPU ProcessorId, motherboard serial, BIOS serial, and the system
        /// UUID. Disk drives are deliberately excluded — their enumeration
        /// is too volatile across reinstalls / driver state changes.
        ///
        /// Inputs are joined with <c>|</c> separators and prefixed by source
        /// (<c>CPU:</c>, <c>MB:</c>, <c>BIOS:</c>, <c>SYS:</c>) so a missing
        /// source leaves a deterministic gap rather than shifting other
        /// inputs into different positions. SHA-256 of the concatenation,
        /// truncated to the first 32 hex characters.
        ///
        /// If fewer than 2 stable inputs are obtained, retries once after
        /// 2 seconds in case WMI was still initializing. If still under 2
        /// the second attempt logs a Warn and proceeds; if zero inputs the
        /// algorithm logs Error and falls back to MachineName (which is
        /// unstable across reinstalls but at least deterministic within
        /// one install).
        /// </summary>
        private string GenerateHardwareIdRaw()
        {
            return GenerateHardwareIdRawCore(retryAllowed: true);
        }

        private string GenerateHardwareIdRawCore(bool retryAllowed)
        {
            var components = new List<string>();

            string? cpu = QueryWmi(
                "SELECT ProcessorId FROM Win32_Processor", "ProcessorId");
            if (!string.IsNullOrWhiteSpace(cpu) && IsRealValue(cpu))
                components.Add($"CPU:{Canonicalize(cpu)}");

            string? mb = QueryWmi(
                "SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber");
            if (!string.IsNullOrWhiteSpace(mb) && IsRealValue(mb))
                components.Add($"MB:{Canonicalize(mb)}");

            string? bios = QueryWmi(
                "SELECT SerialNumber FROM Win32_BIOS", "SerialNumber");
            if (!string.IsNullOrWhiteSpace(bios) && IsRealValue(bios))
                components.Add($"BIOS:{Canonicalize(bios)}");

            string? sysUuid = QueryWmi(
                "SELECT UUID FROM Win32_ComputerSystemProduct", "UUID");
            if (!string.IsNullOrWhiteSpace(sysUuid) && IsRealValue(sysUuid))
                components.Add($"SYS:{Canonicalize(sysUuid)}");

            // If we got fewer than 2 stable inputs, WMI may still be
            // initializing (early-startup race). Sleep 2s and try once.
            if (components.Count < 2 && retryAllowed)
            {
                Logger.Warn(
                    $"[HWID] Only {components.Count} stable input(s) available; " +
                    "WMI may not be ready. Retrying once after 2s.");
                Thread.Sleep(2000);
                return GenerateHardwareIdRawCore(retryAllowed: false);
            }

            if (components.Count == 0)
            {
                Logger.Error(
                    "[HWID] No stable hardware identifiers available. " +
                    "Hardware ID will be UNSTABLE across reinstalls.");
                components.Add($"FALLBACK:{Canonicalize(Environment.MachineName)}");
            }

            Logger.Info($"[HWID] WMI components count: {components.Count}");
            foreach (var c in components)
            {
                Logger.Info($"[HWID] Component: {c}");
            }

            var combined = string.Join("|", components);
            Logger.Info($"[HWID] Hash input string: {combined}");

            using var sha256 = SHA256.Create();
            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
            var hashString = BitConverter.ToString(hashBytes)
                .Replace("-", "")
                .ToUpperInvariant()
                .Substring(0, 32);
            Logger.Info($"[HWID] Computed hash: {hashString}");
            return hashString;
        }

        /// <summary>
        /// Run a WMI SELECT query and return the first non-empty value of
        /// the named property. Returns null on any failure (query throws,
        /// no rows, property null/empty). Failures are logged at Debug.
        /// </summary>
        private static string? QueryWmi(string query, string property)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject obj in searcher.Get())
                {
                    var value = obj[property]?.ToString();
                    if (!string.IsNullOrWhiteSpace(value))
                        return value;
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"[HWID] WMI query failed: {query}");
            }
            return null;
        }

        /// <summary>
        /// Trim, strip control characters, collapse internal whitespace runs
        /// to a single space, and uppercase. Behavior:
        /// <list type="bullet">
        /// <item><description><c>"  ABC-DEF  "</c> → <c>"ABC-DEF"</c></description></item>
        /// <item><description><c>"abc def"</c> → <c>"ABC DEF"</c></description></item>
        /// <item><description><c>"abc\t\ndef"</c> → <c>"ABC DEF"</c></description></item>
        /// </list>
        /// </summary>
        private static string Canonicalize(string value)
        {
            var trimmed = value.Trim();
            var stripped = new string(trimmed
                .Where(c => !char.IsControl(c))
                .ToArray());
            var collapsed = System.Text.RegularExpressions.Regex
                .Replace(stripped, @"\s+", " ");
            return collapsed.ToUpperInvariant();
        }

        /// <summary>
        /// Filter out OEM placeholder strings. Comparison is canonicalized
        /// (uppercase + whitespace-collapsed) so all common variants of
        /// "To Be Filled By O.E.M." land in the same bucket.
        /// Behavior:
        /// <list type="bullet">
        /// <item><description><c>"To Be Filled By O.E.M."</c> → false</description></item>
        /// <item><description><c>"  to be filled by oem  "</c> → false</description></item>
        /// <item><description><c>"0"</c> → false</description></item>
        /// <item><description><c>"00000000-0000-0000-0000-000000000000"</c> → false</description></item>
        /// <item><description><c>"WD-WCC4N0000123"</c> → true (legitimate serial — passes despite "0000" substring)</description></item>
        /// <item><description><c>"REAL_SERIAL_123"</c> → true</description></item>
        /// </list>
        /// </summary>
        private static bool IsRealValue(string value)
        {
            var canonical = Canonicalize(value);
            string[] placeholders = {
                "TO BE FILLED BY O.E.M.",
                "TO BE FILLED BY OEM",
                "DEFAULT STRING",
                "NOT SPECIFIED",
                "NONE",
                "SYSTEM SERIAL NUMBER",
                "SYSTEMSERIALNUMBER",
                "0",
                "00000000",
                "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
                "00000000-0000-0000-0000-000000000000"
            };
            return canonical.Length > 3 && !placeholders.Contains(canonical);
        }
    }

    public class LicenseValidationResult
    {
        public LicenseState State { get; set; } = LicenseState.Expired;

        // Back-compat for callers that branch on a boolean. Active and Stale
        // both pass; only Expired blocks. Derived from State so set-sites only
        // need to assign State.
        public bool IsValid => State != LicenseState.Expired;

        public string Message { get; set; } = string.Empty;

        public string? CachedHardwareId { get; set; }
    }

    /// <summary>
    /// Payload for LicenseService.LicenseStateChanged. Stale transitions
    /// carry ValidityPeriodDays + AgeSinceValidation so the banner can render
    /// "License unchecked for X days (limit: Y days)" without re-querying.
    /// Active and Expired transitions pass null for those fields.
    /// </summary>
    public class LicenseStateChangedEventArgs : EventArgs
    {
        public LicenseState NewState { get; set; }
        public string? Reason { get; set; }
        public int? ValidityPeriodDays { get; set; }
        public TimeSpan? AgeSinceValidation { get; set; }
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
        // null or 0 → unlimited (Active forever offline). Otherwise the
        // tri-split branches in HandleUnreachableWithGrace use this number.
        public int? ValidityPeriodDays { get; set; }
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

        // null or 0 ⇒ unlimited offline validity. Server omits the field
        // for grandfathered licenses; the canonical form encodes that as
        // the literal string "null" so signature verification stays stable.
        [JsonPropertyName("validity_period_days")]
        public int? validity_period_days { get; set; }

        [JsonPropertyName("signature")]
        public string? signature { get; set; }
    }
}

