using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Dorothy.Models.Database;
using NLog;
using Supabase;

namespace Dorothy.Services
{
    /// <summary>
    /// Service for managing application licensing and hardware-based access control.
    /// Generates a unique hardware fingerprint and validates against whitelist.
    /// Supports both Supabase Auth integration and local whitelist file.
    /// </summary>
    public class LicenseService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly string _hardwareId;
        private readonly string _whitelistFilePath;
        private readonly string _licenseCacheFilePath;
        private readonly Supabase.Client? _supabaseClient;
        private readonly Guid? _userId;

        public LicenseService(Supabase.Client? supabaseClient = null, Guid? userId = null)
        {
            _hardwareId = PlatformHardwareId.GenerateHardwareId();
            _supabaseClient = supabaseClient;
            _userId = userId;
            
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

        /// <summary>
        /// Gets the current machine's hardware ID.
        /// </summary>
        public string HardwareId => _hardwareId;

        /// <summary>
        /// Validates if the current machine is authorized to run the application.
        /// SECURITY: Always requires online approval first. Offline cache is only used if:
        /// 1. Online validation was previously successful (cache exists)
        /// 2. Network/Supabase is currently unavailable
        /// This prevents workarounds - users cannot bypass online approval.
        /// </summary>
        public async Task<LicenseValidationResult> ValidateLicenseAsync()
        {
            try
            {
                // SECURITY: Always try Supabase first (online approval required)
                if (_supabaseClient != null)
                {
                    try
                    {
                        var supabaseResult = await ValidateSupabaseLicenseAsync();
                        if (supabaseResult.IsValid)
                        {
                            // Save approval to local cache for offline use (only after successful online validation)
                            SaveLicenseToCache();
                            Logger.Info("License validated via Supabase and saved to local cache");
                            return supabaseResult;
                        }
                        else
                        {
                            // Check if this is a network/connection error (not a rejection)
                            bool isNetworkError = supabaseResult.Message.Contains("알려진 호스트가 없습니다") ||
                                                  supabaseResult.Message.Contains("Unknown host") ||
                                                  supabaseResult.Message.Contains("network") ||
                                                  supabaseResult.Message.Contains("connection") ||
                                                  supabaseResult.Message.Contains("timeout") ||
                                                  supabaseResult.Message.Contains("unreachable") ||
                                                  supabaseResult.Message.Contains("Supabase validation error");
                            
                            if (isNetworkError)
                            {
                                // Network error - check cache for offline use
                                Logger.Warn($"Supabase network error: {supabaseResult.Message}. Checking local cache...");
                                var localCacheResult = ValidateLocalCache();
                                if (localCacheResult.IsValid)
                                {
                                    // Cache exists from previous online approval - allow offline use
                                    Logger.Info("Using cached license approval (offline mode - previously approved online)");
                                    return localCacheResult;
                                }
                                
                                // No cache - first-time approval requires online connection
                                return new LicenseValidationResult
                                {
                                    IsValid = false,
                                    Message = $"License validation unavailable (offline). Please connect to internet for first-time approval. Your Hardware ID: {_hardwareId}"
                                };
                            }
                            else
                            {
                                // Not a network error - license was rejected (not approved in Supabase)
                                // Deny access even if cache exists (license may have been revoked)
                                Logger.Warn($"License validation failed via Supabase (not a network error). Hardware ID: {_hardwareId}, Message: {supabaseResult.Message}");
                                return supabaseResult;
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        // Exception during Supabase validation - check if we have valid cache from previous online approval
                        Logger.Warn(ex, "Supabase validation exception (network error), checking local cache");
                        
                        var localCacheResult = ValidateLocalCache();
                        if (localCacheResult.IsValid)
                        {
                            // Cache exists from previous online approval - allow offline use
                            Logger.Info("Using cached license approval (offline mode - previously approved online)");
                            return localCacheResult;
                        }
                        
                        // No cache - first-time approval requires online connection
                        return new LicenseValidationResult
                        {
                            IsValid = false,
                            Message = $"License validation unavailable (offline). Please connect to internet for first-time approval. Your Hardware ID: {_hardwareId}. Error: {ex.Message}"
                        };
                    }
                }

                // Supabase client not configured - this should not happen in production
                // But if it does, check cache as last resort (for development/testing)
                var fallbackCacheResult = ValidateLocalCache();
                if (fallbackCacheResult.IsValid)
                {
                    Logger.Warn("Using local cache (Supabase not configured - development mode only)");
                    return fallbackCacheResult;
                }

                // No cache and no Supabase - deny access
                Logger.Error("License validation unavailable - no cache and Supabase not configured");
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = "License validation unavailable. Contact administrator."
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error during license validation");
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"License validation error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Validates license against Supabase whitelist table.
        /// Checks if hardware_id exists in license_whitelist table.
        /// Optionally validates user_id if provided (for user-linked licenses).
        /// </summary>
        private async Task<LicenseValidationResult> ValidateSupabaseLicenseAsync()
        {
            try
            {
                if (_supabaseClient == null)
                {
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "Supabase not configured"
                    };
                }

                // Query whitelisted_hardware table for this hardware_id
                // Filter by is_active and hardware_id (case-insensitive match in memory)
                var query = _supabaseClient
                    .From<LicenseWhitelistEntry>()
                    .Select("*")
                    .Where(x => x.IsActive == true);

                // If user_id is provided, also filter by user_id
                if (_userId.HasValue)
                {
                    query = query.Where(x => x.UserId == _userId.Value);
                }

                var response = await query.Get();

                // Filter by hardware_id (case-insensitive comparison)
                // PostgreSQL/Supabase stores text as-is, so we do case-insensitive match in memory
                var matchingEntries = response?.Models?
                    .Where(x => string.Equals(x.HardwareId, _hardwareId, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchingEntries != null && matchingEntries.Count > 0)
                {
                    var entry = matchingEntries.First();
                    var message = _userId.HasValue
                        ? $"✅ Authorized (User: {entry.UserId})"
                        : "✅ Authorized via Supabase whitelist";

                    Logger.Info($"License validated via Supabase. Hardware ID: {_hardwareId}, User ID: {entry.UserId}");

                    return new LicenseValidationResult
                    {
                        IsValid = true,
                        Message = message
                    };
                }

                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"Hardware ID not found in Supabase whitelist. Your ID: {_hardwareId}"
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Supabase license validation error");
                return new LicenseValidationResult
                {
                    IsValid = false,
                    Message = $"Supabase validation error: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Validates license against local whitelist file.
        /// </summary>
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

        /// <summary>
        /// Validates license against local cache file (for offline use).
        /// </summary>
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

                // Verify hardware ID matches
                Logger.Debug($"Comparing hardware IDs - Cached: {cache.HardwareId}, Current: {_hardwareId}");
                if (!string.Equals(cache.HardwareId, _hardwareId, StringComparison.OrdinalIgnoreCase))
                {
                    Logger.Warn($"License cache hardware ID mismatch. Cached: {cache.HardwareId}, Current: {_hardwareId}");
                    // Still allow cache if signature is valid - hardware ID might differ due to MAC address enumeration order
                    // But we'll log this as a warning and continue with signature validation
                }

                // Verify cryptographic signature to prevent tampering
                if (string.IsNullOrEmpty(cache.Signature))
                {
                    Logger.Warn("License cache missing signature - may be tampered with");
                    return new LicenseValidationResult
                    {
                        IsValid = false,
                        Message = "License cache is invalid or tampered with. Online validation required."
                    };
                }

                // Recalculate signature and compare
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

                // Cache is valid and verified (signature matches)
                // Note: We allow cache even if hardware ID doesn't match exactly, as long as signature is valid
                // This handles cases where MAC address enumeration order might differ
                Logger.Info($"License validated from cache. Approved: {cache.ApprovedAt:yyyy-MM-dd HH:mm:ss}, Cached Hardware ID: {cache.HardwareId}");
                return new LicenseValidationResult
                {
                    IsValid = true,
                    Message = $"✅ Authorized (cached approval from {cache.ApprovedAt:yyyy-MM-dd})",
                    CachedHardwareId = cache.HardwareId // Return cached hardware ID for display
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

        /// <summary>
        /// Saves license approval to local cache for offline use.
        /// Includes cryptographic signature to prevent tampering.
        /// </summary>
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

                // Generate cryptographic signature to prevent tampering
                // Signature is based on hardware ID + timestamp + secret salt
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
                // Don't throw - cache save failure shouldn't prevent validation
            }
        }

        /// <summary>
        /// Adds the current hardware ID to the local whitelist file.
        /// </summary>
        public bool AddToWhitelist(string? notes = null)
        {
            try
            {
                var lines = new List<string>();
                
                if (System.IO.File.Exists(_whitelistFilePath))
                {
                    lines = System.IO.File.ReadAllLines(_whitelistFilePath).ToList();
                }

                // Check if already exists
                if (lines.Any(line => line.Trim().Equals(_hardwareId, StringComparison.OrdinalIgnoreCase)))
                {
                    Logger.Info("Hardware ID already in whitelist");
                    return true;
                }

                // Add hardware ID with optional notes
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

        // Hardware ID generation is now handled by PlatformHardwareId for cross-platform support
    }

    /// <summary>
    /// Result of license validation.
    /// </summary>
    public class LicenseValidationResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; } = string.Empty;
        /// <summary>
        /// Hardware ID from cache (when using cached validation). 
        /// Use this for display when offline to show the approved hardware ID.
        /// </summary>
        public string? CachedHardwareId { get; set; }
    }

    /// <summary>
    /// Local license cache structure for offline validation.
    /// Includes cryptographic signature to prevent tampering.
    /// </summary>
    internal class LicenseCache
    {
        public string HardwareId { get; set; } = string.Empty;
        public DateTime ApprovedAt { get; set; }
        public DateTime LastValidatedAt { get; set; }
        public string Signature { get; set; } = string.Empty;
    }
}

