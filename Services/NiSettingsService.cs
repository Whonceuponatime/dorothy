using System;
using System.IO;
using System.Text.Json;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services
{
    /// <summary>
    /// Single-purpose JSON-backed settings store for the NI tab. Persists
    /// the user's probe-level toggle selection across app restarts. Stored
    /// at %APPDATA%\SEACURE(TOOL)\ni-settings.json.
    ///
    /// Default-on-fresh-install: ProbeLevel.Survey (safe for production ICS).
    /// Failure modes (missing file, malformed JSON, permission error) all
    /// fall back to Survey rather than throwing — settings I/O must never
    /// crash the NI tab.
    /// </summary>
    public class NiSettingsService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly string _settingsPath;
        private NiSettings _current = new();

        public NiSettingsService()
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "SEACURE(TOOL)");
            try { Directory.CreateDirectory(dir); } catch { /* best effort */ }
            _settingsPath = Path.Combine(dir, "ni-settings.json");
            Load();
        }

        public ProbeLevel DefaultProbeLevel
        {
            get => _current.DefaultProbeLevel;
            set
            {
                if (_current.DefaultProbeLevel == value) return;
                _current = _current with { DefaultProbeLevel = value };
                Save();
            }
        }

        /// <summary>
        /// When true, the NI tab's discovery paths (ARP sweep, ICMP ping,
        /// bulk probe, industrial port scan) run with reduced concurrency,
        /// 50-200ms jitter between probes, randomised host order, and no
        /// retries. Trades scan speed for lower firewall-trigger risk and
        /// gentler load on production ICS devices.
        /// </summary>
        public bool StealthMode
        {
            get => _current.StealthMode;
            set
            {
                if (_current.StealthMode == value) return;
                _current = _current with { StealthMode = value };
                Save();
            }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_settingsPath)) return;
                var json = File.ReadAllText(_settingsPath);
                var loaded = JsonSerializer.Deserialize<NiSettings>(json);
                if (loaded != null) _current = loaded;
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[NI-SETTINGS] Failed to load — using defaults");
                _current = new NiSettings();
            }
        }

        private void Save()
        {
            try
            {
                var json = JsonSerializer.Serialize(_current,
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_settingsPath, json);
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "[NI-SETTINGS] Failed to save");
            }
        }

        // Record so future settings additions are non-breaking via "with" expr.
        // Existing ni-settings.json files without StealthMode field deserialize
        // to false by default — desired (existing fast behaviour preserved on upgrade).
        private record NiSettings
        {
            public ProbeLevel DefaultProbeLevel { get; init; } = ProbeLevel.Survey;
            public bool StealthMode { get; init; } = false;
        }
    }
}
