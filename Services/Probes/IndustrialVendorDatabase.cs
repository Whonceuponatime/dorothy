using System;
using System.Collections.Generic;
using Dorothy.Models;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// Compiled-in lookup tables for industrial / maritime equipment
    /// fingerprinting. Two surfaces:
    ///
    ///   1. SNMP sysObjectID → (vendor, category, vessel zone hint)
    ///      keyed by IANA enterprise number. The sysObjectID OID format
    ///      is 1.3.6.1.4.1.&lt;enterprise&gt;.… so we extract the enterprise
    ///      number from the OID prefix and look it up.
    ///
    ///   2. MAC OUI prefix → (category, vessel zone hint) for vendors whose
    ///      OUIs are in the IEEE registry. The base vendor name still
    ///      comes from oui.txt via OuiLookup; this overlay just adds the
    ///      industrial category + zone hint.
    ///
    /// Round 1 entry count target: ~50. Round 2 expansion to 100+.
    /// Round 4 will add a %APPDATA% override file that merges into these
    /// defaults at startup.
    /// </summary>
    public static class IndustrialVendorDatabase
    {
        public record VendorEntry(
            string Vendor,
            IndustrialCategory Category,
            VesselZone VesselZoneHint,
            // Hinted protocols this vendor's equipment is most likely to
            // speak. Survey Stage 3 uses this to skip unrelated probes.
            // Empty = unknown; probe whichever ports look open.
            string[] HintedProtocols);

        // SNMP enterprise number → vendor entry.
        // Source: IANA enterprise-numbers registry (PRIVATE ENTERPRISE NUMBERS,
        // https://www.iana.org/assignments/enterprise-numbers/).
        // Selection criterion: maritime / industrial relevance.
        private static readonly Dictionary<int, VendorEntry> _bySnmpEnterprise =
            new()
            {
                // ── Industrial switches / network gear ──
                [248]   = new("Hirschmann (Belden)", IndustrialCategory.IndustrialSwitch, VesselZone.Bridge,       new[] { "SNMP" }),
                [8691]  = new("Moxa",                IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom,   new[] { "SNMP", "Modbus" }),
                [16847] = new("Westermo",            IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom,   new[] { "SNMP" }),
                [21888] = new("Korenix",             IndustrialCategory.IndustrialSwitch, VesselZone.Unknown,      new[] { "SNMP" }),
                [13458] = new("Sixnet",              IndustrialCategory.IndustrialSwitch, VesselZone.Unknown,      new[] { "SNMP" }),
                [368]   = new("Allied Telesis",      IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
                [3375]  = new("F5 Networks",         IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
                [11129] = new("Garrettcom",          IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom,   new[] { "SNMP" }),

                // ── PLCs ──
                [4329]  = new("Schneider Electric",  IndustrialCategory.PLC,              VesselZone.Cargo,        new[] { "Modbus", "OPC UA" }),
                [1314]  = new("Allen-Bradley / Rockwell", IndustrialCategory.PLC,         VesselZone.EngineRoom,   new[] { "EtherNet/IP", "OPC UA" }),
                [4196]  = new("Siemens AG",          IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "S7Comm", "OPC UA", "Profinet" }),
                [17518] = new("Mitsubishi Electric", IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "MELSEC", "OPC UA" }),
                [22400] = new("Yokogawa Electric",   IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "Modbus", "OPC UA" }),
                [791]   = new("Schweitzer Engineering", IndustrialCategory.PLC,           VesselZone.EngineRoom,   new[] { "DNP3", "Modbus" }),
                [4868]  = new("Phoenix Contact",     IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "Modbus", "OPC UA", "Profinet" }),
                [195]   = new("ABB",                 IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "OPC UA", "Modbus" }),
                [13491] = new("WAGO",                IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "Modbus", "OPC UA" }),
                [3833]  = new("Beckhoff Automation", IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "EtherCAT", "OPC UA", "Modbus" }),
                [7165]  = new("Omron",               IndustrialCategory.PLC,              VesselZone.EngineRoom,   new[] { "OPC UA", "Modbus" }),
                [12148] = new("B&R Industrial Automation", IndustrialCategory.PLC,        VesselZone.EngineRoom,   new[] { "OPC UA", "Powerlink" }),

                // ── HMI / SCADA ──
                [5263]  = new("Wonderware",          IndustrialCategory.HMI,              VesselZone.Bridge,       new[] { "OPC UA" }),
                [11096] = new("Inductive Automation", IndustrialCategory.HMI,             VesselZone.Bridge,       new[] { "OPC UA", "Modbus" }),
                [6027]  = new("ABB Marine",          IndustrialCategory.PowerManagement,  VesselZone.EngineRoom,   new[] { "OPC UA", "Modbus" }),

                // ── Maritime / navigation vendors ──
                [4837]  = new("Furuno",              IndustrialCategory.NavigationDevice, VesselZone.Bridge,       new[] { "NMEA", "IEC 61162-450" }),
                [17163] = new("JRC (Japan Radio)",   IndustrialCategory.NavigationDevice, VesselZone.Bridge,       new[] { "NMEA", "IEC 61162-450" }),
                [30622] = new("Wärtsilä",            IndustrialCategory.EngineController, VesselZone.EngineRoom,   new[] { "Modbus", "OPC UA" }),
                [17345] = new("Kongsberg Maritime",  IndustrialCategory.BridgeIntegration, VesselZone.Bridge,      new[] { "NMEA", "OPC UA" }),
                [11796] = new("Praxis Automation",   IndustrialCategory.BridgeIntegration, VesselZone.Bridge,      new[] { "NMEA", "Modbus" }),
                [43775] = new("Sperry Marine",       IndustrialCategory.NavigationDevice, VesselZone.Bridge,       new[] { "NMEA" }),
                [5168]  = new("Raymarine",           IndustrialCategory.NavigationDevice, VesselZone.Bridge,       new[] { "NMEA" }),
                [27989] = new("Garmin Marine",       IndustrialCategory.NavigationDevice, VesselZone.Bridge,       new[] { "NMEA" }),
                [12798] = new("Simrad",              IndustrialCategory.NavigationDevice, VesselZone.Bridge,       new[] { "NMEA" }),
                [3786]  = new("Northrop Grumman Sperry", IndustrialCategory.NavigationDevice, VesselZone.Bridge,   new[] { "NMEA" }),

                // ── Power / engine room ──
                [13742] = new("Eaton",               IndustrialCategory.PowerManagement,  VesselZone.EngineRoom,   new[] { "Modbus", "SNMP" }),
                [232]   = new("HP / HPE",            IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
                [318]   = new("APC (Schneider UPS)", IndustrialCategory.PowerManagement,  VesselZone.EngineRoom,   new[] { "SNMP" }),
                [13146] = new("Tripp Lite",          IndustrialCategory.PowerManagement,  VesselZone.EngineRoom,   new[] { "SNMP" }),

                // ── Satcom / VSAT ──
                [25366] = new("Cobham SATCOM",       IndustrialCategory.SatcomRouter,     VesselZone.Satcom,       new[] { "SNMP" }),
                [10089] = new("Iridium",             IndustrialCategory.SatcomRouter,     VesselZone.Satcom,       new[] { "SNMP" }),
                [22557] = new("Inmarsat",            IndustrialCategory.SatcomRouter,     VesselZone.Satcom,       new[] { "SNMP" }),

                // ── Common IT vendors that might appear in vessel admin VLAN ──
                // (Included for completeness so analyst sees IT classification when
                //  an admin-VLAN host is discovered alongside ICS gear.)
                [9]     = new("Cisco Systems",       IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
                [311]   = new("Microsoft",           IndustrialCategory.Unknown,          VesselZone.Admin,        Array.Empty<string>()),
                [2636]  = new("Juniper Networks",    IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
                [14988] = new("MikroTik",            IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
                [6486]  = new("Alcatel-Lucent",      IndustrialCategory.IndustrialSwitch, VesselZone.Admin,        new[] { "SNMP" }),
            };

        // MAC OUI overlay — 24-bit prefix (first 6 hex chars, uppercase, no
        // separators) → category + zone hint. Vendor name still resolves
        // through OuiLookup; this overlay only adds maritime classification.
        private static readonly Dictionary<string, (IndustrialCategory Category, VesselZone Zone)> _byOui =
            new(StringComparer.Ordinal)
            {
                // Maritime navigation
                ["00248B"] = (IndustrialCategory.NavigationDevice, VesselZone.Bridge),    // Furuno
                ["008064"] = (IndustrialCategory.NavigationDevice, VesselZone.Bridge),    // Sperry Marine (Northrop)
                ["0001B4"] = (IndustrialCategory.NavigationDevice, VesselZone.Bridge),    // JRC
                ["003041"] = (IndustrialCategory.BridgeIntegration, VesselZone.Bridge),   // Kongsberg Maritime
                // Industrial switches
                ["000ADC"] = (IndustrialCategory.IndustrialSwitch, VesselZone.Bridge),    // Hirschmann (subset)
                ["0090E8"] = (IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom),// Moxa
                ["00608C"] = (IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom),// 3Com / industrial (some)
                ["0050C2"] = (IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom),// IEEE registration authority block — used by many small industrial OEMs
                ["F84ABF"] = (IndustrialCategory.IndustrialSwitch, VesselZone.EngineRoom),// Westermo
                // PLCs
                ["00802F"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // Allen-Bradley / Rockwell
                ["001B1B"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // Siemens
                ["1C0D7F"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // Beckhoff Automation
                ["00A045"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // Phoenix Contact
                ["00307C"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // WAGO
                ["00301B"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // Schneider
                ["00800F"] = (IndustrialCategory.PLC, VesselZone.EngineRoom),             // Mitsubishi Electric
                // Engine / power management
                ["001B5C"] = (IndustrialCategory.PowerManagement, VesselZone.EngineRoom), // ABB
                ["AC64DD"] = (IndustrialCategory.EngineController, VesselZone.EngineRoom),// Wärtsilä (subset)
                // Satcom
                ["00184F"] = (IndustrialCategory.SatcomRouter, VesselZone.Satcom),        // Cobham
            };

        /// <summary>
        /// Look up an SNMP sysObjectID OID like
        /// "1.3.6.1.4.1.4329.6.0.1.0" → entry for enterprise 4329 (Schneider).
        /// Returns null when the OID isn't an enterprise OID, or the
        /// enterprise isn't in our table.
        /// </summary>
        public static VendorEntry? LookupBySysObjectID(string? sysObjectId)
        {
            if (string.IsNullOrWhiteSpace(sysObjectId)) return null;

            // Strip leading dot if present.
            var oid = sysObjectId.StartsWith('.') ? sysObjectId.Substring(1) : sysObjectId;

            // Must start with the IANA private-enterprise prefix 1.3.6.1.4.1.
            const string prefix = "1.3.6.1.4.1.";
            if (!oid.StartsWith(prefix, StringComparison.Ordinal)) return null;

            var rest = oid.Substring(prefix.Length);
            int dotIdx = rest.IndexOf('.');
            var enterpriseStr = dotIdx >= 0 ? rest.Substring(0, dotIdx) : rest;
            if (!int.TryParse(enterpriseStr, out var enterprise)) return null;

            return _bySnmpEnterprise.TryGetValue(enterprise, out var entry) ? entry : null;
        }

        /// <summary>
        /// Look up MAC OUI overlay (category + zone). Vendor name is still
        /// resolved through the IEEE OuiLookup. Accepts standard MAC formats
        /// (XX:XX:XX:XX:XX:XX, XX-XX-XX-…, no-separator, etc).
        /// </summary>
        public static (IndustrialCategory Category, VesselZone Zone)? LookupByOui(string? mac)
        {
            if (string.IsNullOrWhiteSpace(mac)) return null;
            var stripped = mac.Replace(":", string.Empty)
                              .Replace("-", string.Empty)
                              .Replace(".", string.Empty);
            if (stripped.Length < 6) return null;
            var key = stripped.Substring(0, 6).ToUpperInvariant();
            return _byOui.TryGetValue(key, out var v) ? v : null;
        }

        /// <summary>
        /// True when an enterprise number is present in the table — used by
        /// Survey Stage 3 to decide whether to consult HintedProtocols.
        /// </summary>
        public static bool HasSnmpEnterprise(int enterprise)
            => _bySnmpEnterprise.ContainsKey(enterprise);
    }
}
