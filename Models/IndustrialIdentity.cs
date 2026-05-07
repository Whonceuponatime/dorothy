using System;

namespace Dorothy.Models
{
    /// <summary>
    /// Equipment categories surfaced on the canvas + detail panel for
    /// industrial / OT devices. Closed enum so consumers can switch on it
    /// without string comparison drift.
    /// </summary>
    public enum IndustrialCategory
    {
        Unknown = 0,
        PLC,
        IndustrialSwitch,
        RTU,
        HMI,
        NavigationDevice,
        SatcomRouter,
        EngineController,
        PowerManagement,
        CargoSystem,
        BridgeIntegration
    }

    /// <summary>
    /// Vessel-zone hint derived from vendor/category. May be Unknown when
    /// the device could legitimately appear in multiple zones (e.g. an
    /// IndustrialSwitch could be Bridge OR EngineRoom).
    /// </summary>
    public enum VesselZone
    {
        Unknown = 0,
        Bridge,
        EngineRoom,
        Cargo,
        Satcom,
        Admin
    }

    /// <summary>
    /// Generic industrial-device identity carrier — the SUMMARY rendered on
    /// the canvas label and as the INDUSTRIAL DEVICE detail-panel header.
    /// Per-protocol specifics live in ModbusInfo / OpcUaInfo / etc.
    /// </summary>
    public record IndustrialIdentity(
        string? Vendor,
        string? ProductFamily,
        string? ProductName,
        string? FirmwareVersion,
        string? SerialNumber,
        string Protocol,                  // "Modbus", "S7Comm", "OPC UA", …
        IndustrialCategory Category,
        VesselZone VesselZoneHint,
        DateTime ProbedAt);
}
