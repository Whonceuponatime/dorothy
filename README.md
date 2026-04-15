# SEACURE(TOOL)

Windows WPF network security testing application for authorized maritime and enterprise network resilience evaluation.

Publisher: SeaNet Co., Ltd. — https://seacuredb.com
Current version: 2.5.0

## Authorized Use Only

This software is intended strictly for legitimate network testing in controlled environments. Users must have explicit written authorization from the network owner before running any attack simulation. SeaNet Co., Ltd. assumes no responsibility for misuse, unauthorized access, or damages.

## Features

- TCP SYN Flood (Basic / Evasion modes, FortiGate-aware evasion)
- UDP Flood
- ICMP Flood
- Ethernet Flood
- ARP Spoofing / Network Storm
- Destination type selection: Unicast / Multicast / Broadcast (TCP SYN, UDP, ICMP)
- Auto-fill of broadcast/multicast IP and MAC
- Real-time attack rate control (Mbps)
- Reachability wizard and network scan
- SNMP walk
- Asset sync (Supabase)
- License management
- Update check

## System Requirements

- Windows 10/11 x64
- Administrative privileges (required for raw packet injection)
- Npcap (or WinPcap) installed
- .NET 8.0 runtime is bundled in the self-contained installer — no separate install required

## Installation

Run `installer/SEACURE(TOOL)_Setup_2.5.0.exe`. The installer:

- Detects previous installations and performs an in-place upgrade
- Registers uninstaller, desktop shortcut (optional), start menu group
- Installs to `C:\Program Files\SeaNet\SEACURE(TOOL)` by default
- Requires administrator elevation via UAC

## Building

Prerequisites:

- .NET 8 SDK
- Inno Setup 6 (`ISCC.exe` on PATH or at `C:\Program Files (x86)\Inno Setup 6\ISCC.exe`)
- PowerShell 5+ (for asset regeneration)

Build the executable and installer:

```
dotnet build Dorothy.csproj -c Release
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
```

The Release build self-publishes to `dist/` via the `CreateDistributionAfterBuild` MSBuild target. The installer packages everything from `dist/` plus `Run-Dorothy.ps1`.

Regenerating the installer sidebar, icon, and `logo.ico` from `Resources/logo.png`:

```
powershell -ExecutionPolicy Bypass -File .\create-installer-images.ps1
```

Output: `installer\SEACURE(TOOL)_Setup_<version>.exe`

## Version Bump

1. Edit `<Version>`, `<AssemblyVersion>`, `<FileVersion>` in `Dorothy.csproj`
2. Edit `#define AppVersion` in `installer.iss`
3. Rebuild

## Technical Stack

- .NET 8 / WPF
- SharpPcap 6.x + PacketDotNet 1.4 for raw packet injection
- Lextm.SharpSnmpLib for SNMP
- ClosedXML for Excel export
- Microsoft.Data.Sqlite for local store
- Supabase .NET client for cloud sync
- NLog for logging

## License

Proprietary. Copyright (C) 2024-2026 SeaNet Co., Ltd. All rights reserved.
