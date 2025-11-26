# Versioning and Update Guide

## How Versioning Works

The application version is managed in `Dorothy.csproj`:
```xml
<Version>1.0.0</Version>
```

When you build the installer, the version is automatically extracted and included in:
- The installer filename: `Dorothy-Setup-1.0.0.exe`
- The Windows installation metadata
- The application's version info

## Creating Updates/Patches

### Step 1: Update Version Number

Edit `Dorothy.csproj` and increment the version:

```xml
<!-- For patch/bugfix updates -->
<Version>1.0.1</Version>

<!-- For minor feature updates -->
<Version>1.1.0</Version>

<!-- For major updates -->
<Version>2.0.0</Version>
```

**Version Format:** `MAJOR.MINOR.PATCH`
- **MAJOR**: Breaking changes, major rewrites
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, small improvements

### Step 2: Build the Application

```bash
dotnet build -c Release
```

This creates the updated files in the `dist/` folder.

### Step 3: Build the Installer

```powershell
.\build-installer.ps1
```

Or:
```cmd
build-installer.bat
```

This creates `installer/Dorothy-Setup-1.0.1.exe` (with your new version).

## How Updates Work for End Users

### Automatic Upgrade Detection

When a user runs a newer installer:

1. **Installer detects previous version** - Checks Windows registry for existing installation
2. **Prompts user** - "A previous version is installed. It will be uninstalled before installing the new version. Continue?"
3. **Uninstalls old version** - Silently removes previous installation
4. **Installs new version** - Installs the updated files
5. **Preserves settings** - User settings in AppData are preserved (if you implement settings storage)

### Manual Update Process

Users can also:
1. Download the new installer (`Dorothy-Setup-X.X.X.exe`)
2. Run it - it will automatically detect and upgrade
3. Or uninstall from Control Panel first, then install new version

## Distribution Strategy

### Option 1: Full Installer (Recommended)
- **File**: `Dorothy-Setup-1.0.1.exe`
- **Size**: ~50-100 MB (includes all dependencies)
- **Use Case**: First-time installs, major updates
- **Pros**: Self-contained, no prerequisites
- **Cons**: Larger download

### Option 2: Patch/Update Package (Future Enhancement)
For smaller updates, you could create a patch system that only downloads changed files. This requires:
- Update server/API
- Update checker in the application
- Delta patching mechanism

## Version History Tracking

Consider maintaining a `CHANGELOG.md`:

```markdown
# Changelog

## [1.0.1] - 2025-01-15
### Fixed
- Gateway MAC resolution issue with multiple NICs
- Log formatting improvements

## [1.0.0] - 2025-01-01
### Added
- Initial release
- Basic attack types
- Network interface selection
```

## Best Practices

1. **Always increment version** before building installer
2. **Test the upgrade path** - Install old version, then upgrade
3. **Document changes** in CHANGELOG.md
4. **Use semantic versioning** (MAJOR.MINOR.PATCH)
5. **Keep installer filename** with version for easy identification
6. **Test on clean system** - Ensure fresh installs work

## Troubleshooting

### Installer says "Already installed" but won't upgrade
- Check Windows Registry: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`
- Look for entry with AppId: `{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}`
- Manually uninstall from Control Panel if needed

### Version not updating in installer filename
- Ensure `build-installer.ps1` successfully extracts version from `.csproj`
- Check that version format matches: `X.Y.Z` (numbers and dots only)

### Users report "corrupted installation" after update
- Ensure all files are properly replaced
- Check that `[Files]` section uses `ignoreversion` flag (already set)
- Test upgrade path thoroughly before distribution

