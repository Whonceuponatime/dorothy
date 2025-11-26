# Patching Guide - How to Release Updates

This guide explains how to release patches and updates for DoS SeaCure(Tool).

## Version Numbering

Follow **Semantic Versioning**: `MAJOR.MINOR.PATCH`
- **MAJOR** (2.x.x): Breaking changes, major rewrites
- **MINOR** (x.1.x): New features, backward compatible
- **PATCH** (x.x.1): Bug fixes, small improvements, UI updates

## Step-by-Step Patching Process

### 1. Update Version Number

Edit `Dorothy.csproj`:
```xml
<Version>2.0.1</Version>  <!-- Increment patch number -->
```

### 2. Make Your Changes

- Fix bugs
- Update UI
- Add features
- Update logos/resources

### 3. Test Your Changes

```powershell
# Build and test locally
dotnet build -c Release
# Run from: bin\Release\net8.0-windows\win-x64\Dorothy.exe
```

### 4. Build Distributable

```powershell
dotnet build -c Release
```

This automatically creates the `dist/` folder with all files.

### 5. Build Installer

```powershell
.\build-installer.ps1
```

This creates: `installer\DoS-SEACURE-Setup-X.X.X.exe`

### 6. Test the Installer

1. Install the new version
2. Verify it upgrades from previous version correctly
3. Test all functionality
4. Check that uninstaller works

### 7. Document Changes (Optional but Recommended)

Create or update `CHANGELOG.md`:
```markdown
## [2.0.1] - 2025-01-XX
### Fixed
- Logo size issue in main window
- Installer wizard images updated

### Changed
- Updated main logo to use larger size (200x80px)
- Installer now uses SEACURE shield logo
```

## Distribution

### For End Users

Distribute the single installer file:
- `installer\DoS-SEACURE-Setup-2.0.1.exe`

Users can:
1. Download the new installer
2. Run it (it will automatically detect and upgrade)
3. Follow the installation wizard

### Version History Tracking

Keep track of versions:
- Version number in `Dorothy.csproj`
- Installer filename includes version
- Windows Control Panel shows version
- Consider maintaining `CHANGELOG.md`

## Quick Reference

```powershell
# Complete patch release workflow:
# 1. Update version in Dorothy.csproj
# 2. Make changes
# 3. Build
dotnet build -c Release

# 4. Build installer
.\build-installer.ps1

# 5. Test installer
# 6. Distribute installer\DoS-SEACURE-Setup-X.X.X.exe
```

## Common Patch Scenarios

### UI Fixes (Logo, Layout, etc.)
1. Update version: `2.0.0` → `2.0.1`
2. Fix UI in XAML files
3. Build → Create installer → Distribute

### Bug Fixes
1. Update version: `2.0.0` → `2.0.1`
2. Fix bugs in code
3. Build → Create installer → Distribute

### New Features
1. Update version: `2.0.0` → `2.1.0` (minor version bump)
2. Add features
3. Build → Create installer → Distribute

### Major Updates
1. Update version: `2.0.0` → `3.0.0` (major version bump)
2. Major changes/rewrites
3. Build → Create installer → Distribute

## Notes

- **Always test upgrades** - Install old version, then upgrade to new version
- **Version is automatic** - Extracted from `Dorothy.csproj` automatically
- **Installer handles upgrades** - Automatically uninstalls old version
- **Keep it simple** - One installer file, one version number

