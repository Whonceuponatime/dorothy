# Building the Installer

This project includes an Inno Setup installer script to create a professional Windows installer.

## Prerequisites

1. **Install Inno Setup** (free):
   - Download from: https://jrsoftware.org/isdl.php
   - Install the latest version (6.x recommended)

2. **Build the distributable**:
   ```bash
   dotnet build -c Release
   ```
   This creates the `dist/` folder with all necessary files.

## Building the Installer

### Option 1: Using PowerShell (Recommended)
```powershell
.\build-installer.ps1
```

### Option 2: Using Batch File
```cmd
build-installer.bat
```

### Option 3: Manual Build
1. Open Inno Setup Compiler
2. Open `installer.iss`
3. Click "Build" → "Compile"

## Output

The installer will be created at:
```
installer/DoS-SEACURE-Setup-X.X.X.exe
```

The version number is automatically extracted from `Dorothy.csproj` and included in the filename.

## Installer Features

- ✅ Single executable installer
- ✅ Installs to Program Files
- ✅ Creates Start Menu shortcuts
- ✅ Optional desktop shortcut
- ✅ Includes uninstaller
- ✅ Professional Windows installer UI
- ✅ Bundles all DLLs and dependencies
- ✅ **Automatic version detection** - Reads version from `Dorothy.csproj`
- ✅ **Upgrade support** - Automatically uninstalls previous version when updating

## Versioning and Updates

The installer automatically:
1. Extracts the version from `Dorothy.csproj` (`<Version>X.X.X</Version>`)
2. Includes it in the installer filename
3. Detects and upgrades existing installations

**To create an update:**
1. Update the version in `Dorothy.csproj`
2. Build: `dotnet build -c Release`
3. Build installer: `.\build-installer.ps1`
4. Distribute the new `DoS-SEACURE-Setup-X.X.X.exe`

See `VERSIONING.md` for detailed versioning guidelines.

## Distribution

You can distribute the single `DoS-SEACURE-Setup-X.X.X.exe` file. Users just need to:
1. Run the installer
2. Follow the installation wizard (it will automatically upgrade if a previous version exists)
3. Launch from Start Menu or desktop shortcut

The installer handles all file organization automatically!


