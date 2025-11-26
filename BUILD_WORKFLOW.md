# Build and Test Workflow

This guide explains the complete workflow for building, testing, and creating the installer.

## Complete Workflow

### Step 1: Build the Application

```powershell
dotnet build -c Release
```

**What this does:**
- Compiles the application in Release mode
- Automatically creates the `dist/` folder with all necessary files
- Output location: `bin\Release\net8.0-windows\win-x64\`

### Step 2: Test the Application

**Option A: Test from Build Output (Recommended)**
```powershell
# Run the executable directly
.\bin\Release\net8.0-windows\win-x64\Dorothy.exe
```

**Option B: Test from Distribution Folder**
```powershell
# Run from the dist folder (same files that will be in installer)
.\dist\Dorothy.exe
```

**What to test:**
- ✅ Application launches correctly
- ✅ UI displays properly (logos, layout)
- ✅ All features work as expected
- ✅ Network interface selection works
- ✅ Attacks can be started/stopped
- ✅ Logging works correctly
- ✅ Admin privileges are requested (UAC prompt)

### Step 3: Create the Installer

**Only after testing is successful:**

```powershell
.\build-installer.ps1
```

**What this does:**
- Extracts version from `Dorothy.csproj`
- Compiles the Inno Setup installer
- Creates: `installer\DoS-SEACURE-Setup-X.X.X.exe`

### Step 4: Test the Installer

1. **Test Fresh Install:**
   - Uninstall any existing version (if installed)
   - Run the installer: `.\installer\DoS-SEACURE-Setup-X.X.X.exe`
   - Verify installation completes
   - Check Start Menu shortcuts
   - Launch the program

2. **Test Upgrade:**
   - Install an older version first
   - Run the new installer
   - Verify it upgrades correctly
   - Verify program still works

## Quick Reference Commands

### Full Workflow (One-liner)
```powershell
# Build, then test, then create installer
dotnet build -c Release; .\bin\Release\net8.0-windows\win-x64\Dorothy.exe
# After testing, create installer:
.\build-installer.ps1
```

### Step-by-Step (Recommended)
```powershell
# 1. Build
dotnet build -c Release

# 2. Test (run the application)
.\bin\Release\net8.0-windows\win-x64\Dorothy.exe

# 3. If tests pass, create installer
.\build-installer.ps1

# 4. Test installer
.\installer\DoS-SEACURE-Setup-X.X.X.exe
```

## Troubleshooting

### Build Fails
- Check for compilation errors
- Ensure all dependencies are installed
- Verify `Resources\` folder has all required files

### Application Doesn't Run
- Check if .NET 8.0 Desktop Runtime is installed
- Verify admin privileges (should prompt UAC)
- Check Windows Event Viewer for errors

### Installer Fails to Build
- Ensure Inno Setup is installed
- Check if `dist\Dorothy.exe` exists
- Try excluding `installer` folder from antivirus
- Check `installer.iss` for syntax errors

### Installer Doesn't Work
- Test on a clean system if possible
- Check Windows Event Viewer
- Verify all files are in `dist\` folder
- Ensure installer has admin privileges

## Best Practices

1. **Always test before creating installer** - Don't skip testing!
2. **Test on clean system** - If possible, test installer on a VM or different machine
3. **Version control** - Update version number before building installer
4. **Document changes** - Keep track of what changed in each version
5. **Test upgrades** - Always test upgrading from previous version

## File Locations

- **Build Output**: `bin\Release\net8.0-windows\win-x64\`
- **Distribution Files**: `dist\` (created automatically)
- **Installer**: `installer\DoS-SEACURE-Setup-X.X.X.exe`
- **Source Code**: Root directory

