# Build installer script for Dorothy
# Requires Inno Setup Compiler to be installed

Write-Host "Building Dorothy installer..." -ForegroundColor Green

# Check if Inno Setup is installed
$innoSetupPath = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $innoSetupPath)) {
    $innoSetupPath = "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
}

if (-not (Test-Path $innoSetupPath)) {
    Write-Host "ERROR: Inno Setup Compiler not found!" -ForegroundColor Red
    Write-Host "Please install Inno Setup from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host "Expected location: $innoSetupPath" -ForegroundColor Yellow
    exit 1
}

# Ensure dist folder exists and has files
if (-not (Test-Path "dist\Dorothy.exe")) {
    Write-Host "ERROR: dist\Dorothy.exe not found!" -ForegroundColor Red
    Write-Host "Please run 'dotnet build -c Release' first to create the distributable." -ForegroundColor Yellow
    exit 1
}

# Extract version from Dorothy.csproj
Write-Host "Extracting version from Dorothy.csproj..." -ForegroundColor Cyan
$csprojContent = Get-Content "Dorothy.csproj" -Raw
if ($csprojContent -match '<Version>([\d.]+)</Version>') {
    $appVersion = $matches[1]
    Write-Host "Found version: $appVersion" -ForegroundColor Green
} else {
    Write-Host "WARNING: Could not extract version from Dorothy.csproj, using default 1.0.0" -ForegroundColor Yellow
    $appVersion = "1.0.0"
}

# Create installer output directory
if (-not (Test-Path "installer")) {
    New-Item -ItemType Directory -Path "installer" | Out-Null
}

# Clean up any existing installer files that might be locked
Write-Host "Cleaning up existing installer files..." -ForegroundColor Cyan
$installerFile = "installer\DoS-SEACURE-Setup-$appVersion.exe"
if (Test-Path $installerFile) {
    try {
        # Try to remove the file
        Remove-Item $installerFile -Force -ErrorAction Stop
        Write-Host "Removed existing installer file." -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not remove existing installer file. It may be locked by antivirus or another process." -ForegroundColor Yellow
        Write-Host "Try closing any antivirus software or exclude the 'installer' folder from antivirus scanning." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
}

# Also remove any other installer files in the directory
Get-ChildItem "installer\*.exe" -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    } catch {
        # Ignore errors for locked files
    }
}

# Build the installer with version parameter
Write-Host "Compiling installer with version $appVersion..." -ForegroundColor Cyan
& $innoSetupPath "installer.iss" "/DAppVersion=$appVersion"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nInstaller created successfully!" -ForegroundColor Green
    Write-Host "Location: installer\DoS-SEACURE-Setup-$appVersion.exe" -ForegroundColor Cyan
    Write-Host "`nVersion: $appVersion" -ForegroundColor Cyan
} else {
    Write-Host "`nERROR: Installer compilation failed!" -ForegroundColor Red
    Write-Host "`nCommon causes:" -ForegroundColor Yellow
    Write-Host "  1. Antivirus software is blocking file access" -ForegroundColor Yellow
    Write-Host "  2. The installer file is locked by another process" -ForegroundColor Yellow
    Write-Host "  3. Insufficient permissions" -ForegroundColor Yellow
    Write-Host "`nTry:" -ForegroundColor Yellow
    Write-Host "  - Exclude the 'installer' folder from antivirus scanning" -ForegroundColor Yellow
    Write-Host "  - Close any programs that might be using the installer file" -ForegroundColor Yellow
    Write-Host "  - Run PowerShell as Administrator" -ForegroundColor Yellow
    exit 1
}


