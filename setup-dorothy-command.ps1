# Setup script to create 'dorothy' command alias (Windows PowerShell)
# Run this script as Administrator or with appropriate permissions

Write-Host "Setting up 'dorothy' command..." -ForegroundColor Green

# Get the current script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$publishPath = Join-Path $scriptDir "bin\Release\net8.0\win-x64\publish\Dorothy.exe"

# Check if published executable exists
if (-not (Test-Path $publishPath)) {
    Write-Host "Published executable not found. Publishing first..." -ForegroundColor Yellow
    & "$scriptDir\publish.ps1" -Runtime "win-x64"
    
    if (-not (Test-Path $publishPath)) {
        Write-Host "ERROR: Could not find executable at $publishPath" -ForegroundColor Red
        Write-Host "Please run: .\publish.ps1 -Runtime win-x64" -ForegroundColor Yellow
        exit 1
    }
}

# Create a wrapper script in a location in PATH
$wrapperScript = "$env:USERPROFILE\dorothy.ps1"
$wrapperContent = @"
# Dorothy launcher script
& '$publishPath' `$args
"@

$wrapperContent | Out-File -FilePath $wrapperScript -Encoding UTF8 -Force
Write-Host "Created wrapper script: $wrapperScript" -ForegroundColor Cyan

# Add to PATH if not already there
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$homeDir = $env:USERPROFILE

if ($userPath -notlike "*$homeDir*") {
    Write-Host "Adding user home directory to PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$homeDir", "User")
    Write-Host "PATH updated. Please restart your terminal for changes to take effect." -ForegroundColor Yellow
} else {
    Write-Host "User home directory already in PATH." -ForegroundColor Green
}

# Create a function in PowerShell profile
$profilePath = $PROFILE
$profileDir = Split-Path -Parent $profilePath

if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

$functionContent = @"

# Dorothy command alias
function dorothy {
    & '$publishPath' `$args
}
"@

if (Test-Path $profilePath) {
    $profileContent = Get-Content $profilePath -Raw
    if ($profileContent -notlike "*function dorothy*") {
        Add-Content -Path $profilePath -Value $functionContent
        Write-Host "Added 'dorothy' function to PowerShell profile." -ForegroundColor Green
    } else {
        Write-Host "'dorothy' function already exists in PowerShell profile." -ForegroundColor Yellow
    }
} else {
    $functionContent | Out-File -FilePath $profilePath -Encoding UTF8
    Write-Host "Created PowerShell profile with 'dorothy' function." -ForegroundColor Green
}

Write-Host "`nSetup complete!" -ForegroundColor Green
Write-Host "You can now use 'dorothy' command in PowerShell." -ForegroundColor Cyan
Write-Host "If the command doesn't work, restart your terminal or run: . `$PROFILE" -ForegroundColor Yellow

