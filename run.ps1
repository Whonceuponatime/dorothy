# Run script for Dorothy (Windows PowerShell)
# Usage: .\run.ps1 [Release|Debug]

param(
    [string]$Configuration = "Release"
)

$exePath = "bin\x64\$Configuration\net8.0\win-x64\Dorothy.exe"

if (-not (Test-Path $exePath)) {
    Write-Host "Executable not found. Building first..." -ForegroundColor Yellow
    .\build.ps1 -Configuration $Configuration
}

if (Test-Path $exePath) {
    Write-Host "Running Dorothy..." -ForegroundColor Green
    & $exePath
} else {
    Write-Host "ERROR: Could not find executable at $exePath" -ForegroundColor Red
    exit 1
}

