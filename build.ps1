# Build script for Dorothy (Windows PowerShell)
# Usage: .\build.ps1 [Release|Debug]

param(
    [string]$Configuration = "Release"
)

Write-Host "Building Dorothy..." -ForegroundColor Green
Write-Host "Configuration: $Configuration" -ForegroundColor Cyan

# Build the project
dotnet build -c $Configuration

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild completed successfully!" -ForegroundColor Green
    $outputPath = "bin\x64\$Configuration\net8.0\win-x64\Dorothy.exe"
    if (Test-Path $outputPath) {
        Write-Host "Output: $outputPath" -ForegroundColor Cyan
    }
} else {
    Write-Host "`nBuild failed!" -ForegroundColor Red
    exit 1
}

