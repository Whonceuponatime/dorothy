# Publish script for Dorothy (Windows PowerShell)
# Usage: .\publish.ps1 [win-x64|linux-x64|linux-arm64|osx-x64]

param(
    [string]$Runtime = "win-x64"
)

Write-Host "Publishing Dorothy for $Runtime..." -ForegroundColor Green

# Validate runtime identifier
$validRuntimes = @("win-x64", "linux-x64", "linux-arm64", "osx-x64")
if ($validRuntimes -notcontains $Runtime) {
    Write-Host "ERROR: Invalid runtime identifier: $Runtime" -ForegroundColor Red
    Write-Host "Valid runtimes: $($validRuntimes -join ', ')" -ForegroundColor Yellow
    exit 1
}

# Publish the project
dotnet publish -c Release -r $Runtime --self-contained

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nPublish completed successfully!" -ForegroundColor Green
    $publishPath = "bin\Release\net8.0\$Runtime\publish"
    if (Test-Path $publishPath) {
        Write-Host "Published files location: $publishPath" -ForegroundColor Cyan
        
        # Show executable name based on platform
        if ($Runtime -like "win-*") {
            $exeName = "Dorothy.exe"
        } else {
            $exeName = "Dorothy"
        }
        
        $exePath = Join-Path $publishPath $exeName
        if (Test-Path $exePath) {
            Write-Host "Executable: $exePath" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "`nPublish failed!" -ForegroundColor Red
    exit 1
}

