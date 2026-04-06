# Dorothy requires Administrator (app.manifest). Non-elevated "dotnet run" fails with Win32 740.
# Run this script; accept the UAC prompt to build (if needed) and start the app elevated.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $hostExe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $hostExe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}
dotnet build Dorothy.csproj -c Release
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet run --project Dorothy.csproj -c Release --no-build
