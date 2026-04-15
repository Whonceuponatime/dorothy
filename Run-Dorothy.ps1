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
