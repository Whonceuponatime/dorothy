@echo off
echo Building Dorothy installer...
echo.

REM Check if Inno Setup is installed
set "INNO_SETUP=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%INNO_SETUP%" set "INNO_SETUP=%ProgramFiles%\Inno Setup 6\ISCC.exe"

if not exist "%INNO_SETUP%" (
    echo ERROR: Inno Setup Compiler not found!
    echo Please install Inno Setup from: https://jrsoftware.org/isdl.php
    echo Expected location: %INNO_SETUP%
    pause
    exit /b 1
)

REM Check if dist folder exists
if not exist "dist\Dorothy.exe" (
    echo ERROR: dist\Dorothy.exe not found!
    echo Please run 'dotnet build -c Release' first to create the distributable.
    pause
    exit /b 1
)

REM Extract version from Dorothy.csproj (simple PowerShell one-liner)
echo Extracting version from Dorothy.csproj...
for /f "tokens=*" %%i in ('powershell -Command "(Get-Content Dorothy.csproj -Raw) -match '<Version>([\d.]+)</Version>' | Out-Null; $matches[1]"') do set APP_VERSION=%%i

if "%APP_VERSION%"=="" (
    echo WARNING: Could not extract version, using default 1.0.0
    set APP_VERSION=1.0.0
) else (
    echo Found version: %APP_VERSION%
)

REM Create installer output directory
if not exist "installer" mkdir installer

REM Build the installer with version parameter
echo Compiling installer with version %APP_VERSION%...
"%INNO_SETUP%" "installer.iss" "/DAppVersion=%APP_VERSION%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Installer created successfully!
    echo Location: installer\SEACURE(TOOL)-setup %APP_VERSION%.exe
    echo Version: %APP_VERSION%
) else (
    echo.
    echo ERROR: Installer compilation failed!
    pause
    exit /b 1
)

pause


