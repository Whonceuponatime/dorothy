@echo off
setlocal enabledelayedexpansion

REM ===========================================================
REM  SEACURE(TOOL) — builds BOTH Full and Lite installers
REM  Outputs (in installer\):
REM    SEACURE(TOOL)_Setup_2.5.3.exe       (~240 MB, full)
REM    SEACURE(TOOL)_Lite_Setup_2.5.3.exe  (~55 MB, lite)
REM ===========================================================

set PROJECT_DIR=%~dp0
cd /d "%PROJECT_DIR%"

set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
    echo [ERROR] Inno Setup compiler not found at %ISCC%
    echo         Install Inno Setup 6 or adjust ISCC path in this script.
    exit /b 2
)

echo.
echo === [1/4] Publishing FULL edition to dist\ ===
if exist dist rmdir /s /q dist
dotnet publish Dorothy.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o dist\ -nologo
if errorlevel 1 (
    echo [ERROR] Full publish failed.
    exit /b 1
)

echo.
echo === [2/4] Publishing LITE edition to dist-lite\ ===
if exist dist-lite rmdir /s /q dist-lite
dotnet publish Dorothy.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:LiteBuild=true -o dist-lite\ -nologo
if errorlevel 1 (
    echo [ERROR] Lite publish failed.
    exit /b 1
)

echo.
echo === [3/4] Compiling FULL installer ===
if exist "installer\SEACURE(TOOL)_Setup_2.5.3.exe" del "installer\SEACURE(TOOL)_Setup_2.5.3.exe"
%ISCC% installer.iss
if errorlevel 1 (
    echo [ERROR] Full installer compile failed.
    exit /b 1
)

echo.
echo === [4/4] Compiling LITE installer ===
if exist "installer\SEACURE(TOOL)_Lite_Setup_2.5.3.exe" del "installer\SEACURE(TOOL)_Lite_Setup_2.5.3.exe"
%ISCC% installer_lite.iss
if errorlevel 1 (
    echo [ERROR] Lite installer compile failed.
    exit /b 1
)

echo.
echo === Done ===
dir /b installer\SEACURE*.exe
echo.
for %%F in ("installer\SEACURE(TOOL)_Setup_2.5.3.exe" "installer\SEACURE(TOOL)_Lite_Setup_2.5.3.exe") do (
    if exist %%F (
        for %%A in (%%F) do echo   %%~nxA = %%~zA bytes
    )
)
endlocal
