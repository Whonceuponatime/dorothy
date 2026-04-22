#ifndef AppVersion
  #define AppVersion "2.5.0"
#endif

[Setup]
AppName=SEACURE(TOOL)
AppVersion={#AppVersion}
AppId={{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}}
AppPublisher=SeaNet Co., Ltd.
AppPublisherURL=https://seacuredb.com
AppSupportURL=https://seacuredb.com
AppUpdatesURL=https://seacuredb.com
DefaultDirName={autopf}\SeaNet\SEACURE(TOOL)
DefaultGroupName=SeaNet\SEACURE(TOOL)
UninstallDisplayIcon={app}\Dorothy.exe
Compression=lzma2
SolidCompression=yes
OutputDir=installer
OutputBaseFilename=SEACURE(TOOL)_Setup_{#AppVersion}
SetupIconFile=Resources\logo.ico
WizardImageFile=Resources\installer-sidebar.bmp
WizardSmallImageFile=Resources\installer-icon.bmp
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=SEACURE(TOOL)
CreateUninstallRegKey=yes
Uninstallable=yes
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
AppVerName=SEACURE(TOOL) {#AppVersion}
VersionInfoCompany=SeaNet Co., Ltd.
VersionInfoProductName=SEACURE(TOOL)
VersionInfoDescription=SEACURE(TOOL) - Network Security Testing Tool
VersionInfoCopyright=Copyright (C) 2024-2026 SeaNet Co., Ltd.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "uninstallshortcut"; Description: "Create uninstall shortcut in installation folder"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked checkedonce

[Files]
Source: "dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Run-Dorothy.ps1"; DestDir: "{app}"; Flags: ignoreversion
; WebView2 standalone (offline) runtime installer. Bundled so installs work
; on air-gapped / Windows 10 LTSC machines. Skipped at runtime if WebView2
; is already present (see [Run] Check: ShouldInstallWebView2).
Source: "installer\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\SEACURE(TOOL)"; Filename: "{app}\Dorothy.exe"
Name: "{group}\Uninstall SEACURE(TOOL)"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"
Name: "{autodesktop}\SEACURE(TOOL)"; Filename: "{app}\Dorothy.exe"; Tasks: desktopicon
Name: "{app}\Uninstall SEACURE(TOOL)"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"; Tasks: uninstallshortcut

[Run]
Filename: "{tmp}\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"; \
  Parameters: "/silent /install"; \
  StatusMsg: "Installing WebView2 runtime (offline installer)..."; \
  Check: ShouldInstallWebView2; \
  BeforeInstall: PrepareWebView2Install; \
  AfterInstall: AfterWebView2Install; \
  Flags: waituntilterminated
Filename: "{app}\Dorothy.exe"; \
  Description: "Launch SEACURE(TOOL)"; \
  Flags: shellexec nowait postinstall skipifsilent

[Code]
var
  UpgradePage: TOutputProgressWizardPage;

function IsWebView2Installed(): Boolean;
var
  Version: String;
begin
  Result := False;

  // System-wide 64-bit registration (most common on x64 Windows)
  if RegQueryStringValue(HKLM,
      'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version) then
  begin
    if (Version <> '') and (Version <> '0.0.0.0') then
    begin
      Result := True;
      Exit;
    end;
  end;

  // System-wide 32-bit registration (x86 Windows / some WebView2 deployments)
  if RegQueryStringValue(HKLM,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version) then
  begin
    if (Version <> '') and (Version <> '0.0.0.0') then
    begin
      Result := True;
      Exit;
    end;
  end;

  // Per-user registration (evergreen fallback)
  if RegQueryStringValue(HKCU,
      'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
      'pv', Version) then
  begin
    if (Version <> '') and (Version <> '0.0.0.0') then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function ShouldInstallWebView2(): Boolean;
begin
  Result := not IsWebView2Installed();
end;

procedure PrepareWebView2Install();
begin
  if ShouldInstallWebView2() then
  begin
    WizardForm.ProgressGauge.Style := npbstMarquee;
    WizardForm.StatusLabel.Caption :=
      'Installing WebView2 Runtime (offline, bundled). ' +
      'This may take 30-60 seconds...';
    WizardForm.Update;
  end;
end;

procedure AfterWebView2Install();
begin
  WizardForm.ProgressGauge.Style := npbstNormal;
end;

function GetMajorMinorVersion(Version: String): String;
var
  DotPos1, DotPos2: Integer;
begin
  // Extract major.minor version (e.g., "2.1" from "2.1.1")
  DotPos1 := Pos('.', Version);
  if DotPos1 = 0 then
  begin
    Result := Version;
    Exit;
  end;
  
  DotPos2 := Pos('.', Copy(Version, DotPos1 + 1, Length(Version)));
  if DotPos2 = 0 then
  begin
    Result := Version;
    Exit;
  end;
  
  // Return major.minor (everything up to second dot)
  Result := Copy(Version, 1, DotPos1 + DotPos2 - 1);
end;

function InitializeSetup(): Boolean;
var
  Uninstaller: String;
  InstalledVersion: String;
  CurrentVersion: String;
  InstalledMajorMinor: String;
  CurrentMajorMinor: String;
  ResultCode: Integer;
  IsPatchUpdate: Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('This application requires a 64-bit version of Windows.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  
  CurrentVersion := '{#AppVersion}';
  
  // Check if already installed
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}_is1') then
  begin
    // Get installed version
    RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}_is1', 'DisplayVersion', InstalledVersion);
    
    if InstalledVersion = '' then
    begin
      InstalledVersion := 'Unknown';
    end;
    
    // Check if this is a patch update (same major.minor, different patch)
    // e.g., 2.1.0 -> 2.1.1 is a patch update
    InstalledMajorMinor := GetMajorMinorVersion(InstalledVersion);
    CurrentMajorMinor := GetMajorMinorVersion(CurrentVersion);
    IsPatchUpdate := (InstalledMajorMinor <> '') and (CurrentMajorMinor <> '') and (InstalledMajorMinor = CurrentMajorMinor);
    
    if IsPatchUpdate then
    begin
      // Patch update - silent uninstall and reinstall (no user prompt)
      RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}_is1', 'UninstallString', Uninstaller);
      if Uninstaller <> '' then
      begin
        Uninstaller := RemoveQuotes(Uninstaller);
        // Silent uninstall for patch updates
        Exec(Uninstaller, '/SILENT', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        // Wait a moment for registry to update
        Sleep(1000);
      end;
    end
    else
    begin
      // Full upgrade - ask user
      if MsgBox('A previous version of SEACURE(TOOL) (v' + InstalledVersion + ') is already installed.' + #13#10 + 
                'It will be upgraded to version ' + CurrentVersion + '.' + #13#10 + #13#10 + 
                'Continue?', mbConfirmation, MB_YESNO) = IDYES then
      begin
        RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}_is1', 'UninstallString', Uninstaller);
        if Uninstaller <> '' then
        begin
          Uninstaller := RemoveQuotes(Uninstaller);
          Exec(Uninstaller, '/SILENT', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
          // Wait a moment for registry to update
          Sleep(1000);
        end;
      end
      else
      begin
        Result := False;
      end;
    end;
  end;
end;

procedure InitializeWizard();
begin
  UpgradePage := CreateOutputProgressPage('Upgrading Installation', 'Please wait while the previous version is being removed...');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  // Post-install launch is handled by the [Run] section checkbox above.
  // No manual Exec call needed here.
end;

