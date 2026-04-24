#ifndef AppVersion
  #define AppVersion "2.5.1"
#endif

[Setup]
AppName=SEACURE(TOOL) Lite
AppVersion={#AppVersion}
; DIFFERENT AppId from the Full installer so both editions can coexist
; side-by-side without the installer attempting a cross-edition upgrade.
AppId={{F9D4A7C3-2E1B-4F8A-9D3C-8A7B5C4E2F1A}}
AppPublisher=SeaNet Co., Ltd.
AppPublisherURL=https://seacuredb.com
AppSupportURL=https://seacuredb.com
AppUpdatesURL=https://seacuredb.com
DefaultDirName={autopf}\SeaNet\SEACURE(TOOL) Lite
DefaultGroupName=SeaNet\SEACURE(TOOL) Lite
UninstallDisplayIcon={app}\Dorothy.exe
Compression=lzma2
SolidCompression=yes
OutputDir=installer
OutputBaseFilename=SEACURE(TOOL)_Lite_Setup_{#AppVersion}
SetupIconFile=Resources\logo.ico
WizardImageFile=Resources\installer-sidebar.bmp
WizardSmallImageFile=Resources\installer-icon.bmp
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName=SEACURE(TOOL) Lite
CreateUninstallRegKey=yes
Uninstallable=yes
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
AppVerName=SEACURE(TOOL) Lite {#AppVersion}
VersionInfoCompany=SeaNet Co., Ltd.
VersionInfoProductName=SEACURE(TOOL) Lite
VersionInfoDescription=SEACURE(TOOL) Lite - Network Attack Simulator (Basic Settings only)
VersionInfoCopyright=Copyright (C) 2024-2026 SeaNet Co., Ltd.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "uninstallshortcut"; Description: "Create uninstall shortcut in installation folder"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked checkedonce

[Files]
; Lite edition ships without WebView2 — Network Intelligence tab is removed
; at runtime so the canvas is never instantiated. Source is dist-lite/,
; produced by: dotnet publish -c Release -r win-x64 --self-contained -p:LiteBuild=true
Source: "dist-lite\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Run-Dorothy.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SEACURE(TOOL) Lite"; Filename: "{app}\Dorothy.exe"
Name: "{group}\Uninstall SEACURE(TOOL) Lite"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"
Name: "{autodesktop}\SEACURE(TOOL) Lite"; Filename: "{app}\Dorothy.exe"; Tasks: desktopicon
Name: "{app}\Uninstall SEACURE(TOOL) Lite"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"; Tasks: uninstallshortcut

[Run]
; No WebView2 runtime install step — Lite doesn't use it.
Filename: "{app}\Dorothy.exe"; \
  Description: "Launch SEACURE(TOOL) Lite"; \
  Flags: shellexec nowait postinstall skipifsilent

[Code]
var
  UpgradePage: TOutputProgressWizardPage;

function GetMajorMinorVersion(Version: String): String;
var
  DotPos1, DotPos2: Integer;
begin
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

  // Check for an existing Lite install under its own AppId (not the Full one)
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F9D4A7C3-2E1B-4F8A-9D3C-8A7B5C4E2F1A}_is1') then
  begin
    RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F9D4A7C3-2E1B-4F8A-9D3C-8A7B5C4E2F1A}_is1', 'DisplayVersion', InstalledVersion);

    if InstalledVersion = '' then
    begin
      InstalledVersion := 'Unknown';
    end;

    InstalledMajorMinor := GetMajorMinorVersion(InstalledVersion);
    CurrentMajorMinor := GetMajorMinorVersion(CurrentVersion);
    IsPatchUpdate := (InstalledMajorMinor <> '') and (CurrentMajorMinor <> '') and (InstalledMajorMinor = CurrentMajorMinor);

    if IsPatchUpdate then
    begin
      RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F9D4A7C3-2E1B-4F8A-9D3C-8A7B5C4E2F1A}_is1', 'UninstallString', Uninstaller);
      if Uninstaller <> '' then
      begin
        Uninstaller := RemoveQuotes(Uninstaller);
        Exec(Uninstaller, '/SILENT', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Sleep(1000);
      end;
    end
    else
    begin
      if MsgBox('A previous version of SEACURE(TOOL) Lite (v' + InstalledVersion + ') is already installed.' + #13#10 +
                'It will be upgraded to version ' + CurrentVersion + '.' + #13#10 + #13#10 +
                'Continue?', mbConfirmation, MB_YESNO) = IDYES then
      begin
        RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{F9D4A7C3-2E1B-4F8A-9D3C-8A7B5C4E2F1A}_is1', 'UninstallString', Uninstaller);
        if Uninstaller <> '' then
        begin
          Uninstaller := RemoveQuotes(Uninstaller);
          Exec(Uninstaller, '/SILENT', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
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
