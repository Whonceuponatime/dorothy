#ifndef AppVersion
  #define AppVersion "2.2.0"
#endif

[Setup]
AppName=SEACURE(TOOL)
AppVersion={#AppVersion}
AppId={{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}}
AppPublisher=SeaNet
AppPublisherURL=
DefaultDirName={autopf}\SeaNet\SEACURE(TOOL)
DefaultGroupName=SeaNet\SEACURE(TOOL)
UninstallDisplayIcon={app}\Dorothy.exe
Compression=lzma2
SolidCompression=yes
OutputDir=installer
OutputBaseFilename=SEACURE(TOOL)-setup {#AppVersion}
SetupIconFile=Resources\icon.ico
WizardImageFile=Resources\SEACURE(SHIELD).png
WizardSmallImageFile=Resources\SEACURE(SHIELD).png
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
; Allow upgrades - uninstall previous version automatically
UninstallDisplayName=SEACURE(TOOL)
CreateUninstallRegKey=yes
Uninstallable=yes
VersionInfoVersion={#AppVersion}
; Enable automatic upgrade detection
AppVerName=SEACURE(TOOL) {#AppVersion}
VersionInfoCompany=SeaNet
VersionInfoProductName=SEACURE(TOOL)
VersionInfoDescription=SEACURE(TOOL)

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "uninstallshortcut"; Description: "Create uninstall shortcut in installation folder"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked checkedonce

[Files]
Source: "dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SEACURE(TOOL)"; Filename: "{app}\Dorothy.exe"
Name: "{group}\Uninstall SEACURE(TOOL)"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"
Name: "{autodesktop}\SEACURE(TOOL)"; Filename: "{app}\Dorothy.exe"; Tasks: desktopicon
Name: "{app}\Uninstall SEACURE(TOOL)"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"; Tasks: uninstallshortcut

[Run]
; Program will be launched with admin privileges via CurStepChanged

[Code]
var
  UpgradePage: TOutputProgressWizardPage;

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
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    // Launch program after installation (manifest will request admin elevation)
    if not WizardSilent() then
    begin
      // Since installer is already admin, use Exec - manifest will ensure program runs as admin
      Exec(ExpandConstant('{app}\Dorothy.exe'), '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
    end;
  end;
end;


