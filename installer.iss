#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppName=DoS SeaCure(Tool)
AppVersion={#AppVersion}
AppId={{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}}
AppPublisher=SeaNet
AppPublisherURL=
DefaultDirName={autopf}\SeaNet\DoS SeaCure
DefaultGroupName=SeaNet\DoS SeaCure
UninstallDisplayIcon={app}\Dorothy.exe
Compression=lzma2
SolidCompression=yes
OutputDir=installer
OutputBaseFilename=DoS-SEACURE-Setup-{#AppVersion}
SetupIconFile=Resources\icon.ico
WizardImageFile=Resources\SEACURE(SHIELD).png
WizardSmallImageFile=Resources\SEACURE(SHIELD).png
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=commandline dialog
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
; Allow upgrades - uninstall previous version automatically
UninstallDisplayName=DoS SeaCure(Tool)
CreateUninstallRegKey=yes
Uninstallable=yes
VersionInfoVersion={#AppVersion}
VersionInfoCompany=SeaNet
VersionInfoProductName=DoS SeaCure(Tool)
VersionInfoDescription=DoS SeaCure(Tool)

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "uninstallshortcut"; Description: "Create uninstall shortcut in installation folder"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked checkedonce

[Files]
Source: "dist\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\DoS SeaCure"; Filename: "{app}\Dorothy.exe"
Name: "{group}\Uninstall DoS SeaCure"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"
Name: "{autodesktop}\DoS SeaCure"; Filename: "{app}\Dorothy.exe"; Tasks: desktopicon
Name: "{app}\Uninstall DoS SeaCure"; Filename: "{uninstallexe}"; IconFilename: "{uninstallexe}"; Tasks: uninstallshortcut

[Run]
; Program will be launched with admin privileges via CurStepChanged

[Code]
var
  UpgradePage: TOutputProgressWizardPage;

function InitializeSetup(): Boolean;
var
  Uninstaller: String;
  ResultCode: Integer;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('This application requires a 64-bit version of Windows.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  
  // Check if already installed and uninstall previous version
  if RegKeyExists(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}_is1') then
  begin
    if MsgBox('A previous version of DoS SeaCure(Tool) is already installed. It will be uninstalled before installing the new version.' + #13#10 + #13#10 + 'Continue?', mbConfirmation, MB_YESNO) = IDYES then
    begin
      RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}_is1', 'UninstallString', Uninstaller);
      if Uninstaller <> '' then
      begin
        Uninstaller := RemoveQuotes(Uninstaller);
        Exec(Uninstaller, '/SILENT', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      end;
    end
    else
    begin
      Result := False;
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


