#define MyAppName "SentryLoom HQ"
#define MyAppVersion "0.4.4"
#define MyAppPublisher "NUC7 Studios"

[Setup]
AppId={{3E7A32CD-B4D2-47FD-A96A-AB441768EBB0}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\SentryLoom HQ
DefaultGroupName=SentryLoom
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=SentryLoom-HQ-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern dynamic
CloseApplications=force
RestartApplications=no
SetupLogging=yes
UninstallDisplayName={#MyAppName}
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=SentryLoom HQ management server installer
VersionInfoCopyright=Copyright (c) 2026 NUC7 Studios
SetupIconFile=..\assets\SentryLoom.ico

[Files]
Source: "..\server\config.example.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Initialize-SentryLoomHq.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Install-SentryLoomHq.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Remove-SentryLoomHq.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Start-SentryLoomHq.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Restart-SentryLoomHq.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Restart-SentryLoomHq-Admin.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\Publish-SentryLoomUpdate.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\public\*"; DestDir: "{app}\public"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\server\src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Open SentryLoom HQ"; Filename: "{app}\SentryLoom HQ.url"
Name: "{group}\Restart SentryLoom HQ"; Filename: "{app}\Restart-SentryLoomHq-Admin.bat"; WorkingDir: "{app}"

[UninstallRun]
Filename: "{code:GetPowerShellPath}"; Parameters: "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\Remove-SentryLoomHq.ps1"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "SentryLoomHqCleanup"

[Code]
var
  HqPage: TInputQueryWizardPage;
  PasswordPage: TInputQueryWizardPage;
  InstallDetails: TNewMemo;

function SetEnvironmentVariable(lpName, lpValue: String): Boolean;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

function GetPowerShellPath(Param: String): String;
begin
  Result := ExpandConstant('{pf64}\PowerShell\7\pwsh.exe');
  if not FileExists(Result) then
    Result := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
end;

function GetNodePath: String;
begin
  Result := ExpandConstant('{pf64}\nodejs\node.exe');
end;

function GetWingetPath: String;
begin
  Result := ExpandConstant('{localappdata}\Microsoft\WindowsApps\winget.exe');
  if not FileExists(Result) then
    Result := 'winget.exe';
end;

function InvalidArgument(Value: String): Boolean;
begin
  Result :=
    (Pos('"', Value) > 0) or
    (Pos(#13, Value) > 0) or
    (Pos(#10, Value) > 0);
end;

procedure InitializeWizard;
begin
  HqPage := CreateInputQueryPage(
    wpSelectDir,
    'Configure SentryLoom HQ',
    'Create the local management service',
    'Choose the DNS name clients use to reach this server. Setup creates a self-signed certificate, firewall rules, and a self-restarting startup task.');
  HqPage.Add('HQ display name:', False);
  HqPage.Add('Public DNS name or computer name:', False);
  HqPage.Add('HTTPS port:', False);
  HqPage.Values[0] := 'SentryLoom HQ';
  HqPage.Values[1] := GetComputerNameString;
  HqPage.Values[2] := '8443';

  PasswordPage := CreateInputQueryPage(
    HqPage.ID,
    'Set the administrator password',
    'Protect the SentryLoom HQ console',
    'Enter the password administrators will use to sign in. It must contain 12 to 128 characters.');
  PasswordPage.Add('Administrator password:', True);
  PasswordPage.Add('Confirm administrator password:', True);

  InstallDetails := TNewMemo.Create(WizardForm);
  InstallDetails.Parent := WizardForm.InstallingPage;
  InstallDetails.Left := ScaleX(0);
  InstallDetails.Top := WizardForm.ProgressGauge.Top + WizardForm.ProgressGauge.Height + ScaleY(18);
  InstallDetails.Width := WizardForm.InstallingPage.ClientWidth;
  InstallDetails.Height := WizardForm.InstallingPage.ClientHeight - InstallDetails.Top;
  InstallDetails.ReadOnly := True;
  InstallDetails.ScrollBars := ssVertical;
  InstallDetails.WordWrap := True;
  InstallDetails.Color := clWindow;
end;

procedure InstallDetail(Message: String);
begin
  WizardForm.StatusLabel.Caption := Message;
  InstallDetails.Lines.Add(GetDateTimeString('hh:nn:ss', '-', ':') + '  ' + Message);
  InstallDetails.SelStart := Length(InstallDetails.Text);
  WizardForm.Update;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Port: Integer;
begin
  Result := True;
  if CurPageID = HqPage.ID then
  begin
    Port := StrToIntDef(Trim(HqPage.Values[2]), 0);
    if (Trim(HqPage.Values[0]) = '') or InvalidArgument(HqPage.Values[0]) then
    begin
      MsgBox('Enter a valid HQ display name.', mbError, MB_OK);
      Result := False;
    end
    else if (Trim(HqPage.Values[1]) = '') or InvalidArgument(HqPage.Values[1]) or
            (Pos(' ', Trim(HqPage.Values[1])) > 0) then
    begin
      MsgBox('Enter a valid DNS name or computer name without spaces.', mbError, MB_OK);
      Result := False;
    end
    else if (Port < 1024) or (Port > 65535) then
    begin
      MsgBox('Enter an HTTPS port from 1024 through 65535.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = PasswordPage.ID then
  begin
    if (Length(PasswordPage.Values[0]) < 12) or
       (Length(PasswordPage.Values[0]) > 128) then
    begin
      MsgBox('The administrator password must contain 12 to 128 characters.', mbError, MB_OK);
      Result := False;
    end
    else if PasswordPage.Values[0] <> PasswordPage.Values[1] then
    begin
      MsgBox('The administrator passwords do not match.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure RequireNode;
var
  ResultCode: Integer;
  Arguments: String;
begin
  if FileExists(GetNodePath) then
  begin
    InstallDetail('Node.js runtime detected.');
    Exit;
  end;
  InstallDetail('Node.js was not found; installing the supported LTS runtime.');
  Arguments :=
    'install --id OpenJS.NodeJS.LTS --exact --source winget --silent ' +
    '--accept-package-agreements --accept-source-agreements --disable-interactivity';
  if (not Exec(GetWingetPath, Arguments, ExpandConstant('{tmp}'), SW_HIDE,
      ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
    RaiseException('Node.js installation failed. Exit code: ' + IntToStr(ResultCode));
  InstallDetail('Node.js runtime installed successfully.');
end;

procedure ConfigureHq;
var
  ResultCode: Integer;
  ResultFile, PasswordFile, InstallLog, Parameters, Summary: String;
  SummaryAnsi: AnsiString;
begin
  InstallDetail('Preparing the selected HQ name, address, port, and administrator credentials.');
  ResultFile := ExpandConstant('{tmp}\SentryLoom-HQ-Install-Result.txt');
  PasswordFile := ExpandConstant('{tmp}\SentryLoom-HQ-Setup-Password.txt');
  InstallLog := ExpandConstant('{commonappdata}\SentryLoom HQ\Logs\install.log');
  DeleteFile(ResultFile);
  DeleteFile(PasswordFile);
  if not SaveStringToFile(PasswordFile, PasswordPage.Values[0], False) then
    RaiseException('Setup could not securely transfer the administrator password.');
  Parameters :=
    '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    ExpandConstant('{app}\Install-SentryLoomHq.ps1') + '" -HqName "' +
    Trim(HqPage.Values[0]) + '" -PublicHost "' + Trim(HqPage.Values[1]) +
    '" -Port ' + Trim(HqPage.Values[2]) + ' -ResultPath "' + ResultFile +
    '" -AdminPasswordFile "' + PasswordFile + '" -InstallLogPath "' + InstallLog +
    '" -TargetVersion "{#MyAppVersion}"';
  InstallDetail('Creating or preserving the HQ database and TLS identity.');
  InstallDetail('Hashing and verifying the administrator password selected in Setup.');
  InstallDetail('Registering the self-restarting background service.');
  InstallDetail('Creating and checking Windows Firewall rules for HTTPS and LAN discovery.');
  InstallDetail('Starting HQ and verifying that its HTTPS listener is reachable.');
  try
    if (not Exec(GetPowerShellPath(''), Parameters, ExpandConstant('{app}'), SW_HIDE,
        ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
    begin
      Summary := '';
      SummaryAnsi := '';
      if FileExists(ResultFile) and LoadStringFromFile(ResultFile, SummaryAnsi) then
        Summary := Trim(String(SummaryAnsi));
      if Summary = '' then
        Summary := 'No additional diagnostic details were produced.';
      RaiseException(
        'SentryLoom HQ configuration failed.' + #13#10 + #13#10 +
        Summary + #13#10 + #13#10 +
        'Exit code: ' + IntToStr(ResultCode));
    end;
  finally
    DeleteFile(PasswordFile);
    PasswordPage.Values[0] := '';
    PasswordPage.Values[1] := '';
  end;

  InstallDetail('HQ configuration and validation completed successfully.');
  Summary := 'SentryLoom HQ installed successfully.';
  SummaryAnsi := '';
  if FileExists(ResultFile) and LoadStringFromFile(ResultFile, SummaryAnsi) then
    Summary := String(SummaryAnsi);
  MsgBox(Summary, mbInformation, MB_OK);
  DeleteFile(ResultFile);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RequireNode;
    ConfigureHq;
  end;
end;
