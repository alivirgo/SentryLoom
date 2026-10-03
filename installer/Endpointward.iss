#define MyAppName "Endpointward Endpoint Security"
#define MyAppVersion "0.17.0"
#define MyAppPublisher "NUC7 Studios"
#define MyAppExeName "Endpointward.exe"

[Setup]
AppId={{9C5046EF-19C0-4A40-91E8-B208A383D827}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Endpointward
DefaultGroupName=Endpointward
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=Endpointward-Setup-{#MyAppVersion}
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
VersionInfoDescription=Endpointward guided security installer
VersionInfoCopyright=Copyright (c) 2026 NUC7 Studios
SetupIconFile=..\assets\Endpointward.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "..\Stop-Endpointward.ps1"; Flags: dontcopy noencryption
Source: "..\Backup-EndpointwardState.ps1"; Flags: dontcopy noencryption
Source: "Relocate-EndpointwardHq.mjs"; Flags: dontcopy noencryption
Source: "..\build\output\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\signatures\base.json"; DestDir: "{app}\signatures"; Flags: ignoreversion
Source: "..\package.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Start-Endpointward.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Register-Endpointward.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Remove-Endpointward.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Set-EndpointwardDns.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Set-EndpointwardUsbStorage.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Show-EndpointwardNotification.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Authorize-EndpointwardMaintenance.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Set-EndpointwardTamperProtection.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Backup-EndpointwardState.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Update-Endpointward.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\*"; DestDir: "{app}\docs"; Excludes: "releases\*"; Flags: ignoreversion recursesubdirs createallsubdirs
[Run]
Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Description: "Open Endpointward security console"; Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{code:GetPowerShellPath}"; Parameters: "-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\Remove-Endpointward.ps1"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "EndpointwardCleanup"

[Code]
var
  DeploymentPage: TInputOptionWizardPage;
  HqPage: TInputQueryWizardPage;
  InstallSummaryPage: TOutputMsgWizardPage;
  InstallDetails: TNewMemo;
  SetupWarnings: String;
  HqEnrollmentConfigured: Boolean;

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

function JsonStringValue(const Json, Key: String): String;
var
  Marker, Remaining: String;
  StartAt, EndAt: Integer;
begin
  Result := '';
  Marker := '"' + Key + '":"';
  StartAt := Pos(Marker, Json);
  if StartAt = 0 then
    Exit;
  Remaining := Copy(Json, StartAt + Length(Marker), Length(Json));
  EndAt := Pos('"', Remaining);
  if EndAt > 0 then
    Result := Copy(Remaining, 1, EndAt - 1);
end;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result :=
    Exec(
      GetPowerShellPath(''),
      '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
        ExpandConstant('{app}\Authorize-EndpointwardMaintenance.ps1') + '" -Action uninstall',
      ExpandConstant('{app}'),
      SW_HIDE,
      ewWaitUntilTerminated,
      ResultCode) and
    (ResultCode = 0);
  if not Result then
    MsgBox(
      'Uninstall was cancelled because Endpointward maintenance authorization was not completed.',
      mbInformation,
      MB_OK);
end;

procedure InitializeWizard;
var
  Intro: String;
begin
  Intro :=
    'Endpointward keeps scanning and telemetry on this PC. Setup will:' + #13#10 + #13#10 +
    '  • install the supported Node.js runtime when needed' + #13#10 +
    '  • install the official Cisco ClamAV engine when needed' + #13#10 +
    '  • download and verify current threat databases' + #13#10 +
    '  • register elevated background protection, daily quick scans, and weekly idle full scans' + #13#10 +
    '  • install reversible DNS and USB removable-storage control helpers' + #13#10 +
    '  • create a native-style Endpointward application shortcut' + #13#10 + #13#10 +
    'Internet access is required during installation. No downloaded database or development tool is embedded in this setup file.';

  InstallSummaryPage := CreateOutputMsgPage(
    wpWelcome,
    'A complete, low-friction setup',
    'Endpointward configures the security engine for you.',
    Intro);

  DeploymentPage := CreateInputOptionPage(
    InstallSummaryPage.ID,
    'Choose endpoint management',
    'How should this Endpointward endpoint be managed?',
    'Standalone mode keeps all management on this PC. Managed mode enrolls the endpoint with an on-premises Endpointward HQ server.',
    True,
    False);
  DeploymentPage.Add('Standalone endpoint (recommended for personal devices)');
  DeploymentPage.Add('Managed endpoint connected to Endpointward HQ');
  DeploymentPage.SelectedValueIndex := 0;

  HqPage := CreateInputQueryPage(
    DeploymentPage.ID,
    'Request Endpointward HQ management',
    'Submit this endpoint for administrator approval',
    'Leave the URL blank to discover Endpointward HQ automatically on this network. The endpoint remains fully protected while approval is pending.');
  HqPage.Add('HQ server URL (optional; https://server:8443):', False);
  HqPage.Add('Certificate SHA-256 fingerprint (optional):', False);

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

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = HqPage.ID) and (DeploymentPage.SelectedValueIndex = 0);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = HqPage.ID) and (DeploymentPage.SelectedValueIndex = 1) then
  begin
    if (Trim(HqPage.Values[0]) <> '') and
       (Pos('https://', Lowercase(Trim(HqPage.Values[0]))) <> 1) then
    begin
      MsgBox('Enter an HTTPS Endpointward HQ URL, or leave it blank for automatic discovery.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Trim(HqPage.Values[1]) <> '') and (Length(Trim(HqPage.Values[1])) <> 64) then
    begin
      MsgBox('Enter the 64-character SHA-256 certificate fingerprint shown by Endpointward HQ, or leave it blank for automatic certificate pinning.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function RunHidden(FileName, Parameters, WorkingDirectory: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(FileName, Parameters, WorkingDirectory, SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure RequireSuccessfulRun(DisplayName, FileName, Parameters, WorkingDirectory: String);
var
  ResultCode: Integer;
begin
  InstallDetail(DisplayName);
  if (not RunHidden(FileName, Parameters, WorkingDirectory, ResultCode)) or (ResultCode <> 0) then
    RaiseException(DisplayName + ' failed. Exit code: ' + IntToStr(ResultCode));
  InstallDetail(DisplayName + ' completed successfully.');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  StopScript, BackupScript, FailureLog, Details, InstalledAuthorizer: String;
  DetailsAnsi: AnsiString;
begin
  Result := '';
  NeedsRestart := False;
  InstalledAuthorizer := ExpandConstant('{app}\Authorize-EndpointwardMaintenance.ps1');
  if FileExists(InstalledAuthorizer) and
     FileExists(ExpandConstant('{app}\Set-EndpointwardTamperProtection.ps1')) then
  begin
    if FileExists(GetNodePath) then
    begin
      ExtractTemporaryFile('Relocate-EndpointwardHq.mjs');
      SetEnvironmentVariable('ENDPOINTWARD_HQ_URL', Trim(HqPage.Values[0]));
      RunHidden(
        GetNodePath,
        '"' + ExpandConstant('{tmp}\Relocate-EndpointwardHq.mjs') + '"',
        ExpandConstant('{tmp}'),
        ResultCode);
      SetEnvironmentVariable('ENDPOINTWARD_HQ_URL', '');
    end;
    InstallDetail('Requesting authorization to update protected Endpointward files.');
    if (not Exec(
      GetPowerShellPath(''),
      '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + InstalledAuthorizer +
        '" -Action file-maintenance',
      ExpandConstant('{app}'),
      SW_SHOW,
      ewWaitUntilTerminated,
      ResultCode)) or (ResultCode <> 0) then
    begin
      Result := 'Setup was cancelled because Endpointward file maintenance was not authorized.';
      Exit;
    end;
  end;
  InstallDetail('Checking for and stopping a previous Endpointward version.');
  ExtractTemporaryFile('Stop-Endpointward.ps1');
  ExtractTemporaryFile('Backup-EndpointwardState.ps1');
  StopScript := ExpandConstant('{tmp}\Stop-Endpointward.ps1');
  BackupScript := ExpandConstant('{tmp}\Backup-EndpointwardState.ps1');
  FailureLog := ExpandConstant('{tmp}\Endpointward-Stop-Error.txt');
  if (not RunHidden(
    GetPowerShellPath(''),
    '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
      StopScript + '" -InstallRoot "' + ExpandConstant('{app}') + '" -FailureLogPath "' + FailureLog + '"',
    ExpandConstant('{tmp}'),
    ResultCode)) or (ResultCode <> 0) then
  begin
    Details := '';
    DetailsAnsi := '';
    if FileExists(FailureLog) and LoadStringFromFile(FailureLog, DetailsAnsi) then
      Details := DetailsAnsi;
    if Details = '' then
      Details := 'No diagnostic details were produced.';
    Result :=
      'Setup could not stop the previous Endpointward instance.' + #13#10 + #13#10 +
      Details + #13#10 + #13#10 + 'Exit code: ' + IntToStr(ResultCode);
    Exit;
  end;
  InstallDetail('Preserving settings, enrollment, credentials, quarantine, logs, history, and runtime state.');
  if (not RunHidden(
    GetPowerShellPath(''),
    '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
      BackupScript + '" -TargetVersion "{#MyAppVersion}"',
    ExpandConstant('{tmp}'),
    ResultCode)) or (ResultCode <> 0) then
  begin
    Result :=
      'Setup stopped because it could not preserve the existing Endpointward state.' +
      Chr(13) + Chr(10) + Chr(13) + Chr(10) +
      'Exit code: ' + IntToStr(ResultCode);
    Exit;
  end;
  InstallDetail('Existing endpoint state was preserved before application files are replaced.');
end;

procedure InstallPrerequisites;
var
  Winget, CommonArguments: String;
begin
  Winget := GetWingetPath;
  CommonArguments := ' --exact --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity';

  if not FileExists(GetNodePath) then
    RequireSuccessfulRun(
      'Installing the supported Node.js runtime…',
      Winget,
      'install --id OpenJS.NodeJS.LTS' + CommonArguments,
      ExpandConstant('{tmp}'));
  if FileExists(GetNodePath) then
    InstallDetail('Supported Node.js runtime is available.');

  if not FileExists(ExpandConstant('{pf64}\ClamAV\clamscan.exe')) then
    RequireSuccessfulRun(
      'Installing the official ClamAV scanning engine…',
      Winget,
      'install --id Cisco.ClamAV' + CommonArguments,
      ExpandConstant('{tmp}'));
  if FileExists(ExpandConstant('{pf64}\ClamAV\clamscan.exe')) then
    InstallDetail('Official ClamAV scanning engine is available.');
end;

procedure SaveHqEnrollment;
var
  ResultCode: Integer;
  FailureLog, ResultFile, Details, RequestResult: String;
  DetailsAnsi, RequestResultAnsi: AnsiString;
  VerificationCode, PollResultFile, PollResult: String;
  PollResultAnsi: AnsiString;
  Ans: Integer;
  Approved: Boolean;
begin
  if DeploymentPage.SelectedValueIndex <> 1 then
  begin
    InstallDetail('Standalone management selected; HQ enrollment is not required.');
    Exit;
  end;
  InstallDetail('Discovering or contacting Endpointward HQ on the configured network.');
  SetEnvironmentVariable('ENDPOINTWARD_HQ_URL', Trim(HqPage.Values[0]));
  SetEnvironmentVariable('ENDPOINTWARD_HQ_FINGERPRINT', Uppercase(Trim(HqPage.Values[1])));
  FailureLog := ExpandConstant('{tmp}\Endpointward-HQ-Enrollment-Error.txt');
  ResultFile := ExpandConstant('{tmp}\Endpointward-HQ-Enrollment-Result.json');
  DeleteFile(FailureLog);
  DeleteFile(ResultFile);
  SetEnvironmentVariable('ENDPOINTWARD_FAILURE_LOG', FailureLog);
  SetEnvironmentVariable('ENDPOINTWARD_HQ_RESULT_FILE', ResultFile);
  try
    if (not RunHidden(
      GetNodePath,
      '--disable-warning=ExperimentalWarning "' + ExpandConstant('{app}\src\cli.js') + '" hq request-env',
      ExpandConstant('{app}'),
      ResultCode)) or (ResultCode <> 0) then
    begin
      HqEnrollmentConfigured := False;
      Details := '';
      DetailsAnsi := '';
      if FileExists(FailureLog) and LoadStringFromFile(FailureLog, DetailsAnsi) then
        Details := Trim(DetailsAnsi);
      if Details = '' then
        Details := 'Setup could not submit the HQ approval request.';
      SetupWarnings := SetupWarnings +
        'HQ approval was not requested: ' + Details + #13#10 +
        'Local protection is installed. Use Settings → Endpointward HQ to retry.' + #13#10;
    end
    else
    begin
      HqEnrollmentConfigured := True;
      RequestResult := '';
      RequestResultAnsi := '';
      if FileExists(ResultFile) and LoadStringFromFile(ResultFile, RequestResultAnsi) then
        RequestResult := RequestResultAnsi;
      if Pos('"status":"preserved"', RequestResult) > 0 then
      begin
        InstallDetail('The existing approved HQ enrollment and device identity were preserved.');
      end
      else
      begin
        VerificationCode := JsonStringValue(RequestResult, 'verificationCode');
        if Length(VerificationCode) <> 6 then
          RaiseException('Setup did not receive a valid client-generated verification code.');
        InstallDetail('HQ was found and the endpoint approval request was submitted.');
        InstallDetail('The selected HQ is now the active enrollment target; any previous server credential was retired.');

        PollResultFile := ExpandConstant('{tmp}\Endpointward-HQ-Poll-Result.json');
        SetEnvironmentVariable('ENDPOINTWARD_HQ_RESULT_FILE', PollResultFile);
        Approved := False;
        while not Approved do
        begin
          DeleteFile(PollResultFile);
          InstallDetail('Polling Endpointward HQ for enrollment approval…');
          if (not RunHidden(
            GetNodePath,
            '--disable-warning=ExperimentalWarning "' + ExpandConstant('{app}\src\cli.js') + '" hq poll-pending-env',
            ExpandConstant('{app}'),
            ResultCode)) or (ResultCode <> 0) then
          begin
            Details := '';
            DetailsAnsi := '';
            if FileExists(FailureLog) and LoadStringFromFile(FailureLog, DetailsAnsi) then
              Details := Trim(DetailsAnsi);
            if Details = '' then
              Details := 'No diagnostic details were produced.';
            RaiseException(
              'Polling pending enrollment failed.' + #13#10 + #13#10 +
              Details + #13#10 + #13#10 + 'Exit code: ' + IntToStr(ResultCode));
          end;

          PollResult := '';
          PollResultAnsi := '';
          if FileExists(PollResultFile) and LoadStringFromFile(PollResultFile, PollResultAnsi) then
            PollResult := PollResultAnsi;

          if Pos('"status":"approved"', PollResult) > 0 then
          begin
            Approved := True;
            InstallDetail('Enrollment request approved by the HQ server.');
          end
          else if Pos('"status":"rejected"', PollResult) > 0 then
          begin
            MsgBox('The Endpointward HQ server rejected the enrollment request.', mbError, MB_OK);
            RaiseException('Enrollment request was rejected by Endpointward HQ.');
          end;

          if not Approved then
          begin
            Ans := MsgBox(
              'This client is waiting for administrator approval on the Endpointward HQ server.' + #13#10 + #13#10 +
              'Verification Code: ' + VerificationCode + #13#10 + #13#10 +
              'Please approve this device in the Endpointward HQ console by entering the verification code above.' + #13#10 + #13#10 +
              'Once approved, click Retry to complete the installation. Click Cancel to abort setup.',
              mbConfirmation,
              MB_RETRYCANCEL
            );
            if Ans = IDCANCEL then
            begin
              RaiseException('Setup aborted by user during server enrollment approval.');
            end;
          end;
        end;

        SetupWarnings := SetupWarnings +
          'This endpoint was approved by Endpointward HQ. Local protection is active.' + #13#10;
      end;
    end;
  finally
    SetEnvironmentVariable('ENDPOINTWARD_HQ_URL', '');
    SetEnvironmentVariable('ENDPOINTWARD_HQ_FINGERPRINT', '');
    SetEnvironmentVariable('ENDPOINTWARD_FAILURE_LOG', '');
    SetEnvironmentVariable('ENDPOINTWARD_HQ_RESULT_FILE', '');
    HqPage.Values[1] := '';
  end;
end;

procedure RegisterProtection;
var
  ResultCode: Integer;
  FailureLog, Details: String;
  DetailsAnsi: AnsiString;
begin
  InstallDetail('Registering elevated realtime protection and scheduled scanning tasks.');
  InstallDetail('Creating application-scoped Windows Firewall rules for HQ discovery and HTTPS.');
  FailureLog := ExpandConstant('{tmp}\Endpointward-Register-Error.txt');
  if (not RunHidden(
    GetPowerShellPath(''),
    '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "' +
      ExpandConstant('{app}\Register-Endpointward.ps1') + '" -SystemWideProtection -FailureLogPath "' +
      ExpandConstant('{tmp}\Endpointward-Register-Error.txt') + '"',
    ExpandConstant('{app}'),
    ResultCode)) or (ResultCode <> 0) then
  begin
    Details := '';
    DetailsAnsi := '';
    if FileExists(FailureLog) and LoadStringFromFile(FailureLog, DetailsAnsi) then
      Details := DetailsAnsi;
    if Details = '' then
      Details := 'No diagnostic details were produced.';
    RaiseException(
      'Registering elevated realtime and scheduled protection failed.' + #13#10 + #13#10 +
      Details + #13#10 + #13#10 + 'Exit code: ' + IntToStr(ResultCode));
  end;
  InstallDetail('Realtime protection, scheduled scans, and firewall policies were verified.');
end;

procedure DownloadDatabases;
var
  ResultCode: Integer;
  Cli, Sources: String;
begin
  Cli := '"' + ExpandConstant('{app}\src\cli.js') + '"';
  Sources := 'clamav';

  InstallDetail('Downloading and cryptographically verifying current threat databases.');
  if (not RunHidden(
    GetNodePath,
    '--disable-warning=ExperimentalWarning ' + Cli + ' update ' + Sources,
    ExpandConstant('{app}'),
    ResultCode)) or (ResultCode <> 0) then
    SetupWarnings := SetupWarnings + 'Some threat databases could not be downloaded. Use Settings → Virus databases to retry.' + #13#10;

  if Sources <> 'all' then
  begin
    InstallDetail('Downloading the public Feodo Tracker network indicators.');
    RunHidden(
      GetNodePath,
      '--disable-warning=ExperimentalWarning ' + Cli + ' update feodotracker',
      ExpandConstant('{app}'),
      ResultCode);
  end;
  InstallDetail('Threat database setup completed; unavailable optional feeds can be retried in Settings.');
end;

procedure RemoveLegacyInstallation;
var
  ResultCode: Integer;
begin
  InstallDetail('Removing obsolete task names from older Endpointward versions.');
  RunHidden(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "Aegis Offline AV - Realtime Protection"', '', ResultCode);
  RunHidden(ExpandConstant('{sys}\schtasks.exe'), '/Delete /F /TN "Aegis Offline AV - Realtime Protection"', '', ResultCode);
  RunHidden(ExpandConstant('{sys}\schtasks.exe'), '/Delete /F /TN "Aegis Offline AV - Daily Quick Scan"', '', ResultCode);
end;

procedure StopExistingProtection;
var
  ResultCode: Integer;
begin
  InstallDetail('Stopping the existing realtime task before files are replaced.');
  RunHidden(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "Endpointward - Realtime Protection"', '', ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopExistingProtection;
  if CurStep = ssPostInstall then
  begin
    InstallDetail('Application files were copied successfully.');
    RemoveLegacyInstallation;
    InstallPrerequisites;
    SaveHqEnrollment;
    DownloadDatabases;
    RegisterProtection;
    InstallDetail('Endpointward Endpoint Security installation and validation completed.');
    if SetupWarnings <> '' then
      MsgBox('Endpointward installed successfully.' + #13#10 + #13#10 + SetupWarnings, mbInformation, MB_OK);
  end;
end;
