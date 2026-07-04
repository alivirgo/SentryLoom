[CmdletBinding()]
param(
    [switch]$SkipScheduledScans,
    [switch]$SkipRealtimeStartup,
    [switch]$SystemWideProtection,
    [string]$FailureLogPath
)

$ErrorActionPreference = 'Stop'
$FailureLog = if ($FailureLogPath) { $FailureLogPath } else { Join-Path $env:TEMP 'SentryLoom-Register-Error.txt' }
Remove-Item -LiteralPath $FailureLog -Force -ErrorAction SilentlyContinue
function Write-RegistrationStep([string]$Message) {
    Write-Host "[SentryLoom setup] $Message" -ForegroundColor Cyan
}
trap {
    $Details = @(
        $_.Exception.Message
        $_.ScriptStackTrace
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $FailureLog -Value $Details -Encoding ASCII -Force
    Write-Error $Details
    exit 1
}
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$NodeCandidate = Join-Path $env:ProgramFiles 'nodejs\node.exe'
$Node = if (Test-Path -LiteralPath $NodeCandidate) { $NodeCandidate } else { (Get-Command node -ErrorAction Stop).Source }
$Launcher = Join-Path $Root 'SentryLoom.exe'
$Cli = Join-Path $Root 'src\cli.js'
$ClamScan = Join-Path $env:ProgramFiles 'ClamAV\clamscan.exe'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$QualifiedUser = [string]$Identity.Name
if ([string]::IsNullOrWhiteSpace($QualifiedUser) -or $QualifiedUser -notmatch '\\') {
    throw "Windows did not provide a fully qualified account name for scheduled protection: '$QualifiedUser'"
}
$RunLevel = if ($SystemWideProtection) { 'Highest' } else { 'Limited' }
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId $QualifiedUser -LogonType Interactive -RunLevel $RunLevel

if (-not (Test-Path -LiteralPath $Launcher)) {
    throw "The native SentryLoom launcher is missing: $Launcher"
}
Write-RegistrationStep "Validated the launcher and runtime paths."

$Programs = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$Desktop = [Environment]::GetFolderPath('Desktop')
$Shell = New-Object -ComObject WScript.Shell

foreach ($LegacyTask in @('Aegis Offline AV - Daily Quick Scan', 'Aegis Offline AV - Realtime Protection')) {
    Stop-ScheduledTask -TaskName $LegacyTask -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $LegacyTask -Confirm:$false -ErrorAction SilentlyContinue
}
foreach ($LegacyLink in @(
    (Join-Path $Programs 'Aegis Offline AV.lnk'),
    (Join-Path $Desktop 'Aegis Offline AV.lnk')
)) {
    Remove-Item -LiteralPath $LegacyLink -Force -ErrorAction SilentlyContinue
}

foreach ($LinkPath in @(
    (Join-Path $Programs 'SentryLoom Endpoint Security.lnk'),
    (Join-Path $Desktop 'SentryLoom Endpoint Security.lnk')
)) {
    $Shortcut = $Shell.CreateShortcut($LinkPath)
    $Shortcut.TargetPath = $Launcher
    $Shortcut.Arguments = ''
    $Shortcut.WorkingDirectory = $Root
    $Shortcut.IconLocation = "$Launcher,0"
    $Shortcut.Description = 'SentryLoom Endpoint Security console'
    $Shortcut.Save()
}
Write-RegistrationStep 'Created the Start Menu and Desktop application shortcuts.'

if (-not $SkipScheduledScans) {
    Stop-ScheduledTask -TaskName 'SentryLoom - Daily Quick Scan' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'SentryLoom - Daily Quick Scan' -Confirm:$false -ErrorAction SilentlyContinue
    Stop-ScheduledTask -TaskName 'SentryLoom - Weekly Idle Full Scan' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'SentryLoom - Weekly Idle Full Scan' -Confirm:$false -ErrorAction SilentlyContinue

    $Action = New-ScheduledTaskAction -Execute $Launcher -Argument '--command=quick' -WorkingDirectory $Root
    $Trigger = New-ScheduledTaskTrigger -Daily -At 2am
    $Trigger.StartBoundary = (Get-Date).Date.AddDays(1).AddHours(2).ToString('s')
    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 4)
    Register-ScheduledTask -TaskName 'SentryLoom - Daily Quick Scan' -Action $Action -Trigger $Trigger -Settings $Settings -Principal $TaskPrincipal -Description 'SentryLoom daily endpoint scan' -Force | Out-Null

    $FullAction = New-ScheduledTaskAction -Execute $Launcher -Argument '--command=full' -WorkingDirectory $Root
    $FullTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
    $FullSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfIdle -IdleDuration (New-TimeSpan -Minutes 10) -IdleWaitTimeout (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 8)
    Register-ScheduledTask -TaskName 'SentryLoom - Weekly Idle Full Scan' -Action $FullAction -Trigger $FullTrigger -Settings $FullSettings -Principal $TaskPrincipal -Description 'SentryLoom weekly full scan while the PC is idle' -Force | Out-Null
    Write-RegistrationStep 'Registered daily quick-scan and weekly idle full-scan tasks.'
}

if (-not $SkipRealtimeStartup) {
    if ($SystemWideProtection) {
        $PrincipalCheck = New-Object Security.Principal.WindowsPrincipal($Identity)
        if (-not $PrincipalCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'SystemWideProtection requires an elevated PowerShell session.'
        }
    }
    Stop-ScheduledTask -TaskName 'SentryLoom - Realtime Protection' -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName 'SentryLoom - Realtime Protection' -Confirm:$false -ErrorAction SilentlyContinue
    $Action = New-ScheduledTaskAction -Execute $Launcher -Argument '--background' -WorkingDirectory $Root
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User $QualifiedUser
    $Settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'SentryLoom - Realtime Protection' -Action $Action -Trigger $Trigger -Settings $Settings -Principal $TaskPrincipal -Description 'SentryLoom realtime endpoint protection' -Force | Out-Null
    Start-ScheduledTask -TaskName 'SentryLoom - Realtime Protection'
    Write-RegistrationStep 'Registered and started self-restarting realtime protection.'
}

Write-RegistrationStep 'Configuring application-scoped Windows Firewall policies.'
Remove-NetFirewallRule -Group 'SentryLoom Endpoint' -ErrorAction SilentlyContinue
$EndpointFirewallRules = @(
    @{
        Name = 'SentryLoom-Endpoint-Web-Out'
        DisplayName = 'SentryLoom Endpoint - HTTPS and threat intelligence outbound'
        Protocol = 'TCP'
        RemotePort = 'Any'
        RemoteAddress = 'Any'
    },
    @{
        Name = 'SentryLoom-Endpoint-HQ-Discovery-Out'
        DisplayName = 'SentryLoom Endpoint - HQ discovery outbound'
        Protocol = 'UDP'
        RemotePort = 32110
        RemoteAddress = 'LocalSubnet'
    }
)
foreach ($Rule in $EndpointFirewallRules) {
    New-NetFirewallRule `
        -Name $Rule.Name `
        -DisplayName $Rule.DisplayName `
        -Group 'SentryLoom Endpoint' `
        -Direction Outbound `
        -Action Allow `
        -Program $Node `
        -Protocol $Rule.Protocol `
        -RemotePort $Rule.RemotePort `
        -RemoteAddress $Rule.RemoteAddress `
        -Profile Any | Out-Null
}
$InvalidFirewallRule = Get-NetFirewallRule -Group 'SentryLoom Endpoint' -ErrorAction Stop |
    Where-Object Enabled -ne 'True' |
    Select-Object -First 1
if ($InvalidFirewallRule) {
    throw "Firewall rule '$($InvalidFirewallRule.DisplayName)' is not enabled."
}
Write-RegistrationStep 'Verified endpoint firewall policies for HQ discovery and HTTPS communication.'

Write-Host 'SentryLoom Endpoint Security registered for the current user.' -ForegroundColor Green
Write-Host "Application: $Root"
Write-Host "Scheduled task identity: $QualifiedUser"
Write-Host 'Use the Desktop or Start Menu shortcut to launch the security console.'
Write-Host "Realtime task privilege: $(if ($SystemWideProtection) { 'Highest' } else { 'Limited' })"
Write-Host 'Firewall: application-scoped outbound HTTPS and LAN discovery rules are enabled.'
if (-not (Test-Path -LiteralPath $ClamScan)) {
    Write-Warning 'ClamAV is not installed. Install the official Cisco.ClamAV package with winget to enable full ClamAV updates and scanning.'
    Write-Host 'winget install --id Cisco.ClamAV --exact --source winget'
}
