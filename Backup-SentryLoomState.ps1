[CmdletBinding()]
param(
    [string]$TargetVersion = 'unknown'
)

$ErrorActionPreference = 'Stop'
$MachineData = Join-Path $env:ProgramData 'SentryLoom'
$LegacyData = Join-Path $env:LOCALAPPDATA 'SentryLoom'
$Preserved = @(
    'config.json',
    'upgrade-state.json',
    'keys',
    'quarantine',
    'logs',
    'scan-history.json',
    'signatures',
    'device-identity.json',
    'hq-connector-state.json',
    'dns',
    'device-control',
    'monitoring',
    'threat-intel',
    'updates'
)

$MachineHadState = Test-Path -LiteralPath (Join-Path $MachineData 'config.json') -PathType Leaf
New-Item -ItemType Directory -Path $MachineData -Force | Out-Null

$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$InteractiveSid = $null
try {
    $InteractiveUser = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).UserName
    if (-not [string]::IsNullOrWhiteSpace($InteractiveUser)) {
        $InteractiveAccount = New-Object Security.Principal.NTAccount($InteractiveUser)
        $InteractiveSid = $InteractiveAccount.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
} catch {}

$AclArguments = @(
    $MachineData,
    '/inheritance:r',
    '/grant:r',
    '*S-1-5-18:(OI)(CI)F',
    '*S-1-5-32-544:(OI)(CI)F',
    "*${CurrentSid}:(OI)(CI)F"
)
if ($InteractiveSid -and $InteractiveSid -ne $CurrentSid) {
    $AclArguments += "*${InteractiveSid}:(OI)(CI)M"
}
& "$env:WINDIR\System32\icacls.exe" @AclArguments | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Could not configure the machine-wide endpoint data permissions.'
}

$LegacyCandidates = @($LegacyData)
if ($InteractiveSid) {
    try {
        $InteractiveProfile = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object { [string]$_.SID -eq $InteractiveSid } |
            Select-Object -First 1
        if ($InteractiveProfile.LocalPath) {
            $InteractiveLegacy = Join-Path $InteractiveProfile.LocalPath 'AppData\Local\SentryLoom'
            if ($InteractiveLegacy -notin $LegacyCandidates) {
                $LegacyCandidates += $InteractiveLegacy
            }
        }
    } catch {}
}
$LegacyData = $LegacyCandidates |
    Where-Object {
        Test-Path -LiteralPath (Join-Path $_ 'keys\hq-credentials.enc') -PathType Leaf
    } |
    Select-Object -First 1
if (-not $LegacyData) {
    $LegacyData = $LegacyCandidates |
        Where-Object { Test-Path -LiteralPath (Join-Path $_ 'config.json') -PathType Leaf } |
        Select-Object -First 1
}
if (-not $LegacyData) {
    $LegacyData = $LegacyCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Container } |
        Select-Object -First 1
}

$MachineHasEnrollment = (
    Test-Path -LiteralPath (Join-Path $MachineData 'keys\hq-credentials.enc') -PathType Leaf
) -or (
    Test-Path -LiteralPath (Join-Path $MachineData 'keys\hq-pending-enrollment.enc') -PathType Leaf
)
$LegacyHasEnrollment = $LegacyData -and ((
    Test-Path -LiteralPath (Join-Path $LegacyData 'keys\hq-credentials.enc') -PathType Leaf
) -or (
    Test-Path -LiteralPath (Join-Path $LegacyData 'keys\hq-pending-enrollment.enc') -PathType Leaf
))
$ShouldMigrate = (-not $MachineHadState) -or (
    -not $MachineHasEnrollment -and $LegacyHasEnrollment
)

if ($ShouldMigrate -and $LegacyData -and
    (Test-Path -LiteralPath $LegacyData -PathType Container)) {
    foreach ($Relative in $Preserved) {
        $LegacyItem = Join-Path $LegacyData $Relative
        if (-not (Test-Path -LiteralPath $LegacyItem)) { continue }
        Copy-Item -LiteralPath $LegacyItem -Destination $MachineData -Recurse -Force
    }
    $MachineHadState = $true
    Write-Host "Migrated endpoint state from $LegacyData to $MachineData"
}

if (-not $MachineHadState) {
    Write-Host "Initialized machine-wide endpoint state at $MachineData"
    exit 0
}

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupRoot = Join-Path $MachineData "UpgradeBackups\$Stamp-$TargetVersion"
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null

$Copied = @()
foreach ($Relative in $Preserved) {
    $Item = Join-Path $MachineData $Relative
    if (-not (Test-Path -LiteralPath $Item)) { continue }
    Copy-Item -LiteralPath $Item -Destination $BackupRoot -Recurse -Force
    $Copied += $Relative
}

$Manifest = @{
    schemaVersion = 1
    createdAt = (Get-Date).ToUniversalTime().ToString('o')
    targetVersion = $TargetVersion
    source = $MachineData
    legacySource = $LegacyData
    backup = $BackupRoot
    preserved = $Copied
    policy = 'retain-unless-versioned-migration'
}
$Manifest | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $BackupRoot 'upgrade-backup.json') -Encoding UTF8 -Force
Write-Host "Preserved existing endpoint state at $BackupRoot"
