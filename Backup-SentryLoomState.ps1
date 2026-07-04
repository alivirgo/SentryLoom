[CmdletBinding()]
param(
    [string]$TargetVersion = 'unknown'
)

$ErrorActionPreference = 'Stop'
$Source = Join-Path $env:LOCALAPPDATA 'SentryLoom'
if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
    Write-Host 'No existing SentryLoom endpoint state was found; this is a first installation.'
    exit 0
}

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupRoot = Join-Path $env:ProgramData "SentryLoom\UpgradeBackups\$Stamp-$TargetVersion"
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& "$env:WINDIR\System32\icacls.exe" `
    $BackupRoot `
    '/inheritance:r' `
    '/grant:r' `
    '*S-1-5-18:(OI)(CI)F' `
    '*S-1-5-32-544:(OI)(CI)F' `
    "*${CurrentSid}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Could not restrict the endpoint upgrade-backup permissions.'
}

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
$Copied = @()
foreach ($Relative in $Preserved) {
    $Item = Join-Path $Source $Relative
    if (-not (Test-Path -LiteralPath $Item)) { continue }
    Copy-Item -LiteralPath $Item -Destination $BackupRoot -Recurse -Force
    $Copied += $Relative
}

$Manifest = @{
    schemaVersion = 1
    createdAt = (Get-Date).ToUniversalTime().ToString('o')
    targetVersion = $TargetVersion
    source = $Source
    backup = $BackupRoot
    preserved = $Copied
    policy = 'retain-unless-versioned-migration'
}
$Manifest | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $BackupRoot 'upgrade-backup.json') -Encoding UTF8 -Force
Write-Host "Preserved existing endpoint state at $BackupRoot"
