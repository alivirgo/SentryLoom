[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Apply', 'Restore')]
    [string]$Action,

    [Parameter(Mandatory)]
    [string]$BackupPath
)

$ErrorActionPreference = 'Stop'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Changing removable-storage policy requires administrator approval.'
}

$PolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
$ValueName = 'Deny_All'

if ($Action -eq 'Apply') {
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        $Existing = Get-ItemProperty -LiteralPath $PolicyPath -Name $ValueName -ErrorAction SilentlyContinue
        $Backup = [ordered]@{
            schemaVersion = 1
            createdAt = [DateTime]::UtcNow.ToString('o')
            valueExisted = $null -ne $Existing
            value = if ($null -ne $Existing) { [int]$Existing.$ValueName } else { $null }
        }
        $Parent = Split-Path -Parent $BackupPath
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
        $Temporary = "$BackupPath.$PID.tmp"
        $Backup | ConvertTo-Json -Compress | Set-Content -LiteralPath $Temporary -Encoding UTF8 -Force
        Move-Item -LiteralPath $Temporary -Destination $BackupPath -Force
    }
    New-Item -Path $PolicyPath -Force | Out-Null
    New-ItemProperty -LiteralPath $PolicyPath -Name $ValueName -PropertyType DWord -Value 1 -Force | Out-Null
    [pscustomobject]@{ action = 'applied'; blocked = $true; policy = $PolicyPath } | ConvertTo-Json -Compress
    exit 0
}

if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
    throw "The removable-storage policy backup is missing: $BackupPath"
}
$Backup = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
if ($Backup.schemaVersion -ne 1 -or $null -eq $Backup.valueExisted) {
    throw 'The removable-storage policy backup is invalid.'
}
if ([bool]$Backup.valueExisted) {
    if ($Backup.value -notin @(0, 1)) { throw 'The saved removable-storage policy value is invalid.' }
    New-Item -Path $PolicyPath -Force | Out-Null
    New-ItemProperty -LiteralPath $PolicyPath -Name $ValueName -PropertyType DWord -Value ([int]$Backup.value) -Force | Out-Null
} else {
    Remove-ItemProperty -LiteralPath $PolicyPath -Name $ValueName -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $BackupPath -Force
[pscustomobject]@{ action = 'restored'; blocked = $false } | ConvertTo-Json -Compress
