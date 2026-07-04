[CmdletBinding()]
param(
    [switch]$RemoveLocalData
)

$ErrorActionPreference = 'Stop'
$ProgramsLink = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SentryLoom Endpoint Security.lnk'
$DesktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'SentryLoom Endpoint Security.lnk'
$UsbBackup = Join-Path $env:LOCALAPPDATA 'SentryLoom\device-control\usb-storage-policy.json'
$UsbHelper = Join-Path $PSScriptRoot 'Set-SentryLoomUsbStorage.ps1'

Unregister-ScheduledTask -TaskName 'SentryLoom - Daily Quick Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom - Weekly Idle Full Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom - Realtime Protection' -Confirm:$false -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $UsbBackup -PathType Leaf) -and (Test-Path -LiteralPath $UsbHelper -PathType Leaf)) {
    & $UsbHelper -Action Restore -BackupPath $UsbBackup
}
Remove-Item -LiteralPath $ProgramsLink -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DesktopLink -Force -ErrorAction SilentlyContinue

if ($RemoveLocalData) {
    $Data = Join-Path $env:LOCALAPPDATA 'SentryLoom'
    $ResolvedParent = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
    $ResolvedData = [IO.Path]::GetFullPath($Data)
    if ($ResolvedData.StartsWith($ResolvedParent, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $ResolvedData -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        throw "Refusing to remove unexpected path: $ResolvedData"
    }
}

Write-Host 'SentryLoom shortcuts and scheduled tasks removed.' -ForegroundColor Green
