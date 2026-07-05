[CmdletBinding()]
param(
    [switch]$RemoveLocalData
)

$ErrorActionPreference = 'Stop'
$ProgramsLink = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\SentryLoom Endpoint Security.lnk'
$MaintenanceLink = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Authorize SentryLoom File Maintenance.lnk'
$DesktopLink = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'SentryLoom Endpoint Security.lnk'
$UsbBackup = Join-Path $env:ProgramData 'SentryLoom\device-control\usb-storage-policy.json'
$UsbHelper = Join-Path $PSScriptRoot 'Set-SentryLoomUsbStorage.ps1'

Unregister-ScheduledTask -TaskName 'SentryLoom - Daily Quick Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom - Weekly Idle Full Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom - Realtime Protection' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom - Restore Tamper Protection' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom - Open Authorized File Maintenance' -Confirm:$false -ErrorAction SilentlyContinue
Remove-ItemProperty `
    -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'SentryLoom Tray' `
    -Force `
    -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Group 'SentryLoom Endpoint' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'SentryLoom-Endpoint-Web-Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'SentryLoom-Endpoint-HQ-Discovery-Out' -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $UsbBackup -PathType Leaf) -and (Test-Path -LiteralPath $UsbHelper -PathType Leaf)) {
    & $UsbHelper -Action Restore -BackupPath $UsbBackup
}
Remove-Item -LiteralPath $ProgramsLink -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $MaintenanceLink -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DesktopLink -Force -ErrorAction SilentlyContinue

if ($RemoveLocalData) {
    $Data = Join-Path $env:ProgramData 'SentryLoom'
    $ResolvedParent = [IO.Path]::GetFullPath($env:ProgramData)
    $ResolvedData = [IO.Path]::GetFullPath($Data)
    if ($ResolvedData.StartsWith($ResolvedParent, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $ResolvedData -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        throw "Refusing to remove unexpected path: $ResolvedData"
    }
}

Write-Host 'SentryLoom shortcuts, scheduled tasks, and firewall rules removed.' -ForegroundColor Green
