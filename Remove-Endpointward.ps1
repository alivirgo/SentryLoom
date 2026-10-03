[CmdletBinding()]
param(
    [switch]$RemoveLocalData
)

$ErrorActionPreference = 'Stop'
$ProgramsLink = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Endpointward Endpoint Security.lnk'
$MaintenanceLink = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Authorize Endpointward File Maintenance.lnk'
$DesktopLink = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Endpointward Endpoint Security.lnk'
$UsbBackup = Join-Path $env:ProgramData 'Endpointward\device-control\usb-storage-policy.json'
$UsbHelper = Join-Path $PSScriptRoot 'Set-EndpointwardUsbStorage.ps1'

Unregister-ScheduledTask -TaskName 'Endpointward - Daily Quick Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Endpointward - Weekly Idle Full Scan' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Endpointward - Realtime Protection' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Endpointward - Restore Tamper Protection' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Endpointward - Open Authorized File Maintenance' -Confirm:$false -ErrorAction SilentlyContinue
Remove-ItemProperty `
    -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'Endpointward Tray' `
    -Force `
    -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Group 'Endpointward Endpoint' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'Endpointward-Endpoint-Web-Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'Endpointward-Endpoint-HQ-Discovery-Out' -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $UsbBackup -PathType Leaf) -and (Test-Path -LiteralPath $UsbHelper -PathType Leaf)) {
    & $UsbHelper -Action Restore -BackupPath $UsbBackup
}
Remove-Item -LiteralPath $ProgramsLink -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $MaintenanceLink -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $DesktopLink -Force -ErrorAction SilentlyContinue

if ($RemoveLocalData) {
    $Data = Join-Path $env:ProgramData 'Endpointward'
    $ResolvedParent = [IO.Path]::GetFullPath($env:ProgramData)
    $ResolvedData = [IO.Path]::GetFullPath($Data)
    if ($ResolvedData.StartsWith($ResolvedParent, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $ResolvedData -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        throw "Refusing to remove unexpected path: $ResolvedData"
    }
}

Write-Host 'Endpointward shortcuts, scheduled tasks, and firewall rules removed.' -ForegroundColor Green
