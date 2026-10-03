[CmdletBinding()]
param(
    [switch]$RemoveServerData
)

$ErrorActionPreference = 'Stop'
Stop-ScheduledTask -TaskName 'Endpointward HQ Server' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Endpointward HQ Server' -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Group 'Endpointward HQ' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'Endpointward-HQ-HTTPS-In' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'Endpointward-HQ-Discovery-In' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'Endpointward-HQ-Discovery-Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'Endpointward-HQ-Wake-On-LAN-Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Endpointward HQ - HTTPS' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'Endpointward HQ - Discovery' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot 'Endpointward HQ.url') -Force -ErrorAction SilentlyContinue

if ($RemoveServerData) {
    $Data = Join-Path $PSScriptRoot 'data'
    $ResolvedRoot = [IO.Path]::GetFullPath($PSScriptRoot)
    $ResolvedData = [IO.Path]::GetFullPath($Data)
    if ($ResolvedData.StartsWith($ResolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $ResolvedData -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        throw "Refusing to remove unexpected path: $ResolvedData"
    }
}

Write-Host 'Endpointward HQ scheduled task and firewall rules removed.' -ForegroundColor Green
