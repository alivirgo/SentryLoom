[CmdletBinding()]
param(
    [switch]$RemoveServerData
)

$ErrorActionPreference = 'Stop'
Stop-ScheduledTask -TaskName 'SentryLoom HQ Server' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'SentryLoom HQ Server' -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Group 'SentryLoom HQ' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'SentryLoom-HQ-HTTPS-In' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'SentryLoom-HQ-Discovery-In' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name 'SentryLoom-HQ-Discovery-Out' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SentryLoom HQ - HTTPS' -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'SentryLoom HQ - Discovery' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $PSScriptRoot 'SentryLoom HQ.url') -Force -ErrorAction SilentlyContinue

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

Write-Host 'SentryLoom HQ scheduled task and firewall rules removed.' -ForegroundColor Green
