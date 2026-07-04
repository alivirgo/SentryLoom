[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Apply', 'Restore')]
    [string]$Action,

    [ValidateSet('adguard-default', 'controld-ads-tracking', 'mullvad-base')]
    [string]$Profile = 'adguard-default',

    [Parameter(Mandatory)]
    [string]$BackupPath
)

$ErrorActionPreference = 'Stop'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Changing Windows DNS settings requires administrator approval.'
}

$Profiles = @{
    'adguard-default' = @{
        Addresses = @('94.140.14.14', '94.140.15.15', '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff')
        DohTemplate = 'https://dns.adguard-dns.com/dns-query'
    }
    'controld-ads-tracking' = @{
        Addresses = @('76.76.2.2', '76.76.10.2', '2606:1a40::2', '2606:1a40:1::2')
        DohTemplate = 'https://freedns.controld.com/p2'
    }
    'mullvad-base' = @{
        Addresses = @('194.242.2.4', '2a07:e340::4')
        DohTemplate = 'https://base.dns.mullvad.net/dns-query'
    }
}

function Read-Backup {
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        throw "DNS backup is missing: $BackupPath"
    }
    $Backup = Get-Content -LiteralPath $BackupPath -Raw | ConvertFrom-Json
    if ($Backup.schemaVersion -ne 1 -or -not $Backup.adapters) {
        throw 'DNS backup format is invalid.'
    }
    return $Backup
}

function Restore-Adapters([object]$Backup) {
    foreach ($Adapter in @($Backup.adapters)) {
        $Index = [int]$Adapter.interfaceIndex
        if (-not (Get-NetAdapter -InterfaceIndex $Index -ErrorAction SilentlyContinue)) { continue }
        $Addresses = @($Adapter.dnsServers | ForEach-Object {
            ([System.Net.IPAddress]::Parse([string]$_)).ToString()
        })
        if ([bool]$Adapter.automatic -or $Addresses.Count -eq 0) {
            Set-DnsClientServerAddress -InterfaceIndex $Index -ResetServerAddresses
        } else {
            Set-DnsClientServerAddress -InterfaceIndex $Index -ServerAddresses $Addresses
        }
    }
    Clear-DnsClientCache
}

$Backup = Read-Backup
if ($Action -eq 'Restore') {
    Restore-Adapters $Backup
    [pscustomobject]@{ action = 'restored'; adapters = @($Backup.adapters).Count } | ConvertTo-Json -Compress
    exit 0
}

$Selected = $Profiles[$Profile]
if (-not $Selected) { throw "Unsupported DNS profile: $Profile" }

try {
    foreach ($Address in $Selected.Addresses) {
        $Canonical = ([System.Net.IPAddress]::Parse($Address)).ToString()
        $Existing = Get-DnsClientDohServerAddress -ServerAddress $Canonical -ErrorAction SilentlyContinue
        if ($Existing) {
            Set-DnsClientDohServerAddress -ServerAddress $Canonical -DohTemplate $Selected.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true
        } else {
            Add-DnsClientDohServerAddress -ServerAddress $Canonical -DohTemplate $Selected.DohTemplate -AllowFallbackToUdp $false -AutoUpgrade $true
        }
    }
    foreach ($Adapter in @($Backup.adapters)) {
        $Index = [int]$Adapter.interfaceIndex
        if (-not (Get-NetAdapter -InterfaceIndex $Index -ErrorAction SilentlyContinue)) { continue }
        Set-DnsClientServerAddress -InterfaceIndex $Index -ServerAddresses $Selected.Addresses
    }
    Clear-DnsClientCache
    Resolve-DnsName -Name 'example.com' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
    [pscustomobject]@{ action = 'applied'; profile = $Profile; adapters = @($Backup.adapters).Count; encrypted = $true } | ConvertTo-Json -Compress
} catch {
    Restore-Adapters $Backup
    throw "DNS profile could not be verified and the previous settings were restored. $($_.Exception.Message)"
}
