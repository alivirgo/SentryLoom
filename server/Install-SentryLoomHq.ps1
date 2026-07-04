[CmdletBinding()]
param(
    [string]$PublicHost = $env:COMPUTERNAME,
    [string]$HqName = 'SentryLoom HQ',
    [ValidateRange(1024, 65535)]
    [int]$Port = 8443,
    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$Node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
if (-not (Test-Path -LiteralPath $Node)) {
    throw 'Node.js 24 or later is required.'
}

$ConfigPath = Join-Path $PSScriptRoot 'data\config.json'
function Wait-HqListener([int]$ListenerPort) {
    $Deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        $Listener = Get-NetTCPConnection `
            -LocalPort $ListenerPort `
            -State Listen `
            -ErrorAction SilentlyContinue
    } until ($Listener -or (Get-Date) -gt $Deadline)
    if (-not $Listener) {
        throw "SentryLoom HQ did not begin listening on TCP $ListenerPort within 30 seconds."
    }
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'Initialize-SentryLoomHq.ps1') `
        -PublicHost $PublicHost `
        -HqName $HqName `
        -Port $Port `
        -RegisterStartupTask `
        -ResultPath $ResultPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $CreatedConfig = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    Wait-HqListener ([int]$CreatedConfig.port)
    Set-Content `
        -LiteralPath (Join-Path $PSScriptRoot 'SentryLoom HQ.url') `
        -Value "[InternetShortcut]`r`nURL=https://$($CreatedConfig.publicHost):$($CreatedConfig.port)`r`n" `
        -Encoding ASCII `
        -Force
    exit 0
}

$Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$Main = Join-Path $PSScriptRoot 'src\main.js'
$Action = New-ScheduledTaskAction `
    -Execute $Node `
    -Argument "--disable-warning=ExperimentalWarning `"$Main`"" `
    -WorkingDirectory $PSScriptRoot
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

Stop-ScheduledTask -TaskName 'SentryLoom HQ Server' -ErrorAction SilentlyContinue
$PasswordUpdated = $false
if (-not [string]::IsNullOrWhiteSpace([string]$env:SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD)) {
    & $Node `
        --disable-warning=ExperimentalWarning `
        (Join-Path $PSScriptRoot 'src\set-admin-password.js') `
        $ConfigPath
    if ($LASTEXITCODE -ne 0) {
        throw "Updating the HQ administrator password failed with exit code $LASTEXITCODE."
    }
    $PasswordUpdated = $true
}
Register-ScheduledTask `
    -TaskName 'SentryLoom HQ Server' `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description 'SentryLoom HQ management server' `
    -Force | Out-Null

$DiscoveryPort = if ($Config.discovery.port) { [int]$Config.discovery.port } else { 32110 }
foreach ($Rule in @(
    @{ Name = 'SentryLoom HQ - HTTPS'; Protocol = 'TCP'; Port = [int]$Config.port },
    @{ Name = 'SentryLoom HQ - Discovery'; Protocol = 'UDP'; Port = $DiscoveryPort }
)) {
    Remove-NetFirewallRule -DisplayName $Rule.Name -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName $Rule.Name `
        -Direction Inbound `
        -Action Allow `
        -Protocol $Rule.Protocol `
        -LocalPort $Rule.Port `
        -Profile Domain,Private `
        -RemoteAddress LocalSubnet | Out-Null
}

Start-ScheduledTask -TaskName 'SentryLoom HQ Server'
Wait-HqListener ([int]$Config.port)
Set-Content `
    -LiteralPath (Join-Path $PSScriptRoot 'SentryLoom HQ.url') `
    -Value "[InternetShortcut]`r`nURL=https://$($Config.publicHost):$($Config.port)`r`n" `
    -Encoding ASCII `
    -Force
$PasswordSummary = if ($PasswordUpdated) {
    'The administrator password was updated to the value entered in Setup.'
} else {
    'The existing administrator password was preserved.'
}
$Summary = @(
    'SentryLoom HQ was upgraded successfully.'
    ''
    "Console: https://$($Config.publicHost):$($Config.port)"
    "Certificate SHA-256: $($Config.tls.fingerprint256)"
    ''
    'The existing database, certificate, and configuration were preserved.'
    $PasswordSummary
) -join [Environment]::NewLine
Write-Host $Summary -ForegroundColor Green
if ($ResultPath) {
    Set-Content -LiteralPath $ResultPath -Value $Summary -Encoding ASCII -Force
}
