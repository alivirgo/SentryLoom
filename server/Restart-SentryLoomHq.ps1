[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell window.'
}

$ConfigPath = Join-Path $PSScriptRoot 'data\config.json'
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "SentryLoom HQ is not initialized at $ConfigPath"
}
$Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$Port = [int]$Config.port
$ExpectedMain = (Resolve-Path (Join-Path $PSScriptRoot 'src\main.js')).Path
$Listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue

if ($Listener) {
    $Owner = Get-CimInstance Win32_Process -Filter "ProcessId=$($Listener.OwningProcess)"
    $CommandLine = [string]$Owner.CommandLine
    if (($CommandLine -notlike "*$ExpectedMain*") -and
        ($CommandLine -notmatch 'server[\\/]src[\\/]main\.js|src[\\/]main\.js')) {
        throw "Port $Port is owned by a process that is not this SentryLoom HQ installation."
    }
    Stop-Process -Id $Listener.OwningProcess -Force
    $Deadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 250
        $Existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    } until (-not $Existing -or (Get-Date) -gt $Deadline)
    if ($Existing) { throw "The previous HQ process did not release TCP port $Port." }
}

$Node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
if (-not (Test-Path -LiteralPath $Node)) { throw 'Node.js runtime was not found.' }
$Log = Join-Path $PSScriptRoot 'data\hq-server.log'
$ErrorLog = Join-Path $PSScriptRoot 'data\hq-server-error.log'
Start-Process `
    -FilePath $Node `
    -ArgumentList '--disable-warning=ExperimentalWarning', "`"$ExpectedMain`"" `
    -WorkingDirectory $PSScriptRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $Log `
    -RedirectStandardError $ErrorLog

$Deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 500
    $Started = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
} until ($Started -or (Get-Date) -gt $Deadline)
if (-not $Started) {
    $Details = if (Test-Path -LiteralPath $ErrorLog) {
        Get-Content -LiteralPath $ErrorLog -Raw
    } else {
        'No server error log was produced.'
    }
    throw "Updated SentryLoom HQ did not start. $Details"
}

Write-Host "SentryLoom HQ restarted successfully on TCP $Port." -ForegroundColor Green
