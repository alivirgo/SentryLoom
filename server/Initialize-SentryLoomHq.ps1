[CmdletBinding()]
param(
    [string]$PublicHost = $env:COMPUTERNAME,
    [string]$HqName = 'SentryLoom HQ',
    [ValidateRange(1024, 65535)]
    [int]$Port = 8443,
    [string]$DataDirectory = (Join-Path $PSScriptRoot 'data'),
    [switch]$RegisterStartupTask,
    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'
$Node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
if (-not (Test-Path -LiteralPath $Node)) {
    throw 'Node.js 24 or later is required. Install OpenJS.NodeJS.LTS with winget.'
}
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
$ConfigPath = Join-Path $DataDirectory 'config.json'
if (Test-Path -LiteralPath $ConfigPath) {
    throw "HQ is already initialized at $ConfigPath"
}

function New-RandomBytes([int]$Length) {
    $Bytes = New-Object byte[] $Length
    $Generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $Generator.GetBytes($Bytes) } finally { $Generator.Dispose() }
    return $Bytes
}

$PasswordAlphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%'
$ProvidedAdminPassword = [string]$env:SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD
$PasswordWasProvided = -not [string]::IsNullOrWhiteSpace($ProvidedAdminPassword)
if ($PasswordWasProvided) {
    if ($ProvidedAdminPassword.Length -lt 12 -or $ProvidedAdminPassword.Length -gt 128) {
        throw 'The HQ administrator password must contain 12 to 128 characters.'
    }
    $AdminPassword = $ProvidedAdminPassword
} else {
    $AdminPassword = -join ((New-RandomBytes 24) | ForEach-Object {
        $PasswordAlphabet[$_ % $PasswordAlphabet.Length]
    })
}
$PfxPassword = [Convert]::ToBase64String((New-RandomBytes 24))
$SecurePfxPassword = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
$DnsNames = @($PublicHost, 'localhost')
$Certificate = New-SelfSignedCertificate `
    -DnsName $DnsNames `
    -CertStoreLocation 'Cert:\LocalMachine\My' `
    -FriendlyName 'SentryLoom HQ TLS' `
    -NotAfter (Get-Date).AddYears(3) `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable
$PfxPath = Join-Path $DataDirectory 'sentryloom-hq.pfx'
Export-PfxCertificate -Cert $Certificate -FilePath $PfxPath -Password $SecurePfxPassword | Out-Null
$Hasher = [Security.Cryptography.SHA256]::Create()
try {
    $Fingerprint = ([BitConverter]::ToString($Hasher.ComputeHash($Certificate.RawData))).Replace('-', '')
} finally {
    $Hasher.Dispose()
}

$env:SENTRYLOOM_HQ_ADMIN_PASSWORD = $AdminPassword
$env:SENTRYLOOM_HQ_PFX_PASSWORD = $PfxPassword
$env:SENTRYLOOM_HQ_PFX_PATH = $PfxPath
$env:SENTRYLOOM_HQ_CERT_FINGERPRINT = $Fingerprint
$env:SENTRYLOOM_HQ_PUBLIC_HOST = $PublicHost
$env:SENTRYLOOM_HQ_NAME = $HqName
$env:SENTRYLOOM_HQ_PORT = [string]$Port
try {
    & $Node --disable-warning=ExperimentalWarning (Join-Path $PSScriptRoot 'src\init.js') $ConfigPath
    if ($LASTEXITCODE -ne 0) { throw "HQ initialization failed with exit code $LASTEXITCODE" }
} finally {
    $env:SENTRYLOOM_HQ_ADMIN_PASSWORD = $null
    $env:SENTRYLOOM_HQ_PFX_PASSWORD = $null
    $env:SENTRYLOOM_HQ_CERT_FINGERPRINT = $null
}

if ($RegisterStartupTask) {
    $Action = New-ScheduledTaskAction -Execute $Node -Argument "--disable-warning=ExperimentalWarning `"$PSScriptRoot\src\main.js`"" -WorkingDirectory $PSScriptRoot
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'SentryLoom HQ Server' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
    Start-ScheduledTask -TaskName 'SentryLoom HQ Server'
}

foreach ($Rule in @(
    @{ Name = 'SentryLoom HQ - HTTPS'; Protocol = 'TCP'; Port = $Port },
    @{ Name = 'SentryLoom HQ - Discovery'; Protocol = 'UDP'; Port = 32110 }
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

Write-Host ''
Write-Host 'SentryLoom HQ initialized.' -ForegroundColor Green
Write-Host "Console: https://${PublicHost}:$Port"
Write-Host "Certificate SHA-256: $Fingerprint"
if ($PasswordWasProvided) {
    Write-Host 'Administrator password: configured during setup' -ForegroundColor Yellow
} else {
    Write-Host "Administrator password: $AdminPassword" -ForegroundColor Yellow
}
Write-Host 'New endpoints appear in the HQ approval queue automatically.' -ForegroundColor Yellow
Write-Host 'Save the administrator password now. It is not shown again.'
if ($ResultPath) {
    $PasswordResult = if ($PasswordWasProvided) {
        'Administrator password: configured during setup'
    } else {
        "Administrator password: $AdminPassword"
    }
    $Result = @(
        'SentryLoom HQ was initialized successfully.'
        ''
        "Console: https://${PublicHost}:$Port"
        "Certificate SHA-256: $Fingerprint"
        $PasswordResult
        ''
        'Save the administrator password now. It is not shown again.'
        'New endpoints will appear in the HQ approval queue.'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $ResultPath -Value $Result -Encoding ASCII -Force
}
