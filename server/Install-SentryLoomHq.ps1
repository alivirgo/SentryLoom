[CmdletBinding()]
param(
    [string]$PublicHost = $env:COMPUTERNAME,
    [string]$HqName = 'SentryLoom HQ',
    [ValidateRange(1024, 65535)]
    [int]$Port = 8443,
    [string]$ResultPath,
    [string]$AdminPasswordFile,
    [string]$InstallLogPath,
    [string]$TargetVersion = '0.4.5'
)

$ErrorActionPreference = 'Stop'
$InstallLog = if ($InstallLogPath) {
    $InstallLogPath
} else {
    Join-Path $env:ProgramData 'SentryLoom HQ\Logs\install.log'
}
New-Item -ItemType Directory -Path (Split-Path -Parent $InstallLog) -Force | Out-Null
function Write-InstallStep([string]$Message) {
    $Line = '{0:u} {1}' -f (Get-Date), $Message
    Add-Content -LiteralPath $InstallLog -Value $Line -Encoding UTF8
    Write-Host $Message -ForegroundColor Cyan
}
trap {
    $Failure = "SentryLoom HQ setup failed: $($_.Exception.Message)"
    Add-Content -LiteralPath $InstallLog -Value ('{0:u} ERROR {1}' -f (Get-Date), $Failure) -Encoding UTF8
    if ($ResultPath) {
        Set-Content -LiteralPath $ResultPath -Value "$Failure`r`nDetailed log: $InstallLog" -Encoding UTF8 -Force
    }
    Write-Error $Failure
    exit 1
}
Write-InstallStep 'Starting SentryLoom HQ configuration.'

$Node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
if (-not (Test-Path -LiteralPath $Node)) {
    throw 'Node.js 24 or later is required.'
}

$ConfigPath = Join-Path $PSScriptRoot 'data\config.json'
$FreshInstall = -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)
$SelectedPassword = ''
if ($AdminPasswordFile) {
    if (-not (Test-Path -LiteralPath $AdminPasswordFile -PathType Leaf)) {
        throw 'Setup did not provide the administrator password transfer file.'
    }
    $SelectedPassword = [IO.File]::ReadAllText(
        [IO.Path]::GetFullPath($AdminPasswordFile),
        [Text.UTF8Encoding]::new($true)
    )
    if ($SelectedPassword.Length -lt 12 -or $SelectedPassword.Length -gt 128) {
        throw 'The HQ administrator password must contain 12 to 128 characters.'
    }
}

function Wait-HqListener([int]$ListenerPort) {
    Write-InstallStep "Waiting for the HQ HTTPS listener on TCP port $ListenerPort."
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
    Write-InstallStep "HQ is accepting HTTPS connections on TCP port $ListenerPort."
}

function Backup-HqState([string]$DataPath, [string]$TargetVersion) {
    if (-not (Test-Path -LiteralPath $DataPath -PathType Container)) { return $null }
    $Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Backup = Join-Path $env:ProgramData "SentryLoom HQ\UpgradeBackups\$Stamp-$TargetVersion"
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    & "$env:WINDIR\System32\icacls.exe" `
        $Backup `
        '/inheritance:r' `
        '/grant:r' `
        '*S-1-5-18:(OI)(CI)F' `
        '*S-1-5-32-544:(OI)(CI)F' `
        "*${CurrentSid}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restrict the HQ upgrade-backup permissions.'
    }
    Get-ChildItem -LiteralPath $DataPath -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $Backup -Recurse -Force
    }
    @{
        schemaVersion = 1
        createdAt = (Get-Date).ToUniversalTime().ToString('o')
        targetVersion = $TargetVersion
        source = $DataPath
        backup = $Backup
        policy = 'retain-unless-versioned-migration'
    } | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $Backup 'upgrade-backup.json') -Encoding UTF8 -Force
    return $Backup
}

try {
    if ($SelectedPassword) {
        $env:SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD = $SelectedPassword
    }

    if ($FreshInstall) {
        Write-InstallStep 'Creating the HQ TLS certificate, configuration, and database.'
        & (Join-Path $PSScriptRoot 'Initialize-SentryLoomHq.ps1') `
            -PublicHost $PublicHost `
            -HqName $HqName `
            -Port $Port
        if ($LASTEXITCODE -ne 0) {
            throw "HQ initialization failed with exit code $LASTEXITCODE."
        }
    } else {
        Write-InstallStep 'Existing HQ data was found; preserving its database and TLS certificate.'
    }

    $Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    & "$env:WINDIR\System32\icacls.exe" `
        (Join-Path $PSScriptRoot 'data') `
        '/inheritance:r' `
        '/grant:r' `
        '*S-1-5-18:(OI)(CI)F' `
        '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restrict the HQ data and protected-secret permissions.'
    }
    Write-InstallStep 'Restricted HQ data and protected secrets to SYSTEM and local administrators.'
    $StagingDirectory = if ($Config.updates.stagingDirectory) {
        [string]$Config.updates.stagingDirectory
    } else {
        'Z:\Extreme Control\SentryLoom Updates'
    }
    $StagingDrive = if ($StagingDirectory -match '^([A-Za-z]):\\') {
        Get-PSDrive -Name $Matches[1] -PSProvider FileSystem -ErrorAction SilentlyContinue
    } else {
        $null
    }
    $NetworkStaging = $StagingDirectory.StartsWith('\\') -or
        -not [string]::IsNullOrWhiteSpace([string]$StagingDrive.DisplayRoot)
    if (Test-Path -LiteralPath $StagingDirectory -PathType Container) {
        if ($NetworkStaging) {
            Write-InstallStep 'The update staging folder is a mapped/network share. Configure its UNC path in HQ and grant share plus NTFS read access to this HQ computer account.'
        } else {
            & "$env:WINDIR\System32\icacls.exe" `
                $StagingDirectory `
                '/grant' `
                '*S-1-5-18:(OI)(CI)RX' | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Could not grant the HQ SYSTEM task read access to update staging: $StagingDirectory"
            }
            Write-InstallStep "Granted the HQ SYSTEM task read access to update staging: $StagingDirectory"
        }
    } else {
        Write-InstallStep "Update staging is not currently visible to Setup: $StagingDirectory"
    }
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

    Write-InstallStep 'Stopping any running HQ task before configuration is replaced.'
    Stop-ScheduledTask -TaskName 'SentryLoom HQ Server' -ErrorAction SilentlyContinue
    $StateBackup = $null
    if (-not $FreshInstall) {
        Write-InstallStep 'Preserving the HQ database, settings, TLS certificate, updates, and operational history.'
        Start-Sleep -Milliseconds 750
        $StateBackup = Backup-HqState (Join-Path $PSScriptRoot 'data') $TargetVersion
        Write-InstallStep "Existing HQ state was preserved at $StateBackup."
    }
    $PasswordUpdated = $false
    if ($SelectedPassword) {
        Write-InstallStep 'Hashing the administrator password selected in Setup.'
        & $Node `
            --disable-warning=ExperimentalWarning `
            (Join-Path $PSScriptRoot 'src\set-admin-password.js') `
            $ConfigPath
        if ($LASTEXITCODE -ne 0) {
            throw "Updating the HQ administrator password failed with exit code $LASTEXITCODE."
        }
        Write-InstallStep 'Verifying the stored administrator password before HQ starts.'
        & $Node `
            --disable-warning=ExperimentalWarning `
            (Join-Path $PSScriptRoot 'src\verify-admin-password.js') `
            $ConfigPath
        if ($LASTEXITCODE -ne 0) {
            throw "Verifying the HQ administrator password failed with exit code $LASTEXITCODE."
        }
        $PasswordUpdated = $true
        Write-InstallStep 'Administrator password verification succeeded.'
    }

    Write-InstallStep 'Registering the self-restarting HQ startup task under Local System.'
    Register-ScheduledTask `
        -TaskName 'SentryLoom HQ Server' `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Settings $Settings `
        -Description 'SentryLoom HQ management server' `
        -Force | Out-Null

    $DiscoveryPort = if ($Config.discovery.port) { [int]$Config.discovery.port } else { 32110 }
    Write-InstallStep "Configuring Windows Firewall for HTTPS TCP $($Config.port) and discovery UDP $DiscoveryPort."
    Remove-NetFirewallRule -DisplayName 'SentryLoom HQ - HTTPS' -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName 'SentryLoom HQ - Discovery' -ErrorAction SilentlyContinue
    $FirewallRules = @(
        @{
            Name = 'SentryLoom-HQ-HTTPS-In'
            DisplayName = 'SentryLoom HQ - HTTPS inbound'
            Direction = 'Inbound'
            Protocol = 'TCP'
            LocalPort = [int]$Config.port
            RemotePort = 'Any'
        },
        @{
            Name = 'SentryLoom-HQ-Discovery-In'
            DisplayName = 'SentryLoom HQ - Discovery inbound'
            Direction = 'Inbound'
            Protocol = 'UDP'
            LocalPort = $DiscoveryPort
            RemotePort = 'Any'
        },
        @{
            Name = 'SentryLoom-HQ-Discovery-Out'
            DisplayName = 'SentryLoom HQ - Discovery responses outbound'
            Direction = 'Outbound'
            Protocol = 'UDP'
            LocalPort = $DiscoveryPort
            RemotePort = 'Any'
        },
        @{
            Name = 'SentryLoom-HQ-Wake-On-LAN-Out'
            DisplayName = 'SentryLoom HQ - Wake-on-LAN outbound'
            Direction = 'Outbound'
            Protocol = 'UDP'
            LocalPort = 'Any'
            RemotePort = 9
        }
    )
    foreach ($Rule in $FirewallRules) {
        Remove-NetFirewallRule -Name $Rule.Name -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName $Rule.DisplayName -ErrorAction SilentlyContinue
        New-NetFirewallRule `
            -Name $Rule.Name `
            -DisplayName $Rule.DisplayName `
            -Group 'SentryLoom HQ' `
            -Direction $Rule.Direction `
            -Action Allow `
            -Protocol $Rule.Protocol `
            -LocalPort $Rule.LocalPort `
            -RemotePort $Rule.RemotePort `
            -Profile Any `
            -RemoteAddress LocalSubnet | Out-Null
    }
    Get-NetFirewallRule -Group 'SentryLoom HQ' -ErrorAction Stop |
        Where-Object Enabled -ne 'True' |
        ForEach-Object { throw "Firewall rule '$($_.DisplayName)' is not enabled." }
    Write-InstallStep 'Windows Firewall rules were created and verified.'

    Write-InstallStep 'Starting SentryLoom HQ.'
    Start-ScheduledTask -TaskName 'SentryLoom HQ Server'
    Wait-HqListener ([int]$Config.port)
    Set-Content `
        -LiteralPath (Join-Path $PSScriptRoot 'SentryLoom HQ.url') `
        -Value "[InternetShortcut]`r`nURL=https://$($Config.publicHost):$($Config.port)`r`n" `
        -Encoding ASCII `
        -Force
    $PasswordSummary = if ($PasswordUpdated) {
        'The administrator password was stored and verified successfully.'
    } else {
        'The existing administrator password was preserved.'
    }
    $InstallKind = if ($FreshInstall) { 'initialized' } else { 'upgraded' }
    $DataSummary = if ($FreshInstall) {
        'A new database, certificate, and configuration were created.'
    } else {
        'The existing database, certificate, and configuration were preserved.'
    }
    $Summary = @(
        "SentryLoom HQ was $InstallKind successfully."
        ''
        "Console: https://$($Config.publicHost):$($Config.port)"
        "Certificate SHA-256: $($Config.tls.fingerprint256)"
        ''
        $DataSummary
        $(if ($StateBackup) { "Upgrade backup: $StateBackup" } else { 'Upgrade backup: not required for a first installation.' })
        $PasswordSummary
        'Firewall: HTTPS and LAN discovery rules are enabled.'
        "Detailed log: $InstallLog"
    ) -join [Environment]::NewLine
    Write-InstallStep "SentryLoom HQ $InstallKind successfully."
    Write-Host $Summary -ForegroundColor Green
    if ($ResultPath) {
        Set-Content -LiteralPath $ResultPath -Value $Summary -Encoding UTF8 -Force
    }
} finally {
    $env:SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD = $null
    $SelectedPassword = $null
    if ($AdminPasswordFile -and (Test-Path -LiteralPath $AdminPasswordFile)) {
        Remove-Item -LiteralPath $AdminPasswordFile -Force -ErrorAction SilentlyContinue
    }
}
