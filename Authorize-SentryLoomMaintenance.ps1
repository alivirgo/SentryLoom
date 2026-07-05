[CmdletBinding()]
param(
    [ValidateSet('uninstall', 'disable-protection', 'critical-settings', 'file-maintenance')]
    [string]$Action = 'uninstall',

    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$PowerShell = (Get-Process -Id $PID -ErrorAction Stop).Path
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevated) {
        throw 'Maintenance authorization requires administrator elevation.'
    }
    $Process = Start-Process `
        -FilePath $PowerShell `
        -ArgumentList @(
            '-NoLogo',
            '-NoProfile',
            '-WindowStyle', 'Hidden',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$PSCommandPath`"",
            '-Action', $Action,
            '-Elevated'
        ) `
        -Verb RunAs `
        -Wait `
        -PassThru
    exit $Process.ExitCode
}

$TamperHelper = Join-Path $PSScriptRoot 'Set-SentryLoomTamperProtection.ps1'
function Enable-AuthorizedFileMaintenance {
    if ($Action -notin @('uninstall', 'file-maintenance')) {
        return
    }
    if (-not (Test-Path -LiteralPath $TamperHelper -PathType Leaf)) {
        throw 'SentryLoom tamper-protection components are missing.'
    }

    $TaskName = 'SentryLoom - Open Authorized File Maintenance'
    $Arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass ' +
        "-File `"$TamperHelper`" -Mode Disable -InstallRoot `"$PSScriptRoot`" -RelockAfterMinutes 5"
    $TaskAction = New-ScheduledTaskAction `
        -Execute $PowerShell `
        -Argument $Arguments `
        -WorkingDirectory $PSScriptRoot
    $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $TaskPrincipal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $TaskSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $StartedAfter = (Get-Date).AddSeconds(-2)

    try {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $TaskAction `
            -Trigger $TaskTrigger `
            -Principal $TaskPrincipal `
            -Settings $TaskSettings `
            -Description 'Opens a bounded SentryLoom file-maintenance window after HQ authorization.' `
            -Force | Out-Null
        Start-ScheduledTask -TaskName $TaskName

        $Deadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 200
            $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            $Info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
            $Completed = $Info.LastRunTime -ge $StartedAfter -and $Task.State -ne 'Running'
        } while (-not $Completed -and [DateTime]::UtcNow -lt $Deadline)

        if (-not $Completed) {
            throw 'SentryLoom timed out while opening the authorized file-maintenance window.'
        }
        if ($Info.LastTaskResult -ne 0) {
            throw "SentryLoom could not open the authorized file-maintenance window (task result $($Info.LastTaskResult))."
        }
    } finally {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# The resident protection and signed automatic updater run as LocalSystem.
# That machine identity already owns the protected tree and does not need a
# reusable password or a writable administrator ACL.
if ($Identity.User.Value -eq 'S-1-5-18') {
    return
}

$ConfigPath = Join-Path $env:ProgramData 'SentryLoom\config.json'
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    Enable-AuthorizedFileMaintenance
    exit 0
}
$Config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if (-not $Config.management.enabled) {
    Enable-AuthorizedFileMaintenance
    exit 0
}

$Node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
$Cli = Join-Path $PSScriptRoot 'src\cli.js'
if (-not (Test-Path -LiteralPath $Node) -or -not (Test-Path -LiteralPath $Cli)) {
    throw 'SentryLoom maintenance authorization components are missing.'
}

function Test-MaintenancePassword([string]$Password) {
    $env:SENTRYLOOM_MAINTENANCE_PASSWORD = $Password
    $env:SENTRYLOOM_MAINTENANCE_ACTION = $Action
    try {
        $Output = & $Node `
            --disable-warning=ExperimentalWarning `
            $Cli `
            hq maintenance-authorize-env 2>&1 | Out-String
        return @{
            Accepted = $LASTEXITCODE -eq 0
            Message = ($Output -replace 'SentryLoom error:\s*', '').Trim()
        }
    } finally {
        $env:SENTRYLOOM_MAINTENANCE_PASSWORD = $null
        $env:SENTRYLOOM_MAINTENANCE_ACTION = $null
        $Password = $null
    }
}

$ProvidedPassword = [string]$env:SENTRYLOOM_MAINTENANCE_PASSWORD
if ($ProvidedPassword) {
    $Result = Test-MaintenancePassword $ProvidedPassword
    if ($Result.Accepted) {
        Enable-AuthorizedFileMaintenance
    }
    exit $(if ($Result.Accepted) { 0 } else { 1 })
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
    $Form = New-Object Windows.Forms.Form
    $Form.Text = 'SentryLoom maintenance authorization'
    $Form.StartPosition = 'CenterScreen'
    $Form.FormBorderStyle = 'FixedDialog'
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Form.ClientSize = New-Object Drawing.Size(520, 205)
    $Form.TopMost = $true

    $Heading = New-Object Windows.Forms.Label
    $Heading.Text = 'Administrator approval required'
    $Heading.Font = New-Object Drawing.Font('Segoe UI Semibold', 13)
    $Heading.AutoSize = $true
    $Heading.Location = New-Object Drawing.Point(22, 18)
    $Form.Controls.Add($Heading)

    $Description = New-Object Windows.Forms.Label
    $Description.Text = 'Enter a current one-time maintenance password generated by SentryLoom HQ. The password expires automatically and can be revoked by an HQ administrator.'
    $Description.Size = New-Object Drawing.Size(475, 48)
    $Description.Location = New-Object Drawing.Point(24, 54)
    $Form.Controls.Add($Description)

    $PasswordBox = New-Object Windows.Forms.TextBox
    $PasswordBox.UseSystemPasswordChar = $true
    $PasswordBox.Size = New-Object Drawing.Size(472, 28)
    $PasswordBox.Location = New-Object Drawing.Point(24, 108)
    $Form.Controls.Add($PasswordBox)

    $Cancel = New-Object Windows.Forms.Button
    $Cancel.Text = 'Cancel'
    $Cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $Cancel.Size = New-Object Drawing.Size(100, 32)
    $Cancel.Location = New-Object Drawing.Point(288, 153)
    $Form.Controls.Add($Cancel)

    $Authorize = New-Object Windows.Forms.Button
    $Authorize.Text = 'Authorize'
    $Authorize.DialogResult = [Windows.Forms.DialogResult]::OK
    $Authorize.Size = New-Object Drawing.Size(100, 32)
    $Authorize.Location = New-Object Drawing.Point(396, 153)
    $Form.Controls.Add($Authorize)
    $Form.AcceptButton = $Authorize
    $Form.CancelButton = $Cancel

    $Form.Add_Shown({ $PasswordBox.Focus() })
    if ($Form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) {
        exit 1
    }
    $Result = Test-MaintenancePassword $PasswordBox.Text
    $PasswordBox.Text = ''
    $Form.Dispose()
    if ($Result.Accepted) {
        Enable-AuthorizedFileMaintenance
        [Windows.Forms.MessageBox]::Show(
            $(if ($Action -eq 'file-maintenance') {
                'Maintenance authorization accepted. SentryLoom files can be maintained for five minutes and will then lock automatically.'
            } else {
                'Maintenance authorization accepted. The requested operation can continue.'
            }),
            'SentryLoom',
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        exit 0
    }
    [Windows.Forms.MessageBox]::Show(
        $(if ($Result.Message) { $Result.Message } else { 'The maintenance password was not accepted.' }),
        'SentryLoom authorization failed',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
}
exit 1
