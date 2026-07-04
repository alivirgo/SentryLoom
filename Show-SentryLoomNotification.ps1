[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Title,

    [Parameter(Mandatory)]
    [string]$Message,

    [Parameter(Mandatory)]
    [string]$LauncherPath,

    [ValidateSet('overview', 'scan', 'quarantine', 'activity', 'settings')]
    [string]$Page = 'quarantine',

    [ValidateSet('Info', 'Warning', 'Error')]
    [string]$Severity = 'Warning'
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$notification = New-Object System.Windows.Forms.NotifyIcon
$notification.Icon = if (Test-Path -LiteralPath $LauncherPath) {
    [System.Drawing.Icon]::ExtractAssociatedIcon($LauncherPath)
} else {
    [System.Drawing.SystemIcons]::Shield
}
$notification.Text = 'SentryLoom Endpoint Security'
$notification.BalloonTipTitle = $Title
$notification.BalloonTipText = $Message
$notification.BalloonTipIcon = [System.Enum]::Parse([System.Windows.Forms.ToolTipIcon], $Severity)
$notification.Visible = $true

$script:activated = $false
$script:closed = $false
$openConsole = {
    if ($script:activated) { return }
    $script:activated = $true
    Start-Process -FilePath $LauncherPath -ArgumentList "--page=$Page"
}
$notification.add_BalloonTipClicked($openConsole)
$notification.add_Click($openConsole)
$notification.add_BalloonTipClosed({ $script:closed = $true })

try {
    $notification.ShowBalloonTip(15000)
    $expiresAt = [DateTime]::UtcNow.AddSeconds(45)
    while (-not $script:activated -and -not $script:closed -and [DateTime]::UtcNow -lt $expiresAt) {
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 100
    }
} finally {
    $notification.Visible = $false
    $notification.Dispose()
}
