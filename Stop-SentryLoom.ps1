[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallRoot,

    [string]$FailureLogPath,

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 15,

    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$FailureLog = if ($FailureLogPath) { $FailureLogPath } else { Join-Path $env:TEMP 'SentryLoom-Stop-Error.txt' }
Remove-Item -LiteralPath $FailureLog -Force -ErrorAction SilentlyContinue
trap {
    $Details = @(
        $_.Exception.Message
        $_.ScriptStackTrace
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $FailureLog -Value $Details -Encoding ASCII -Force
    Write-Error $Details
    exit 1
}

$Root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($Root) -or $Root.Length -lt 4) {
    throw "Refusing an invalid SentryLoom installation path: '$InstallRoot'"
}

$Launcher = [IO.Path]::GetFullPath((Join-Path $Root 'SentryLoom.exe'))
$Cli = [IO.Path]::GetFullPath((Join-Path $Root 'src\cli.js'))
$StartScript = [IO.Path]::GetFullPath((Join-Path $Root 'Start-SentryLoom.ps1'))
$CliForward = $Cli.Replace('\', '/')
$StartForward = $StartScript.Replace('\', '/')

if (-not $WhatIf) {
    Stop-ScheduledTask -TaskName 'SentryLoom - Realtime Protection' -ErrorAction SilentlyContinue
}

$Targets = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
    if ([int]$_.ProcessId -eq $PID) { return $false }
    $Name = [string]$_.Name
    $Executable = [string]$_.ExecutablePath
    $CommandLine = [string]$_.CommandLine
    if ($Name -ieq 'SentryLoom.exe') {
        return $Executable -and [IO.Path]::GetFullPath($Executable).Equals($Launcher, [StringComparison]::OrdinalIgnoreCase)
    }
    if ($Name -ieq 'node.exe') {
        return $CommandLine.IndexOf($Cli, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $CommandLine.IndexOf($CliForward, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    if ($Name -in @('powershell.exe', 'pwsh.exe')) {
        return $CommandLine.IndexOf($StartScript, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
            $CommandLine.IndexOf($StartForward, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    return $false
})

if ($WhatIf) {
    $Targets | Select-Object ProcessId, Name, ExecutablePath, CommandLine | ConvertTo-Json -Compress
    exit 0
}

foreach ($Target in $Targets) {
    Stop-Process -Id ([int]$Target.ProcessId) -Force -ErrorAction SilentlyContinue
}

$Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    $Remaining = @($Targets | Where-Object { Get-Process -Id ([int]$_.ProcessId) -ErrorAction SilentlyContinue })
    if ($Remaining.Count -eq 0) { break }
    Start-Sleep -Milliseconds 200
} while ([DateTime]::UtcNow -lt $Deadline)

if ($Remaining.Count -gt 0) {
    throw "SentryLoom processes did not exit: $($Remaining.ProcessId -join ', ')"
}

[pscustomobject]@{
    stopped = $Targets.Count
    installRoot = $Root
} | ConvertTo-Json -Compress
