[CmdletBinding()]
param(
    [int]$Port = 0,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$NodeCandidate = Join-Path $env:ProgramFiles 'nodejs\node.exe'
$Node = if (Test-Path -LiteralPath $NodeCandidate) { $NodeCandidate } else { (Get-Command node -ErrorAction Stop).Source }
$Arguments = @('--disable-warning=ExperimentalWarning', (Join-Path $Root 'src\cli.js'), 'dashboard')
if ($Port -gt 0) { $Arguments += @('--port', $Port) }
if ($NoBrowser) { $Arguments += '--no-open' }

Set-Location $Root
& $Node @Arguments
