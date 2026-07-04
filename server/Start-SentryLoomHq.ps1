$ErrorActionPreference = 'Stop'
$Node = Join-Path $env:ProgramFiles 'nodejs\node.exe'
& $Node --disable-warning=ExperimentalWarning (Join-Path $PSScriptRoot 'src\main.js')
exit $LASTEXITCODE
