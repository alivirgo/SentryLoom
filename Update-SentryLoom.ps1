[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SetupFile,

    [Parameter(Mandatory)]
    [string]$ExpectedVersion,

    [Parameter(Mandatory)]
    [string]$ExpectedSha256,

    [Parameter(Mandatory)]
    [string]$ExpectedSignerThumbprint,

    [Parameter(Mandatory)]
    [string]$ExpectedSignerSubject,

    [Parameter(Mandatory)]
    [string]$StatusFile,

    [int]$ParentProcessId = 0
)

$ErrorActionPreference = 'Stop'

function Write-UpdateStatus([string]$State, [string]$ErrorMessage = '') {
    $Directory = Split-Path -Parent $StatusFile
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $Temporary = "$StatusFile.$PID.tmp"
    [ordered]@{
        state = $State
        currentVersion = if ($State -eq 'completed') { $ExpectedVersion } else { $null }
        targetVersion = $ExpectedVersion
        updatedAt = [DateTime]::UtcNow.ToString('o')
        error = if ($ErrorMessage) { $ErrorMessage } else { $null }
    } | ConvertTo-Json | Set-Content -LiteralPath $Temporary -Encoding utf8NoBOM -Force
    Move-Item -LiteralPath $Temporary -Destination $StatusFile -Force
}

try {
    Start-Sleep -Seconds 8
    $Setup = (Resolve-Path -LiteralPath $SetupFile).Path
    if ([IO.Path]::GetExtension($Setup) -ne '.exe') { throw 'The staged update is not an executable.' }
    $Hash = (Get-FileHash -LiteralPath $Setup -Algorithm SHA256).Hash
    if ($Hash -ne $ExpectedSha256) { throw 'The staged update failed SHA-256 verification.' }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Setup
    if ($Signature.Status -ne 'Valid' -or -not $Signature.SignerCertificate) {
        throw "Windows did not validate the update signature: $($Signature.StatusMessage)"
    }
    $ActualThumbprint = ([string]$Signature.SignerCertificate.Thumbprint).Replace(' ', '').ToUpperInvariant()
    $RequiredThumbprint = $ExpectedSignerThumbprint.Replace(' ', '').ToUpperInvariant()
    if ($ActualThumbprint -ne $RequiredThumbprint) {
        throw 'The staged update signer does not match the HQ manifest.'
    }
    if ([string]$Signature.SignerCertificate.Subject -ne $ExpectedSignerSubject) {
        throw "The staged update publisher does not match the HQ manifest: $($Signature.SignerCertificate.Subject)"
    }
    $Version = [string](Get-Item -LiteralPath $Setup).VersionInfo.ProductVersion
    if ($Version.Trim() -ne $ExpectedVersion) { throw "The staged update version is $Version, expected $ExpectedVersion." }
    Write-UpdateStatus 'installing'
    $LogDirectory = Join-Path $env:ProgramData 'SentryLoom\Updates'
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    $SetupLog = Join-Path $LogDirectory "Setup-$ExpectedVersion.log"
    $Arguments = @(
        '/VERYSILENT',
        '/SUPPRESSMSGBOXES',
        '/NORESTART',
        '/CLOSEAPPLICATIONS',
        "/LOG=`"$SetupLog`""
    )
    $Process = Start-Process -FilePath $Setup -ArgumentList $Arguments -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode -ne 0) { throw "Setup exited with code $($Process.ExitCode)." }
    $Installed = Join-Path $env:ProgramFiles 'SentryLoom\SentryLoom.exe'
    $InstalledVersion = [string](Get-Item -LiteralPath $Installed).VersionInfo.ProductVersion
    if ($InstalledVersion.Trim() -ne $ExpectedVersion) {
        throw "Setup completed but the installed version is $InstalledVersion."
    }
    Write-UpdateStatus 'completed'
    Remove-Item -LiteralPath $Setup -Force -ErrorAction SilentlyContinue
} catch {
    Write-UpdateStatus 'failed' $_.Exception.Message
    exit 1
}
