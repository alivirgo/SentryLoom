[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SetupFile,

    [string]$UpdatesDirectory = (Join-Path $PSScriptRoot 'data\updates'),

    [string]$ReleaseNotes = ''
)

$ErrorActionPreference = 'Stop'
$Source = (Resolve-Path -LiteralPath $SetupFile).Path
$Item = Get-Item -LiteralPath $Source
if ($Item.Extension -ne '.exe') {
    throw 'The client update package must be a SentryLoom Setup executable.'
}
$Version = ([string]$Item.VersionInfo.ProductVersion).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "The Setup executable has an invalid product version: $Version"
}
$Signature = Get-AuthenticodeSignature -LiteralPath $Source
if ($Signature.Status -ne 'Valid' -or -not $Signature.SignerCertificate) {
    throw "Windows did not validate the Setup signature: $($Signature.StatusMessage)"
}
$UpdatesRoot = [IO.Path]::GetFullPath($UpdatesDirectory)
New-Item -ItemType Directory -Path $UpdatesRoot -Force | Out-Null
$FileName = "SentryLoom-Setup-$Version.exe"
$Destination = Join-Path $UpdatesRoot $FileName
$TemporaryPackage = "$Destination.$PID.tmp"
Copy-Item -LiteralPath $Source -Destination $TemporaryPackage -Force
$Hash = (Get-FileHash -LiteralPath $TemporaryPackage -Algorithm SHA256).Hash
$Copied = Get-Item -LiteralPath $TemporaryPackage
$Manifest = [ordered]@{
    schemaVersion = 1
    version = $Version
    fileName = $FileName
    size = [long]$Copied.Length
    sha256 = $Hash
    signerThumbprint = $Signature.SignerCertificate.Thumbprint
    signerSubject = $Signature.SignerCertificate.Subject
    publishedAt = [DateTime]::UtcNow.ToString('o')
    releaseNotes = $ReleaseNotes
}
$ManifestPath = Join-Path $UpdatesRoot 'latest.json'
$TemporaryManifest = "$ManifestPath.$PID.tmp"
try {
    Move-Item -LiteralPath $TemporaryPackage -Destination $Destination -Force
    $Manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $TemporaryManifest -Encoding utf8NoBOM
    Move-Item -LiteralPath $TemporaryManifest -Destination $ManifestPath -Force
} finally {
    Remove-Item -LiteralPath $TemporaryPackage,$TemporaryManifest -Force -ErrorAction SilentlyContinue
}

Write-Host "Published SentryLoom client update $Version." -ForegroundColor Green
Write-Host "Package: $Destination"
Write-Host "SHA-256: $Hash"
Write-Host "Signer: $($Signature.SignerCertificate.Subject)"
