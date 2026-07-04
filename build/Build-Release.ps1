[CmdletBinding(DefaultParameterSetName = 'Unsigned')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Pfx')]
    [string]$PfxPath,

    [Parameter(Mandatory, ParameterSetName = 'Pfx')]
    [securestring]$PfxPassword,

    [Parameter(Mandatory, ParameterSetName = 'Store')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
    [switch]$AllowUnsignedDevelopmentBuild,

    [string]$ExpectedPublisher
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Package = Get-Content -LiteralPath (Join-Path $Root 'package.json') -Raw | ConvertFrom-Json
$HqPackage = Get-Content -LiteralPath (Join-Path $Root 'server\package.json') -Raw | ConvertFrom-Json
$Version = [string]$Package.version
$HqVersion = [string]$HqPackage.version
$Output = Join-Path $Root 'build\output'
$Launcher = Join-Path $Output 'SentryLoom.exe'
$Setup = Join-Path $Root "dist\SentryLoom-Setup-$Version.exe"
$HqSetup = Join-Path $Root "dist\SentryLoom-HQ-Setup-$HqVersion.exe"
$Source = Join-Path $Root 'launcher\SentryLoomLauncher.cs'
$Icon = Join-Path $Root 'assets\SentryLoom.ico'
$Compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$InnoCompiler = Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "package.json contains an invalid release version: $Version"
}
if ($HqVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "server/package.json contains an invalid release version: $HqVersion"
}

New-Item -ItemType Directory -Path $Output -Force | Out-Null
& $Compiler /nologo /target:winexe /platform:anycpu /optimize+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll "/win32icon:$Icon" "/out:$Launcher" $Source
if ($LASTEXITCODE -ne 0) { throw 'Native launcher compilation failed.' }

function Find-SignTool {
    $Roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin')
    )
    return $Roots |
        Where-Object { Test-Path -LiteralPath $_ } |
        ForEach-Object { Get-ChildItem -LiteralPath $_ -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue } |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

function Invoke-ReleaseSignature([string]$File) {
    $SignTool = Find-SignTool
    if (-not $SignTool) {
        throw 'SignTool was not found. Install the Windows SDK Signing Tools before producing a signed release.'
    }

    $Arguments = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', 'http://timestamp.digicert.com')
    if ($PSCmdlet.ParameterSetName -eq 'Pfx') {
        $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
        try {
            $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
            $ResolvedPfx = (Resolve-Path -LiteralPath $PfxPath).Path
            $Arguments += @('/f', $ResolvedPfx, '/p', $Password)
            & $SignTool @Arguments $File
        } finally {
            if ($Password) { $Password = $null }
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
        }
    } else {
        $Arguments += @('/sha1', ($CertificateThumbprint -replace '\s', ''))
        & $SignTool @Arguments $File
    }
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed: $File" }

    $Signature = Get-AuthenticodeSignature -LiteralPath $File
    if ($Signature.Status -ne 'Valid') { throw "Windows did not validate the signature on ${File}: $($Signature.StatusMessage)" }
    if ($ExpectedPublisher -and
        $Signature.SignerCertificate.Subject -notmatch [Regex]::Escape($ExpectedPublisher)) {
        throw "The signing certificate does not match expected publisher '$ExpectedPublisher': $($Signature.SignerCertificate.Subject)"
    }
}

if ($PSCmdlet.ParameterSetName -ne 'Unsigned') {
    Invoke-ReleaseSignature $Launcher
}

& $InnoCompiler (Join-Path $Root 'installer\SentryLoom.iss')
if ($LASTEXITCODE -ne 0) { throw 'Client installer compilation failed.' }
& $InnoCompiler (Join-Path $Root 'installer\SentryLoomHq.iss')
if ($LASTEXITCODE -ne 0) { throw 'HQ server installer compilation failed.' }

if ($PSCmdlet.ParameterSetName -ne 'Unsigned') {
    Invoke-ReleaseSignature $Setup
    Invoke-ReleaseSignature $HqSetup
} else {
    Write-Warning 'Unsigned development artifacts were created. Do not distribute them as a signed release.'
}

Get-Item $Launcher, $Setup, $HqSetup | Select-Object FullName, Length, @{
    Name = 'SignatureStatus'
    Expression = { (Get-AuthenticodeSignature $_.FullName).Status }
}, @{
    Name = 'SHA256'
    Expression = { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
}
