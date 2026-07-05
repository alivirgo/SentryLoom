[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Disable', 'Status')]
    [string]$Mode = 'Status',

    [string]$InstallRoot = $PSScriptRoot,

    [ValidateRange(1, 60)]
    [int]$RelockAfterMinutes = 5
)

$ErrorActionPreference = 'Stop'
$RelockTaskName = 'SentryLoom - Restore Tamper Protection'
$SystemSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$AdministratorsSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$UsersSid = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')

function Get-ValidatedInstallRoot {
    $Root = [IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($Root) -or $Root.Length -lt 4) {
        throw "Refusing an invalid SentryLoom installation path: '$InstallRoot'"
    }
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "The SentryLoom installation directory does not exist: $Root"
    }
    $ExpectedLauncher = Join-Path $Root 'SentryLoom.exe'
    if (-not (Test-Path -LiteralPath $ExpectedLauncher -PathType Leaf)) {
        throw "The selected directory is not a SentryLoom installation: $Root"
    }
    return $Root
}

function Test-IsAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-SentryLoomAcl([bool]$Directory, [bool]$Protected) {
    $Acl = if ($Directory) {
        New-Object Security.AccessControl.DirectorySecurity
    } else {
        New-Object Security.AccessControl.FileSecurity
    }
    $Acl.SetAccessRuleProtection($true, $false)
    $Acl.SetOwner($SystemSid)

    $Inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $Propagation = [Security.AccessControl.PropagationFlags]::None
    $Allow = [Security.AccessControl.AccessControlType]::Allow
    $AdministratorRights = if ($Protected) {
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    } else {
        [Security.AccessControl.FileSystemRights]::FullControl
    }

    foreach ($Rule in @(
        (New-Object Security.AccessControl.FileSystemAccessRule(
            $SystemSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance,
            $Propagation,
            $Allow
        )),
        (New-Object Security.AccessControl.FileSystemAccessRule(
            $AdministratorsSid,
            $AdministratorRights,
            $Inheritance,
            $Propagation,
            $Allow
        )),
        (New-Object Security.AccessControl.FileSystemAccessRule(
            $UsersSid,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            $Inheritance,
            $Propagation,
            $Allow
        ))
    )) {
        [void]$Acl.AddAccessRule($Rule)
    }
    return $Acl
}

function Set-TreeProtection([string]$Root, [bool]$Protected) {
    $Items = @(Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop)
    if (-not $Protected) {
        Set-Acl -LiteralPath $Root -AclObject (New-SentryLoomAcl $true $false)
    }

    foreach ($Item in $Items) {
        $FullName = [IO.Path]::GetFullPath($Item.FullName)
        if (-not $FullName.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to change permissions outside the installation directory: $FullName"
        }
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to change permissions through a reparse point: $FullName"
        }
        Set-Acl -LiteralPath $FullName -AclObject (New-SentryLoomAcl $Item.PSIsContainer $Protected)
    }

    if ($Protected) {
        Set-Acl -LiteralPath $Root -AclObject (New-SentryLoomAcl $true $true)
    }
}

function Register-Relock([string]$Root) {
    $PowerShell = (Get-Process -Id $PID -ErrorAction Stop).Path
    $Script = Join-Path $Root 'Set-SentryLoomTamperProtection.ps1'
    $Arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass ' +
        "-File `"$Script`" -Mode Apply -InstallRoot `"$Root`""
    $Action = New-ScheduledTaskAction -Execute $PowerShell -Argument $Arguments -WorkingDirectory $Root
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($RelockAfterMinutes)
    $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask `
        -TaskName $RelockTaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Settings $Settings `
        -Description 'Restores SentryLoom installation-directory tamper protection after authorized maintenance.' `
        -Force | Out-Null
}

function Get-ProtectionStatus([string]$Root) {
    $Acl = Get-Acl -LiteralPath $Root
    $AdministratorRules = @($Acl.Access | Where-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) -eq $AdministratorsSid -and
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
    })
    $AdministratorCanWrite = @($AdministratorRules | Where-Object {
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0 -or
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Delete) -ne 0 -or
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -ne 0
    }).Count -gt 0
    return [pscustomobject]@{
        protected = $Acl.AreAccessRulesProtected -and -not $AdministratorCanWrite
        installRoot = $Root
        owner = [string]$Acl.Owner
        administratorsCanWrite = $AdministratorCanWrite
        relockTask = [bool](Get-ScheduledTask -TaskName $RelockTaskName -ErrorAction SilentlyContinue)
    }
}

$Root = Get-ValidatedInstallRoot
if ($Mode -eq 'Status') {
    Get-ProtectionStatus $Root | ConvertTo-Json -Compress
    return
}
if (-not (Test-IsAdministrator)) {
    throw 'Changing SentryLoom tamper protection requires an elevated administrator process.'
}
if ($Mode -eq 'Disable' -and
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    throw 'Only the SentryLoom machine maintenance task can disable tamper protection.'
}

if ($Mode -eq 'Apply') {
    Set-TreeProtection $Root $true
    Unregister-ScheduledTask -TaskName $RelockTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host 'SentryLoom installation-directory tamper protection is active.' -ForegroundColor Green
    return
}

Set-TreeProtection $Root $false
Register-Relock $Root
Write-Host "SentryLoom file maintenance is authorized for $RelockAfterMinutes minute(s)." -ForegroundColor Yellow
