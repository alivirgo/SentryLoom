import path from "node:path";
import { runPowerShell } from "./windows-monitoring.js";

function jsonArray(output) {
  if (!output) return [];
  const parsed = JSON.parse(output);
  return Array.isArray(parsed) ? parsed : [parsed];
}

export function parseProcessSnapshot(output) {
  return jsonArray(output).map((item) => ({
    pid: Number(item.pid),
    parentPid: Number(item.parentPid) || 0,
    name: String(item.name || ""),
    executablePath: item.executablePath ? String(item.executablePath) : null,
    commandLine: item.commandLine ? String(item.commandLine).slice(0, 4096) : null,
    creationDate: item.creationDate ? String(item.creationDate) : null
  })).filter((item) => Number.isInteger(item.pid) && item.pid > 0);
}

export async function readProcessSnapshot() {
  if (process.platform !== "win32") return [];
  const command = [
    "Get-CimInstance Win32_Process -ErrorAction Stop |",
    "Select-Object @{n='pid';e={[int]$_.ProcessId}},@{n='parentPid';e={[int]$_.ParentProcessId}},",
    "@{n='name';e={[string]$_.Name}},@{n='executablePath';e={[string]$_.ExecutablePath}},",
    "@{n='commandLine';e={[string]$_.CommandLine}},@{n='creationDate';e={$_.CreationDate.ToUniversalTime().ToString('o')}} |",
    "ConvertTo-Json -Compress -Depth 3"
  ].join(" ");
  return parseProcessSnapshot(await runPowerShell(command, 30000));
}

export function parseTelemetryArray(output) {
  return jsonArray(output).filter((item) => item && typeof item === "object");
}

export async function readPersistenceSnapshot() {
  if (process.platform !== "win32") return [];
  const command = [
    "$items = [System.Collections.Generic.List[object]]::new();",
    "$runKeys = @(",
    "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',",
    "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',",
    "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
    ");",
    "foreach ($key in $runKeys) {",
    " if (Test-Path $key) { $props = Get-ItemProperty -LiteralPath $key;",
    "  foreach ($prop in $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }) {",
    "   $items.Add([pscustomobject]@{type='run-key';id=($key+'|'+$prop.Name);value=[string]$prop.Value})",
    "  }",
    " }",
    "}",
    "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -eq 'Auto' } | ForEach-Object {",
    " $items.Add([pscustomobject]@{type='service';id=[string]$_.Name;value=([string]$_.PathName+'|'+[string]$_.StartName)})",
    "};",
    "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {",
    " $actions = @($_.Actions | ForEach-Object { ([string]$_.Execute+' '+[string]$_.Arguments).Trim() }) -join ';';",
    " $items.Add([pscustomobject]@{type='scheduled-task';id=([string]$_.TaskPath+[string]$_.TaskName);value=$actions})",
    "};",
    "$startup = @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'));",
    "foreach ($folder in $startup) { if ($folder -and (Test-Path $folder)) {",
    " Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | ForEach-Object {",
    "  $items.Add([pscustomobject]@{type='startup-file';id=$_.FullName;value=($_.Length.ToString()+'|'+$_.LastWriteTimeUtc.ToString('o'))})",
    " }",
    "}}",
    "Get-CimInstance -Namespace root\\subscription -Class __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object {",
    " $items.Add([pscustomobject]@{type='wmi-consumer';id=[string]$_.__RELPATH;value=[string]$_.Name})",
    "};",
    "$items | Sort-Object type,id | ConvertTo-Json -Compress -Depth 4"
  ].join(" ");
  return parseTelemetryArray(await runPowerShell(command, 60000));
}

export async function readWindowsSecurityEvents(since) {
  if (process.platform !== "win32") return [];
  const logs = [
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Security"
  ];
  const safeSince = new Date(since).toISOString();
  const logList = logs.map((item) => `'${item.replaceAll("'", "''")}'`).join(",");
  const command = [
    `$since = [DateTime]::Parse('${safeSince}').ToLocalTime();`,
    `$logs = @(${logList});`,
    "$items = [System.Collections.Generic.List[object]]::new();",
    "foreach ($log in $logs) {",
    " try {",
    "  Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$since} -MaxEvents 100 -ErrorAction Stop |",
    "  Where-Object { $_.Level -le 3 -or $_.Id -in @(4103,4104,4688,4697,7045,1116,1117,5001,5007,3033,3077,106,140,141) } |",
    "  ForEach-Object {",
    "   $message = [string]$_.Message;",
    "   $ownCollector = $log -eq 'Microsoft-Windows-PowerShell/Operational' -and ($message -match 'Get-WinEvent -FilterHashtable|Get-CimInstance Win32_Process|Get-NetFirewall(Profile|Rule)|Get-ScheduledTask.+ConvertTo-Json|SentryLoom|AegisOfflineAV|__cmdletization|Export-ModuleMember -Function|loading the extended type data file|Author\\s*=\\s*\"PowerShell\"' -or ($message -match 'Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter' -and $message -match 'ROOT/StandardCimv2'));",
    "   if (-not $ownCollector) {",
    "    if ($message.Length -gt 2000) { $message = $message.Substring(0,2000) };",
    "    $items.Add([pscustomobject]@{log=$log;recordId=[long]$_.RecordId;eventId=[int]$_.Id;level=[int]$_.Level;at=$_.TimeCreated.ToUniversalTime().ToString('o');provider=[string]$_.ProviderName;message=$message})",
    "   }",
    "  }",
    " } catch {}",
    "}",
    "$items | Sort-Object at,log,recordId | ConvertTo-Json -Compress -Depth 3"
  ].join(" ");
  return parseTelemetryArray(await runPowerShell(command, 45000));
}

export async function discoverRemovableDrives() {
  if (process.platform !== "win32") return [];
  const command = [
    "[System.IO.DriveInfo]::GetDrives() |",
    "Where-Object { $_.DriveType -eq 'Removable' -and $_.IsReady } |",
    "Select-Object @{n='root';e={$_.RootDirectory.FullName}},@{n='label';e={$_.VolumeLabel}},",
    "@{n='format';e={$_.DriveFormat}},@{n='totalBytes';e={$_.TotalSize}},@{n='freeBytes';e={$_.AvailableFreeSpace}} |",
    "ConvertTo-Json -Compress -Depth 3"
  ].join(" ");
  return parseTelemetryArray(await runPowerShell(command, 20000)).map((drive) => ({
    root: path.parse(String(drive.root)).root,
    label: String(drive.label || ""),
    format: String(drive.format || ""),
    totalBytes: Number(drive.totalBytes) || 0,
    freeBytes: Number(drive.freeBytes) || 0
  })).filter((drive) => drive.root);
}

export async function readFirewallSnapshot() {
  if (process.platform !== "win32") return { profiles: [], inboundAllows: [] };
  const command = [
    "$profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction);",
    "$rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop |",
    " Select-Object Name,DisplayName,Profile,PolicyStoreSourceType);",
    "[pscustomobject]@{profiles=$profiles;inboundAllows=$rules} | ConvertTo-Json -Compress -Depth 5"
  ].join(" ");
  const parsed = JSON.parse(await runPowerShell(command, 60000));
  return {
    profiles: Array.isArray(parsed.profiles) ? parsed.profiles : parsed.profiles ? [parsed.profiles] : [],
    inboundAllows: Array.isArray(parsed.inboundAllows) ? parsed.inboundAllows : parsed.inboundAllows ? [parsed.inboundAllows] : []
  };
}

export async function readAuthenticodeStatus(file) {
  if (process.platform !== "win32" || !file) return { status: "Unsupported", signer: null };
  const literal = String(file).replaceAll("'", "''");
  const command = [
    `$signature = Get-AuthenticodeSignature -LiteralPath '${literal}' -ErrorAction SilentlyContinue;`,
    "if ($signature) { [pscustomobject]@{status=[string]$signature.Status;signer=[string]$signature.SignerCertificate.Subject} | ConvertTo-Json -Compress }"
  ].join(" ");
  const output = await runPowerShell(command, 15000);
  return output ? JSON.parse(output) : { status: "UnknownError", signer: null };
}
