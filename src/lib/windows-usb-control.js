import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { appPaths } from "../constants.js";
import { fileExists } from "./fs-safe.js";
import { isProcessElevated, runPowerShell } from "./windows-monitoring.js";

function powershellPath() {
  if (process.platform !== "win32") return "pwsh";
  const modern = path.join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
  return fs.existsSync(modern)
    ? modern
    : path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

function runFile(file, args, timeout = 120000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr.trim() || stdout.trim() || error.message, { cause: error }));
      else resolve(stdout.trim());
    });
  });
}

function psLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function windowsArgument(value) {
  const text = String(value);
  return `"${text.replaceAll(/(\\*)"/g, "$1$1\\\"").replaceAll(/\\+$/g, "$&$&")}"`;
}

export function parseUsbPolicyStatus(output) {
  if (!output) return { blocked: false, configured: false };
  const parsed = JSON.parse(output);
  return {
    blocked: Number(parsed.value) === 1,
    configured: Boolean(parsed.configured)
  };
}

export async function usbStorageStatus() {
  if (process.platform !== "win32") {
    return { supported: false, blocked: false, configured: false, backupAvailable: false };
  }
  const command = [
    "$path = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices';",
    "$item = Get-ItemProperty -LiteralPath $path -Name Deny_All -ErrorAction SilentlyContinue;",
    "[pscustomobject]@{ configured = $null -ne $item; value = if ($null -ne $item) { [int]$item.Deny_All } else { 0 } } | ConvertTo-Json -Compress"
  ].join(" ");
  return {
    supported: true,
    ...parseUsbPolicyStatus(await runPowerShell(command, 15000)),
    backupAvailable: await fileExists(appPaths().usbPolicyBackup)
  };
}

async function runUsbHelper(action) {
  const script = fileURLToPath(new URL("../../Set-SentryLoomUsbStorage.ps1", import.meta.url));
  const args = [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Action", action, "-BackupPath", appPaths().usbPolicyBackup
  ];
  if (await isProcessElevated()) return runFile(powershellPath(), args);
  const argumentLine = args.map(windowsArgument).join(" ");
  const command = [
    `$process = Start-Process -FilePath ${psLiteral(powershellPath())}`,
    `-ArgumentList ${psLiteral(argumentLine)}`,
    "-Verb RunAs -Wait -PassThru -WindowStyle Hidden;",
    "if ($process.ExitCode -ne 0) { throw \"Elevated USB policy helper failed with exit code $($process.ExitCode).\" }"
  ].join(" ");
  return runPowerShell(command, 180000);
}

export async function setUsbStorageBlocked(blocked) {
  if (process.platform !== "win32") throw new Error("USB storage control is available only on Windows");
  await runUsbHelper(blocked ? "Apply" : "Restore");
  return usbStorageStatus();
}
