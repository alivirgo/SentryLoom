import path from "node:path";
import fs from "node:fs";
import { execFile } from "node:child_process";

function powershellPath() {
  if (process.platform !== "win32") return "pwsh";
  const modern = path.join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
  return fs.existsSync(modern)
    ? modern
    : path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

export function runPowerShell(command, timeout = 15000) {
  return new Promise((resolve, reject) => {
    execFile(powershellPath(), ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command], {
      windowsHide: true,
      timeout,
      maxBuffer: 4 * 1024 * 1024
    }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr.trim() || error.message, { cause: error }));
      else resolve(stdout.trim());
    });
  });
}

export function parsePowerShellStringArray(output) {
  if (!output) return [];
  const parsed = JSON.parse(output);
  return (Array.isArray(parsed) ? parsed : [parsed])
    .filter((value) => typeof value === "string" && value)
    .map((value) => path.parse(value).root || value);
}

export async function discoverFixedDrives() {
  if (process.platform !== "win32") return [path.parse(process.cwd()).root];
  try {
    const output = await runPowerShell(
      "[System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName } | ConvertTo-Json -Compress"
    );
    const drives = [...new Set(parsePowerShellStringArray(output))];
    return drives.length ? drives : [process.env.SystemDrive ? `${process.env.SystemDrive}\\` : "C:\\"];
  } catch {
    return [process.env.SystemDrive ? `${process.env.SystemDrive}\\` : "C:\\"];
  }
}

export async function isProcessElevated() {
  if (process.platform !== "win32") return typeof process.getuid === "function" ? process.getuid() === 0 : false;
  try {
    const output = await runPowerShell(
      "$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    );
    return output.trim().toLowerCase() === "true";
  } catch {
    return false;
  }
}

export async function readDnsCacheEntries() {
  if (process.platform !== "win32") return [];
  const output = await runPowerShell(
    "Get-DnsClientCache -ErrorAction Stop | Select-Object -ExpandProperty Entry | Sort-Object -Unique | ConvertTo-Json -Compress",
    20000
  );
  if (!output) return [];
  const parsed = JSON.parse(output);
  return (Array.isArray(parsed) ? parsed : [parsed])
    .filter((entry) => typeof entry === "string" && entry)
    .map((entry) => entry.toLowerCase().replace(/\.$/, ""));
}
