import fs from "node:fs/promises";
import syncFs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { appPaths } from "../constants.js";
import { DNS_PROFILES, getDnsProfile } from "./dns-profiles.js";
import { fileExists, writeJsonAtomic } from "./fs-safe.js";
import { isProcessElevated, runPowerShell } from "./windows-monitoring.js";

function powershellPath() {
  if (process.platform !== "win32") return "pwsh";
  const modern = path.join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
  return syncFs.existsSync(modern)
    ? modern
    : path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

function runFile(file, args, timeout = 120000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {
      windowsHide: true,
      timeout,
      maxBuffer: 4 * 1024 * 1024
    }, (error, stdout, stderr) => {
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

export function parseAdapterJson(output) {
  if (!output) return [];
  const parsed = JSON.parse(output);
  return (Array.isArray(parsed) ? parsed : [parsed]).map((adapter) => ({
    interfaceIndex: Number(adapter.interfaceIndex),
    alias: String(adapter.alias || ""),
    description: String(adapter.description || ""),
    dnsServers: (Array.isArray(adapter.dnsServers) ? adapter.dnsServers : [adapter.dnsServers])
      .filter((value) => typeof value === "string" && value),
    automatic: Boolean(adapter.automatic)
  })).filter((adapter) => Number.isInteger(adapter.interfaceIndex) && adapter.interfaceIndex > 0);
}

export async function listDnsAdapters() {
  if (process.platform !== "win32") return [];
  const command = [
    "$items = @(Get-NetIPConfiguration -ErrorAction Stop |",
    "Where-Object { $_.NetAdapter.Status -eq 'Up' -and ($_.IPv4DefaultGateway -or $_.IPv6DefaultGateway) } |",
    "ForEach-Object {",
    "  $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction Stop;",
    "  $key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{' + $adapter.InterfaceGuid.ToString() + '}';",
    "  $static = (Get-ItemProperty -LiteralPath $key -Name NameServer -ErrorAction SilentlyContinue).NameServer;",
    "  [pscustomobject]@{",
    "    interfaceIndex = [int]$_.InterfaceIndex;",
    "    alias = [string]$_.InterfaceAlias;",
    "    description = [string]$_.InterfaceDescription;",
    "    dnsServers = @($_.DNSServer.ServerAddresses);",
    "    automatic = [string]::IsNullOrWhiteSpace([string]$static)",
    "  }",
    "});",
    "$items | ConvertTo-Json -Compress -Depth 4"
  ].join(" ");
  return parseAdapterJson(await runPowerShell(command, 30000));
}

async function runDnsHelper(action, profileId) {
  const script = fileURLToPath(new URL("../../Set-SentryLoomDns.ps1", import.meta.url));
  const args = [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    script,
    "-Action",
    action,
    "-BackupPath",
    appPaths().dnsBackup
  ];
  if (profileId) args.push("-Profile", profileId);

  if (await isProcessElevated()) {
    return runFile(powershellPath(), args);
  }

  const argumentLine = args.map(windowsArgument).join(" ");
  const command = [
    `$process = Start-Process -FilePath ${psLiteral(powershellPath())}`,
    `-ArgumentList ${psLiteral(argumentLine)}`,
    "-Verb RunAs -Wait -PassThru -WindowStyle Hidden;",
    "if ($process.ExitCode -ne 0) { throw \"Elevated DNS helper failed with exit code $($process.ExitCode).\" }"
  ].join(" ");
  return runPowerShell(command, 180000);
}

function matchingProfile(adapters) {
  if (!adapters.length) return null;
  return DNS_PROFILES.find((profile) => {
    const expected = new Set([...profile.ipv4, ...profile.ipv6].map((item) => item.toLowerCase()));
    return adapters.every((adapter) => {
      const actual = new Set(adapter.dnsServers.map((item) => item.toLowerCase()));
      return expected.size === actual.size && [...expected].every((item) => actual.has(item));
    });
  })?.id || null;
}

export async function dnsFilteringStatus(config) {
  const adapters = await listDnsAdapters();
  const detectedProfile = matchingProfile(adapters);
  return {
    supported: process.platform === "win32",
    elevated: await isProcessElevated(),
    selectedProfile: config.dnsFiltering.selectedProfile,
    configuredProfile: config.dnsFiltering.lastAppliedProfile,
    detectedProfile,
    inSync: config.dnsFiltering.lastAppliedProfile === null
      ? detectedProfile === null
      : detectedProfile === config.dnsFiltering.lastAppliedProfile,
    lastAppliedAt: config.dnsFiltering.lastAppliedAt,
    backupAvailable: await fileExists(appPaths().dnsBackup),
    adapters,
    profiles: DNS_PROFILES
  };
}

export async function applyDnsProfile(profileId, options = {}) {
  const profile = getDnsProfile(profileId);
  if (!profile) throw new Error("Unsupported DNS filtering profile");
  const adapters = await listDnsAdapters();
  if (!adapters.length) throw new Error("No active routed Windows network adapter was found");
  if (!options.preserveBackup || !await fileExists(appPaths().dnsBackup)) {
    await writeJsonAtomic(appPaths().dnsBackup, {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      adapters
    });
  }
  await runDnsHelper("Apply", profile.id);
  return { profile, adapters };
}

export async function restoreDnsConfiguration() {
  if (!await fileExists(appPaths().dnsBackup)) {
    throw new Error("No saved DNS configuration is available to restore");
  }
  await runDnsHelper("Restore");
  await fs.rm(appPaths().dnsBackup, { force: true });
}
