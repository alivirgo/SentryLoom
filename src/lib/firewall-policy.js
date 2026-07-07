import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isIP } from "node:net";
import { appendAudit } from "./audit-log.js";
import { isProcessElevated, runPowerShell } from "./windows-monitoring.js";
import { execFile } from "node:child_process";

const GROUP = "SentryLoom - Threat Intelligence";

function psLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function run(command, args, timeout = 30000) {
  return new Promise((resolve, reject) => {
    execFile(command, args, {
      windowsHide: true,
      timeout,
      maxBuffer: 8 * 1024 * 1024,
      encoding: "utf8"
    }, (error, stdout, stderr) => {
      if (error) reject(new Error(String(stderr || "").trim() || error.message, { cause: error }));
      else resolve(String(stdout || "").trim());
    });
  });
}

async function ensureLinuxTable() {
  await run("nft", ["add", "table", "inet", "sentryloom"]).catch((error) => {
    if (!/file exists/i.test(error.message)) throw error;
  });
  await run("nft", [
    "add", "chain", "inet", "sentryloom", "output",
    "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"
  ]).catch((error) => {
    if (!/file exists/i.test(error.message)) throw error;
  });
}

export async function blockThreatIp(address, matches = []) {
  if (!isIP(address)) throw new Error("Only validated IP addresses can be blocked");
  if (!await isProcessElevated()) {
    return { blocked: false, reason: "administrator access required" };
  }
  const hash = crypto.createHash("sha256").update(address).digest("hex").slice(0, 20);
  const name = `SentryLoom-IOC-${hash}`;
  const description = `SentryLoom threat-intelligence block for ${address}`.slice(0, 250);
  if (process.platform === "linux") {
    await ensureLinuxTable();
    await run("nft", [
      "add", "rule", "inet", "sentryloom", "output",
      isIP(address) === 6 ? "ip6" : "ip", "daddr", address,
      "counter", "drop", "comment", name
    ]).catch((error) => {
      if (!/file exists/i.test(error.message)) throw error;
    });
    await appendAudit("firewall.ioc-blocked", {
      address,
      rule: name,
      sources: [...new Set(matches.map((match) => match.source))]
    });
    return { blocked: true, address, rule: name };
  }
  if (process.platform !== "win32") {
    return { blocked: false, reason: "automatic IOC blocking is not supported on this platform" };
  }
  const command = [
    `$existing = Get-NetFirewallRule -Name ${psLiteral(name)} -ErrorAction SilentlyContinue;`,
    "if (-not $existing) {",
    ` New-NetFirewallRule -Name ${psLiteral(name)} -DisplayName ${psLiteral(`SentryLoom blocked ${address}`)}`,
    ` -Description ${psLiteral(description)} -Group ${psLiteral(GROUP)} -Direction Outbound -Action Block`,
    ` -RemoteAddress ${psLiteral(address)} -Profile Any -Enabled True | Out-Null`,
    "}"
  ].join(" ");
  await runPowerShell(command, 30000);
  await appendAudit("firewall.ioc-blocked", {
    address,
    rule: name,
    sources: [...new Set(matches.map((match) => match.source))]
  });
  return { blocked: true, address, rule: name };
}

export async function firewallPolicyStatus() {
  if (process.platform === "linux") {
    const output = await run("nft", ["-j", "list", "table", "inet", "sentryloom"]).catch(() => "");
    if (!output) return { supported: true, blockedAddresses: 0, rules: [], implementation: "nftables" };
    try {
      const rules = (JSON.parse(output).nftables || [])
        .filter((item) => item.rule)
        .map((item) => item.rule)
        .filter((rule) => String(rule.comment || "").startsWith("SentryLoom-IOC-"));
      return { supported: true, blockedAddresses: rules.length, rules, implementation: "nftables" };
    } catch {
      return { supported: true, blockedAddresses: 0, rules: [], implementation: "nftables" };
    }
  }
  if (process.platform !== "win32") return { supported: false, blockedAddresses: 0, rules: [] };
  const command = [
    `$rules = @(Get-NetFirewallRule -Group ${psLiteral(GROUP)} -ErrorAction SilentlyContinue);`,
    "$items = @($rules | ForEach-Object {",
    " $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue;",
    " [pscustomobject]@{name=$_.Name;enabled=[string]$_.Enabled;remoteAddress=@($filter.RemoteAddress)}",
    "});",
    "if ($items.Count -eq 0) { '[]' } else { $items | ConvertTo-Json -Compress -Depth 3 }"
  ].join(" ");
  const output = await runPowerShell(command, 30000);
  const parsed = output ? JSON.parse(output) : [];
  const rules = (Array.isArray(parsed) ? parsed : [parsed]).filter(Boolean);
  return { supported: true, blockedAddresses: rules.length, rules };
}

export async function clearThreatFirewallRules() {
  if (process.platform === "linux") {
    if (!await isProcessElevated()) throw new Error("administrator access is required");
    await run("nft", ["delete", "table", "inet", "sentryloom"]).catch((error) => {
      if (!/no such file|not found/i.test(error.message)) throw error;
    });
    await appendAudit("firewall.ioc-rules-cleared");
    return firewallPolicyStatus();
  }
  if (process.platform !== "win32") {
    throw new Error("SentryLoom firewall IOC rules are not supported on this platform");
  }
  const removal = `$rules = @(Get-NetFirewallRule -Group ${psLiteral(GROUP)} -ErrorAction SilentlyContinue); if ($rules.Count) { $rules | Remove-NetFirewallRule -ErrorAction Stop }`;
  if (await isProcessElevated()) {
    await runPowerShell(removal, 30000);
  } else {
    const encoded = Buffer.from(removal, "utf16le").toString("base64");
    const modern = path.join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
    const executable = fs.existsSync(modern)
      ? modern
      : `${process.env.SystemRoot || "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
    const command = [
      `$process = Start-Process -FilePath ${psLiteral(executable)}`,
      `-ArgumentList ${psLiteral(`-NoLogo -NoProfile -NonInteractive -EncodedCommand ${encoded}`)}`,
      "-Verb RunAs -Wait -PassThru -WindowStyle Hidden;",
      "if ($process.ExitCode -ne 0) { throw \"Elevated firewall cleanup failed with exit code $($process.ExitCode).\" }"
    ].join(" ");
    await runPowerShell(command, 180000);
  }
  await appendAudit("firewall.ioc-rules-cleared");
  return firewallPolicyStatus();
}
