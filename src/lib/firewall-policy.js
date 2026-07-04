import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isIP } from "node:net";
import { appendAudit } from "./audit-log.js";
import { isProcessElevated, runPowerShell } from "./windows-monitoring.js";

const GROUP = "SentryLoom - Threat Intelligence";

function psLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

export async function blockThreatIp(address, matches = []) {
  if (!isIP(address)) throw new Error("Only validated IP addresses can be blocked");
  if (!await isProcessElevated()) {
    return { blocked: false, reason: "administrator access required" };
  }
  const hash = crypto.createHash("sha256").update(address).digest("hex").slice(0, 20);
  const name = `SentryLoom-IOC-${hash}`;
  const description = `SentryLoom threat-intelligence block for ${address}`.slice(0, 250);
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
