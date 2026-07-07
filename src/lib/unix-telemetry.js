import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";

function run(command, args, timeout = 15000) {
  return new Promise((resolve) => {
    execFile(command, args, {
      windowsHide: true,
      timeout,
      maxBuffer: 16 * 1024 * 1024,
      encoding: "utf8"
    }, (error, stdout) => resolve(error ? "" : stdout.trim()));
  });
}

function runResult(command, args, timeout = 15000) {
  return new Promise((resolve) => {
    execFile(command, args, {
      windowsHide: true,
      timeout,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8"
    }, (error, stdout, stderr) => resolve({
      ok: !error,
      stdout: String(stdout || "").trim(),
      stderr: String(stderr || "").trim()
    }));
  });
}

function cleanText(value, maximum = 4096) {
  return String(value || "").replaceAll("\0", "").trim().slice(0, maximum);
}

export function parsePsOutput(output) {
  const records = [];
  for (const line of String(output || "").split(/\r?\n/)) {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$/);
    if (!match) continue;
    const [, pid, parentPid, started, executablePath, commandLine] = match;
    records.push({
      pid: Number(pid),
      parentPid: Number(parentPid),
      name: path.basename(executablePath),
      executablePath: executablePath.startsWith("/") ? cleanText(executablePath, 32767) : null,
      commandLine: cleanText(commandLine, 32767),
      creationDate: started
    });
  }
  return records.slice(0, 10000);
}

export async function readProcessSnapshot() {
  const output = await run("ps", ["-axo", "pid=,ppid=,lstart=,comm=,args="]);
  // lstart contains five fields; normalize it before applying the compact parser.
  const normalized = output.split(/\r?\n/).map((line) => {
    const match = line.match(
      /^\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\s+(\S+)\s+(.*)$/
    );
    return match ? `${match[1]} ${match[2]} ${Date.parse(match[3]) || match[3]} ${match[4]} ${match[5]}` : line;
  }).join("\n");
  return parsePsOutput(normalized);
}

async function readDesktopAutostart() {
  const roots = [
    "/etc/xdg/autostart",
    path.join(os.homedir(), ".config", "autostart")
  ];
  const records = [];
  for (const root of roots) {
    let entries = [];
    try { entries = await fs.readdir(root, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".desktop")) continue;
      const file = path.join(root, entry.name);
      let content = "";
      try { content = await fs.readFile(file, "utf8"); } catch { continue; }
      const command = content.match(/^Exec=(.+)$/m)?.[1] || "";
      records.push({ type: "desktop-autostart", id: file, value: cleanText(command) });
    }
  }
  return records;
}

async function linuxPersistence() {
  const records = await readDesktopAutostart();
  const output = await run("systemctl", [
    "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"
  ]);
  for (const line of output.split(/\r?\n/)) {
    const [unit, state] = line.trim().split(/\s+/);
    if (!unit?.endsWith(".service")) continue;
    records.push({ type: "systemd-service", id: unit, value: state || "enabled" });
  }
  return records.slice(0, 5000);
}

async function macPersistence() {
  const roots = [
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    path.join(os.homedir(), "Library", "LaunchAgents")
  ];
  const records = [];
  for (const root of roots) {
    let entries = [];
    try { entries = await fs.readdir(root, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.endsWith(".plist")) continue;
      const file = path.join(root, entry.name);
      const details = await run("plutil", ["-convert", "json", "-o", "-", file]);
      let value = file;
      try {
        const plist = JSON.parse(details);
        value = plist.Program || plist.ProgramArguments || plist.Label || file;
      } catch {}
      records.push({ type: "launchd-item", id: file, value });
    }
  }
  return records.slice(0, 5000);
}

export async function readPersistenceSnapshot() {
  return process.platform === "darwin" ? macPersistence() : linuxPersistence();
}

export async function readSecurityEvents(since) {
  if (process.platform === "linux") {
    const output = await run("journalctl", [
      "--since", since || "-1 minute",
      "--priority", "warning",
      "--output", "json",
      "--no-pager",
      "--lines", "250"
    ]);
    return output.split(/\r?\n/).map((line) => {
      try {
        const record = JSON.parse(line);
        return {
          log: "systemd-journal",
          recordId: record.__CURSOR || `${record.__REALTIME_TIMESTAMP}:${record._PID || 0}`,
          eventId: record.SYSLOG_IDENTIFIER || record._SYSTEMD_UNIT || "journal",
          level: Number(record.PRIORITY),
          provider: record._SYSTEMD_UNIT || record.SYSLOG_IDENTIFIER || "system",
          message: cleanText(record.MESSAGE, 8192),
          at: record.__REALTIME_TIMESTAMP
            ? new Date(Number(record.__REALTIME_TIMESTAMP) / 1000).toISOString()
            : new Date().toISOString()
        };
      } catch {
        return null;
      }
    }).filter(Boolean);
  }
  const start = since || new Date(Date.now() - 60000).toISOString();
  const output = await run("log", [
    "show", "--style", "json", "--start", start,
    "--predicate", "messageType == error OR messageType == fault"
  ]);
  try {
    const records = JSON.parse(output);
    return records.slice(-250).map((record, index) => ({
      log: "macos-unified-log",
      recordId: record.traceID || `${record.timestamp}:${index}`,
      eventId: record.category || "unified-log",
      level: record.messageType === "Fault" ? 1 : 2,
      provider: record.subsystem || record.processImagePath || "system",
      message: cleanText(record.eventMessage, 8192),
      at: record.timestamp || new Date().toISOString()
    }));
  } catch {
    return [];
  }
}

export async function readExecutableTrust(file) {
  if (!file) return { status: "Unknown", signer: null };
  if (process.platform === "darwin") {
    const result = await runResult("codesign", ["--verify", "--deep", "--strict", "--verbose=2", file]);
    const details = result.ok ? await runResult("codesign", ["-dvv", file]) : result;
    const signer = `${details.stdout}\n${details.stderr}`.match(/Authority=(.+)/)?.[1] || null;
    return { status: result.ok ? "Valid" : "NotSigned", signer };
  }
  const owner = await run("dpkg-query", ["-S", file]);
  return {
    status: owner ? "PackageManaged" : "Unmanaged",
    signer: owner ? owner.split(":")[0] : null
  };
}

export function parseLsblkJson(output) {
  try {
    const parsed = JSON.parse(output);
    return (parsed.blockdevices || []).flatMap(function visit(device) {
      const current = device.rm && device.mountpoint
        ? [{
          root: String(device.mountpoint),
          label: device.label || device.name || null,
          fileSystem: device.fstype || null,
          size: Number(device.size) || null
        }]
        : [];
      return current.concat((device.children || []).flatMap(visit));
    });
  } catch {
    return [];
  }
}

export async function discoverRemovableDrives() {
  if (process.platform === "linux") {
    return parseLsblkJson(await run("lsblk", [
      "--json", "--bytes", "--output", "NAME,RM,MOUNTPOINT,LABEL,FSTYPE,SIZE"
    ]));
  }
  const output = await run("mount", []);
  return output.split(/\r?\n/).map((line) => {
    const match = line.match(/^(.+?) on (\/Volumes\/.+?) \((.+)\)$/);
    return match ? {
      root: match[2],
      label: path.basename(match[2]),
      fileSystem: match[3].split(",")[0],
      size: null
    } : null;
  }).filter(Boolean);
}

export async function readFirewallSnapshot() {
  if (process.platform === "darwin") {
    const [applicationFirewall, packetFilter] = await Promise.all([
      run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"]),
      run("pfctl", ["-s", "info"])
    ]);
    return {
      profiles: [{
        Name: "macOS application firewall",
        Enabled: /enabled/i.test(applicationFirewall),
        DefaultInboundAction: "Block",
        DefaultOutboundAction: "Allow"
      }],
      inboundAllows: [],
      platformDetails: { applicationFirewall, packetFilter: cleanText(packetFilter, 2048) }
    };
  }
  const [ufw, nftables] = await Promise.all([
    run("ufw", ["status"]),
    run("nft", ["list", "ruleset"])
  ]);
  return {
    profiles: [{
      Name: "Linux host firewall",
      Enabled: /status:\s*active/i.test(ufw) || Boolean(nftables),
      DefaultInboundAction: /default:\s*deny\s*\(incoming\)/i.test(ufw) ? "Block" : "Unknown",
      DefaultOutboundAction: /allow\s*\(outgoing\)/i.test(ufw) ? "Allow" : "Unknown"
    }],
    inboundAllows: ufw.split(/\r?\n/).filter((line) => /\bALLOW\b.*\bIN\b/i.test(line))
      .slice(0, 500).map((line, index) => ({ Name: `ufw-${index}`, Rule: cleanText(line) })),
    platformDetails: { ufw: cleanText(ufw, 4096), nftablesPresent: Boolean(nftables) }
  };
}
