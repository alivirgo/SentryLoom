import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";

function run(command, args, timeout = 10000) {
  return new Promise((resolve) => {
    execFile(command, args, {
      windowsHide: true,
      timeout,
      maxBuffer: 4 * 1024 * 1024,
      encoding: "utf8"
    }, (error, stdout) => resolve(error ? "" : stdout.trim()));
  });
}

export function parseDfOutput(output) {
  return String(output || "").split(/\r?\n/).slice(1).map((line) => {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6) return null;
    const [filesystem, blocks, used, available, capacity, ...mountParts] = fields;
    return {
      filesystem: filesystem.slice(0, 300),
      mount: mountParts.join(" ").slice(0, 500),
      totalBytes: Number(blocks) * 1024,
      usedBytes: Number(used) * 1024,
      availableBytes: Number(available) * 1024,
      capacity
    };
  }).filter((item) =>
    item && Number.isFinite(item.totalBytes) && !/^(?:tmpfs|devtmpfs|overlay|map|udev)$/i.test(item.filesystem)
  ).slice(0, 100);
}

async function unixDisks() {
  const output = await run("df", ["-Pk"]);
  return parseDfOutput(output);
}

async function windowsDisks() {
  const script = [
    "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\"",
    "| Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace",
    "| ConvertTo-Json -Compress"
  ].join(" ");
  const shell = path.join(
    process.env.SystemRoot || "C:\\Windows",
    "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
  );
  const output = await run(shell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
  if (!output) return [];
  try {
    const parsed = JSON.parse(output);
    return (Array.isArray(parsed) ? parsed : [parsed]).map((disk) => ({
      filesystem: disk.FileSystem || null,
      mount: disk.DeviceID || null,
      label: disk.VolumeName || null,
      totalBytes: Number(disk.Size) || 0,
      usedBytes: Math.max(0, Number(disk.Size) - Number(disk.FreeSpace)),
      availableBytes: Number(disk.FreeSpace) || 0
    }));
  } catch {
    return [];
  }
}

async function osDescription() {
  if (process.platform === "linux") {
    try {
      const content = await fs.readFile("/etc/os-release", "utf8");
      const values = Object.fromEntries(content.split(/\r?\n/).map((line) => {
        const separator = line.indexOf("=");
        if (separator < 1) return null;
        return [
          line.slice(0, separator),
          line.slice(separator + 1).replace(/^"|"$/g, "").replaceAll("\\n", " ")
        ];
      }).filter(Boolean));
      return values.PRETTY_NAME || values.NAME || `${os.type()} ${os.release()}`;
    } catch {}
  }
  if (process.platform === "darwin") {
    const version = await run("sw_vers", ["-productVersion"]);
    return version ? `macOS ${version}` : `${os.type()} ${os.release()}`;
  }
  return `${os.type()} ${os.release()}`;
}

export async function collectSystemInformation() {
  const cpus = os.cpus();
  const totalMemoryBytes = os.totalmem();
  const freeMemoryBytes = os.freemem();
  const interfaces = os.networkInterfaces();
  return {
    collectedAt: new Date().toISOString(),
    operatingSystem: {
      description: await osDescription(),
      platform: os.platform(),
      release: os.release(),
      version: typeof os.version === "function" ? os.version() : null,
      architecture: os.arch(),
      hostname: os.hostname(),
      endianness: os.endianness()
    },
    hardware: {
      cpuModel: cpus[0]?.model?.trim() || null,
      logicalProcessors: cpus.length,
      cpuSpeedMhz: cpus[0]?.speed || null,
      totalMemoryBytes,
      freeMemoryBytes,
      usedMemoryBytes: Math.max(0, totalMemoryBytes - freeMemoryBytes)
    },
    runtime: {
      systemUptimeSeconds: Math.floor(os.uptime()),
      bootedAt: new Date(Date.now() - os.uptime() * 1000).toISOString(),
      loadAverage: os.loadavg().map((value) => Number(value.toFixed(2))),
      nodeVersion: process.version,
      processArchitecture: process.arch,
      processId: process.pid,
      user: (() => {
        try {
          const user = os.userInfo();
          return { username: user.username, uid: user.uid, gid: user.gid, shell: user.shell || null };
        } catch {
          return null;
        }
      })()
    },
    storage: process.platform === "win32" ? await windowsDisks() : await unixDisks(),
    network: {
      interfaceCount: Object.keys(interfaces).length,
      addresses: Object.entries(interfaces).flatMap(([name, records]) =>
        (records || []).filter((record) => !record.internal).map((record) => ({
          name,
          family: record.family,
          address: record.address,
          netmask: record.netmask,
          cidr: record.cidr || null,
          mac: record.mac || null
        }))
      ).slice(0, 100)
    }
  };
}
