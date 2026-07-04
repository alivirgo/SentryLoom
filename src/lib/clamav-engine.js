import fs from "node:fs/promises";
import path from "node:path";
import { execFile, spawn } from "node:child_process";
import { appPaths } from "../constants.js";
import { findClamExecutable } from "./threat-feeds.js";
import { fileExists } from "./fs-safe.js";

export async function clamAvEngineStatus() {
  const executable = await findClamExecutable("clamscan");
  const paths = appPaths();
  const main = path.join(paths.threatArtifacts, "main.cvd");
  const daily = path.join(paths.threatArtifacts, "daily.cvd");
  const databasesReady = await fileExists(main) && await fileExists(daily);
  let databaseVersion = null;
  let signatureCount = 0;
  if (databasesReady) {
    for (const file of [main, daily]) {
      try {
        const handle = await fs.open(file, "r");
        const header = Buffer.alloc(512);
        try { await handle.read(header, 0, 512, 0); } finally { await handle.close(); }
        const fields = header.toString("ascii").replace(/\0.*$/s, "").trim().split(":");
        if (fields[0] === "ClamAV-VDB") {
          signatureCount += Number(fields[3]) || 0;
          if (file === daily) databaseVersion = fields[2];
        }
      } catch {}
    }
  }
  return {
    installed: Boolean(executable),
    executable,
    databasesReady,
    databaseDirectory: paths.threatArtifacts,
    databaseVersion,
    signatureCount
  };
}

export async function scanWithClamAv(target, options = {}) {
  const status = options.status || await clamAvEngineStatus();
  if (!status.installed || !status.databasesReady || options.enabled === false) {
    return { available: false, detections: [], errors: [] };
  }
  const maxMb = Math.max(1, Math.ceil(options.maxFileBytes / 1024 / 1024));
  const args = [
    `--database=${status.databaseDirectory}`,
    "--infected",
    "--no-summary",
    "--stdout",
    "--recursive=yes",
    `--max-filesize=${maxMb}M`,
    `--max-scansize=${Math.max(maxMb * 2, 256)}M`,
    "--max-recursion=30",
    path.resolve(target)
  ];
  return new Promise((resolve, reject) => {
    const spawnImpl = options.spawnImpl || spawn;
    const child = spawnImpl(status.executable, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const timeoutMs = Math.max(10, Number(options.timeoutMs) || 30 * 60 * 1000);
    let output = "";
    let errors = "";
    let settled = false;
    let timedOut = false;
    const terminate = options.terminateImpl || ((processToStop) => {
      try { processToStop.kill("SIGKILL"); } catch {}
      if (process.platform === "win32" && processToStop.pid) {
        const executable = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "taskkill.exe");
        execFile(executable, ["/PID", String(processToStop.pid), "/T", "/F"], { windowsHide: true }, () => {});
      }
    });
    const abort = () => terminate(child);
    options.signal?.addEventListener("abort", abort, { once: true });
    options.onProgress?.({ engine: "clamav", current: target, phase: "clamav" });
    const timer = setTimeout(() => {
      timedOut = true;
      terminate(child);
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      output = `${output}${chunk}`.slice(-16 * 1024 * 1024);
      options.onProgress?.({ engine: "clamav", current: target, phase: "clamav" });
    });
    child.stderr.on("data", (chunk) => { errors = `${errors}${chunk}`.slice(-1024 * 1024); });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      reject(error);
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
      if (options.signal?.aborted) {
        reject(new Error("Scan cancelled"));
        return;
      }
      const detections = [];
      for (const line of output.split(/\r?\n/)) {
        const match = line.match(/^(.*): ([^:]+) FOUND$/);
        if (!match) continue;
        detections.push({ path: match[1], name: match[2] });
      }
      if (timedOut) {
        resolve({
          available: true,
          detections,
          errors: [{ path: target, error: `ClamAV verification timed out after ${Math.round(timeoutMs / 1000)} seconds` }]
        });
        return;
      }
      if (code === 0 || code === 1) {
        resolve({ available: true, detections, errors: errors ? [{ path: target, error: errors.trim() }] : [] });
      } else {
        resolve({
          available: true,
          detections,
          errors: [{ path: target, error: `ClamAV exited with code ${code}: ${errors.trim() || output.trim()}` }]
        });
      }
    });
  });
}

export async function mergeClamAvDetections(results, detections) {
  const byPath = new Map(results.map((item) => [path.resolve(item.path).toLowerCase(), item]));
  for (const detection of detections) {
    const normalized = path.resolve(detection.path).toLowerCase();
    let result = byPath.get(normalized);
    if (!result) {
      let stat = null;
      try { stat = await fs.stat(detection.path); } catch {}
      result = {
        path: detection.path,
        size: stat?.size ?? null,
        modifiedAt: stat?.mtime?.toISOString() ?? null,
        status: "detected",
        findings: [],
        virtual: !stat?.isFile()
      };
      results.push(result);
      byPath.set(normalized, result);
    }
    result.status = "detected";
    if (!result.findings.some((finding) => finding.id === `clamav:${detection.name}`)) {
      result.findings.push({
        id: `clamav:${detection.name}`,
        name: detection.name,
        severity: "critical",
        confirmed: true,
        category: "clamav-engine",
        evidence: detection.name,
        source: "clamav"
      });
    }
  }
}
