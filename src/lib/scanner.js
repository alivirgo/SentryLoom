import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { compileSignatures, loadSignatures } from "./signature-store.js";
import { matchesExclusion } from "./fs-safe.js";
import { openThreatIndex } from "./threat-index.js";
import { scanWithClamAv, mergeClamAvDetections } from "./clamav-engine.js";

const EXECUTABLE_EXTENSIONS = new Set([
  ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com",
  ".pyd", ".node", ".drv", ".efi", ".mui", ".ax", ".ime", ".tsp"
]);
const LURE_EXTENSIONS = new Set([".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip"]);
const ACTIVE_EXTENSIONS = new Set([".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".lnk"]);

function entropy(buffer) {
  if (!buffer.length) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let value = 0;
  for (const count of counts) {
    if (!count) continue;
    const probability = count / buffer.length;
    value -= probability * Math.log2(probability);
  }
  return value;
}

function filenameFindings(file, sample) {
  const findings = [];
  const lower = path.basename(file).toLowerCase();
  const parts = lower.split(".");
  const extension = path.extname(lower);
  if (parts.length >= 3) {
    const previousExtension = `.${parts.at(-2)}`;
    if (LURE_EXTENSIONS.has(previousExtension) && ACTIVE_EXTENSIONS.has(extension)) {
      findings.push({
        id: "heuristic-double-extension",
        name: "Deceptive-Double-Extension",
        severity: "high",
        confirmed: false,
        category: "filename",
        evidence: `${previousExtension}${extension}`
      });
    }
  }
  const hasMzHeader = sample.length >= 2 && sample[0] === 0x4d && sample[1] === 0x5a;
  if (hasMzHeader && !EXECUTABLE_EXTENSIONS.has(extension)) {
    findings.push({
      id: "heuristic-mz-extension",
      name: "Executable-With-Misleading-Extension",
      severity: "high",
      confirmed: false,
      category: "format",
      evidence: extension || "(none)"
    });
  }
  if (hasMzHeader && sample.length >= 64 * 1024 && entropy(sample) >= 7.65) {
    findings.push({
      id: "heuristic-packed-pe",
      name: "High-Entropy-Executable",
      severity: "medium",
      confirmed: false,
      category: "packing",
      evidence: `entropy=${entropy(sample).toFixed(2)}`
    });
  }
  return findings;
}

async function hashFile(file) {
  const hashers = {
    md5: crypto.createHash("md5"),
    sha1: crypto.createHash("sha1"),
    sha256: crypto.createHash("sha256")
  };
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(file);
    stream.on("data", (chunk) => {
      for (const hasher of Object.values(hashers)) hasher.update(chunk);
    });
    stream.on("error", reject);
    stream.on("end", resolve);
  });
  return Object.fromEntries(Object.entries(hashers).map(([name, hasher]) => [name, hasher.digest("hex")]));
}

async function readSample(file, bytes) {
  const handle = await fsp.open(file, "r");
  try {
    const buffer = Buffer.allocUnsafe(bytes);
    const { bytesRead } = await handle.read(buffer, 0, bytes, 0);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

function contentFindings(file, sample, signatures) {
  const extension = path.extname(file).toLowerCase();
  const text = sample.toString("utf8");
  const findings = [];
  for (const signature of signatures.patterns) {
    if (signature.extensions?.length && !signature.extensions.includes(extension)) continue;
    const matched = signature.kind === "regex" ? signature.matcher.test(text) : text.includes(signature.matcher);
    if (!matched) continue;
    findings.push({
      id: signature.id,
      name: signature.name,
      severity: signature.severity,
      confirmed: Boolean(signature.confirmed),
      category: signature.category || "content",
      evidence: signature.id
    });
  }
  return findings;
}

async function enumerate(target, config, signal) {
  const files = [];
  const errors = [];
  const stack = [path.resolve(target)];
  while (stack.length) {
    if (signal?.aborted) throw new Error("Scan cancelled");
    const current = stack.pop();
    if (matchesExclusion(current, config.exclusions)) continue;
    let stat;
    try {
      stat = await fsp.lstat(current);
    } catch (error) {
      errors.push({ path: current, error: error.message });
      continue;
    }
    if (stat.isSymbolicLink() && !config.followSymbolicLinks) continue;
    if (stat.isDirectory()) {
      try {
        const entries = await fsp.readdir(current);
        for (const entry of entries) {
          if (!config.scanHiddenFiles && entry.startsWith(".")) continue;
          stack.push(path.join(current, entry));
        }
      } catch (error) {
        errors.push({ path: current, error: error.message });
      }
    } else if (stat.isFile()) {
      files.push({ path: current, size: stat.size, modifiedAt: stat.mtime.toISOString() });
    }
  }
  return { files, errors };
}

export async function scanFile(file, options) {
  const { config, signatures, signal } = options;
  if (signal?.aborted) throw new Error("Scan cancelled");
  const stat = await fsp.stat(file);
  if (!stat.isFile()) throw new Error("Not a regular file");
  if (stat.size > config.maxFileBytes) {
    return { path: file, size: stat.size, status: "skipped", reason: "size-limit", findings: [] };
  }
  const sample = await readSample(file, Math.min(config.sampleBytes, Math.max(stat.size, 1)));
  const hashes = await hashFile(file);
  const sha256 = hashes.sha256;
  const findings = filenameFindings(file, sample);
  const exact = signatures.hashes.get(sha256);
  if (exact) {
    findings.unshift({
      id: `sha256:${sha256}`,
      name: exact.name,
      severity: exact.severity,
      confirmed: exact.confirmed !== false,
      category: exact.category || "malware",
      evidence: sha256
    });
  }
  if (signatures.threatIndex) {
    const intelligence = signatures.threatIndex.lookup(hashes, stat.size);
    for (const match of intelligence) {
      findings.push({
        id: `intel:${match.source}:${match.name}`,
        name: match.name,
        severity: match.severity,
        confirmed: match.confirmed,
        category: "threat-intelligence",
        evidence: `${match.source}:${match.algorithm}:${match.hash}`,
        source: match.source,
        details: match.details
      });
    }
  }
  findings.push(...contentFindings(file, sample, signatures));
  const deduplicated = [...new Map(findings.map((item) => [item.id, item])).values()];
  return {
    path: file,
    size: stat.size,
    modifiedAt: stat.mtime.toISOString(),
    hashes,
    sha256,
    status: deduplicated.length ? "detected" : "clean",
    findings: deduplicated
  };
}

export async function scanPath(target, options = {}) {
  const startedAt = new Date();
  const database = options.signatureDatabase || await loadSignatures();
  const signatures = compileSignatures(database);
  const threatIndex = await openThreatIndex();
  signatures.threatIndex = threatIndex;
  const config = options.config;
  if (!config) throw new Error("Scanner configuration is required");
  try {
    const enumeration = await enumerate(target, config, options.signal);
    const results = [];
    const errors = [...enumeration.errors];
    let cursor = 0;
    const workerCount = Math.min(config.concurrency, Math.max(enumeration.files.length, 1));

    async function worker() {
      while (cursor < enumeration.files.length) {
        const index = cursor;
        cursor += 1;
        const item = enumeration.files[index];
        try {
          const result = await scanFile(item.path, { config, signatures, signal: options.signal });
          results.push(result);
          options.onProgress?.({
            completed: results.length + errors.length,
            total: enumeration.files.length + enumeration.errors.length,
            current: item.path,
            result
          });
        } catch (error) {
          errors.push({ path: item.path, error: error.message });
        }
      }
    }
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    const targetIsSingleFile = enumeration.files.length === 1 &&
      path.resolve(enumeration.files[0].path) === path.resolve(target);
    options.onProgress?.({
      completed: enumeration.files.length + enumeration.errors.length,
      total: enumeration.files.length + enumeration.errors.length,
      current: `Final ClamAV verification: ${path.resolve(target)}`,
      phase: "clamav"
    });
    const clamav = await scanWithClamAv(target, {
      enabled: options.clamavEngineEnabled,
      maxFileBytes: config.maxFileBytes,
      timeoutMs: targetIsSingleFile ? config.clamavFileTimeoutMs : config.clamavDirectoryTimeoutMs,
      signal: options.signal,
      onProgress: () => options.onProgress?.({
        completed: results.length + errors.length,
        total: enumeration.files.length + enumeration.errors.length,
        current: `Final ClamAV verification: ${path.resolve(target)}`,
        phase: "clamav"
      })
    });
    errors.push(...clamav.errors);
    await mergeClamAvDetections(results, clamav.detections);
    const endedAt = new Date();
    const detections = results.filter((result) => result.status === "detected");
    return {
      id: crypto.randomUUID(),
      target: path.resolve(target),
      host: os.hostname(),
      signatureVersion: signatures.version,
      startedAt: startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      durationMs: endedAt - startedAt,
      scanned: results.filter((result) => result.status !== "skipped").length,
      skipped: results.filter((result) => result.status === "skipped").length,
      detections: detections.length,
      errors,
      results
    };
  } finally {
    threatIndex.close();
  }
}

export function quickScanTargets() {
  const home = os.homedir();
  return [
    path.join(home, "Desktop"),
    path.join(home, "Downloads"),
    path.join(home, "Documents"),
    process.env.TEMP || os.tmpdir()
  ];
}
