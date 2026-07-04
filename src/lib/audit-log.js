import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { appPaths } from "../constants.js";
import { ensureDirectory } from "./fs-safe.js";
import { getMasterKey } from "./key-store.js";

let auditQueue = Promise.resolve();

function recordMac(key, record) {
  const unsigned = { ...record };
  delete unsigned.mac;
  return crypto.createHmac("sha256", key).update(JSON.stringify(unsigned)).digest("hex");
}

function inspectAudit(text, key) {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  let previousMac = null;
  let first = null;
  let last = null;
  for (let index = 0; index < lines.length; index += 1) {
    let record;
    try {
      record = JSON.parse(lines[index]);
    } catch {
      return {
        valid: false,
        records: index,
        failedAt: index + 1,
        reason: "malformed-record",
        last
      };
    }
    first ||= record;
    if (record.sequence !== index + 1 ||
        record.previousMac !== previousMac ||
        recordMac(key, record) !== record.mac) {
      return {
        valid: false,
        records: index,
        failedAt: index + 1,
        reason: "chain-mismatch",
        last
      };
    }
    previousMac = record.mac;
    last = record;
  }
  const recovery = first?.event === "audit.chain-recovered" ? first.details : null;
  return {
    valid: true,
    records: lines.length,
    last,
    ...(recovery ? {
      recovered: true,
      recoveredAt: first.at,
      evidenceFile: recovery.evidenceFile,
      evidenceSha256: recovery.evidenceSha256,
      originalFailedAt: recovery.originalFailedAt,
      originalFailureReason: recovery.originalFailureReason
    } : {})
  };
}

async function readAudit(file) {
  try {
    return await fs.readFile(file, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return "";
    throw error;
  }
}

async function withAuditLock(file, operation) {
  const lockFile = `${file}.lock`;
  const nonce = crypto.randomBytes(16).toString("hex");
  let handle = null;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      handle = await fs.open(lockFile, "wx", 0o600);
      await handle.writeFile(JSON.stringify({
        pid: process.pid,
        nonce,
        acquiredAt: new Date().toISOString()
      }));
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      try {
        const stat = await fs.stat(lockFile);
        if (Date.now() - stat.mtimeMs > 60000) await fs.rm(lockFile, { force: true });
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 15 + Math.min(attempt, 25)));
    }
  }
  if (!handle) throw new Error("Timed out waiting for the audit log writer");
  try {
    return await operation();
  } finally {
    await handle.close().catch(() => {});
    try {
      const owner = JSON.parse(await fs.readFile(lockFile, "utf8"));
      if (owner.nonce === nonce) await fs.rm(lockFile, { force: true });
    } catch {
      await fs.rm(lockFile, { force: true }).catch(() => {});
    }
  }
}

async function recoverAuditChain(paths, key, text, inspection) {
  const evidenceSha256 = crypto.createHash("sha256").update(text, "utf8").digest("hex");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const evidenceFile = `audit-evidence-${timestamp}-${evidenceSha256.slice(0, 12)}.jsonl`;
  const evidencePath = path.join(paths.logs, evidenceFile);
  await fs.rename(paths.auditLog, evidencePath);
  const recovery = {
    sequence: 1,
    at: new Date().toISOString(),
    event: "audit.chain-recovered",
    details: {
      evidenceFile,
      evidenceSha256,
      originalFailedAt: inspection.failedAt,
      originalFailureReason: inspection.reason
    },
    previousMac: null
  };
  recovery.mac = recordMac(key, recovery);
  await fs.writeFile(paths.auditLog, `${JSON.stringify(recovery)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx"
  });
  return recovery;
}

async function appendAuditRecord(event, details = {}) {
  const paths = appPaths();
  await ensureDirectory(paths.logs);
  const key = await getMasterKey();
  return withAuditLock(paths.auditLog, async () => {
    const text = await readAudit(paths.auditLog);
    const inspection = inspectAudit(text, key);
    const previous = inspection.valid
      ? inspection.last
      : await recoverAuditChain(paths, key, text, inspection);
    const record = {
      sequence: (previous?.sequence || 0) + 1,
      at: new Date().toISOString(),
      event,
      details,
      previousMac: previous?.mac || null
    };
    record.mac = recordMac(key, record);
    await fs.appendFile(paths.auditLog, `${JSON.stringify(record)}\n`, {
      encoding: "utf8",
      mode: 0o600
    });
    return record;
  });
}

export function appendAudit(event, details = {}) {
  const operation = auditQueue.then(() => appendAuditRecord(event, details));
  auditQueue = operation.catch(() => {});
  return operation;
}

export async function verifyAuditLog() {
  const paths = appPaths();
  await ensureDirectory(paths.logs);
  const key = await getMasterKey();
  return withAuditLock(paths.auditLog, async () => {
    const { last, ...status } = inspectAudit(await readAudit(paths.auditLog), key);
    return status;
  });
}

export async function readRecentAudit(limit = 100) {
  const paths = appPaths();
  await ensureDirectory(paths.logs);
  return withAuditLock(paths.auditLog, async () => {
    const text = await readAudit(paths.auditLog);
    const lines = text.trim().split(/\r?\n/).filter(Boolean);
    return lines.slice(-limit).reverse().flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
  });
}
