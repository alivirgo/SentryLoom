import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { pipeline } from "node:stream/promises";
import { appPaths } from "../constants.js";
import { ensureDirectory, fileExists, writeJsonAtomic } from "./fs-safe.js";
import { getMasterKey } from "./key-store.js";
import { appendAudit } from "./audit-log.js";

const MAGIC = Buffer.from("SLOOMQ1", "ascii");
const LEGACY_MAGIC = Buffer.from("AEGISQ1", "ascii");
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const EMPTY_INDEX = Object.freeze({ schemaVersion: 1, items: [] });
let indexQueue = Promise.resolve();

function validateId(id) {
  if (!/^[a-f0-9-]{36}$/i.test(id)) throw new Error("Invalid quarantine identifier");
}

function emptyIndex() {
  return structuredClone(EMPTY_INDEX);
}

function validateIndex(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      value.schemaVersion !== 1 || !Array.isArray(value.items)) {
    throw new Error("Quarantine index has an invalid structure");
  }
  for (const item of value.items) {
    if (!item || typeof item !== "object" ||
        !/^[a-f0-9-]{36}$/i.test(item.id || "") ||
        path.basename(item.storedFile || "") !== item.storedFile ||
        !item.storedFile.endsWith(".sloomq") ||
        typeof item.state !== "string") {
      throw new Error("Quarantine index contains an invalid item");
    }
  }
  return value;
}

async function readIndexFile(file, fallbackOnMissing = false) {
  try {
    return validateIndex(JSON.parse(await fsp.readFile(file, "utf8")));
  } catch (error) {
    if (fallbackOnMissing && error.code === "ENOENT") return emptyIndex();
    throw error;
  }
}

async function withIndexLock(operation) {
  const paths = appPaths();
  await ensureDirectory(paths.quarantine);
  const nonce = crypto.randomBytes(16).toString("hex");
  let handle = null;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      handle = await fsp.open(paths.quarantineIndexLock, "wx", 0o600);
      await handle.writeFile(JSON.stringify({
        pid: process.pid,
        nonce,
        acquiredAt: new Date().toISOString()
      }));
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      try {
        const stat = await fsp.stat(paths.quarantineIndexLock);
        if (Date.now() - stat.mtimeMs > 60000) {
          await fsp.rm(paths.quarantineIndexLock, { force: true });
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 15 + Math.min(attempt, 25)));
    }
  }
  if (!handle) throw new Error("Timed out waiting for the quarantine index writer");
  try {
    return await operation();
  } finally {
    await handle.close().catch(() => {});
    try {
      const owner = JSON.parse(await fsp.readFile(paths.quarantineIndexLock, "utf8"));
      if (owner.nonce === nonce) await fsp.rm(paths.quarantineIndexLock, { force: true });
    } catch {
      await fsp.rm(paths.quarantineIndexLock, { force: true }).catch(() => {});
    }
  }
}

async function writeIndex(index) {
  const paths = appPaths();
  const validated = validateIndex(index);
  await writeJsonAtomic(paths.quarantineIndexBackup, validated);
  await writeJsonAtomic(paths.quarantineIndex, validated);
}

async function quarantineContainers() {
  const paths = appPaths();
  let entries;
  try {
    entries = await fsp.readdir(paths.quarantine, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  return Promise.all(entries
    .filter((entry) => entry.isFile() && /^[a-f0-9-]{36}\.sloomq$/i.test(entry.name))
    .map(async (entry) => {
      let stat = null;
      try {
        stat = await fsp.stat(path.join(paths.quarantine, entry.name));
      } catch {}
      return {
        id: entry.name.slice(0, -".sloomq".length),
        storedFile: entry.name,
        size: stat?.size ?? null,
        modifiedAt: stat?.mtime.toISOString() || new Date().toISOString()
      };
    }));
}

async function preserveCorruptIndex(error) {
  const paths = appPaths();
  let bytes;
  try {
    bytes = await fsp.readFile(paths.quarantineIndex);
  } catch (readError) {
    if (readError.code === "ENOENT") return null;
    throw readError;
  }
  const sha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const evidenceFile = `index-evidence-${timestamp}-${sha256.slice(0, 12)}.bin`;
  const evidencePath = path.join(paths.quarantine, evidenceFile);
  try {
    await fsp.rename(paths.quarantineIndex, evidencePath);
  } catch {
    await fsp.copyFile(paths.quarantineIndex, evidencePath, fs.constants.COPYFILE_EXCL);
    await fsp.rm(paths.quarantineIndex, { force: true }).catch(() => {});
  }
  return {
    evidenceFile,
    evidenceSha256: sha256,
    originalError: error.message
  };
}

function reconcileIndex(index, containers, recoveredAt) {
  const containerByName = new Map(containers.map((item) => [item.storedFile, item]));
  const known = new Set();
  const items = index.items.map((item) => {
    known.add(item.storedFile);
    if (item.state === "quarantined" && !containerByName.has(item.storedFile)) {
      return { ...item, state: "missing", missingAt: recoveredAt };
    }
    return item;
  });
  for (const container of containers) {
    if (known.has(container.storedFile)) continue;
    items.push({
      id: container.id,
      originalPath: null,
      storedFile: container.storedFile,
      originalSize: null,
      originalModifiedAt: null,
      quarantinedAt: container.modifiedAt,
      sha256: null,
      findings: [{ name: "Recovered encrypted item", severity: "unknown" }],
      state: "orphaned",
      containerSize: container.size,
      metadataLost: true,
      recoveredAt
    });
  }
  return { ...index, schemaVersion: 1, items };
}

async function recoverIndex(originalError) {
  return withIndexLock(async () => {
    const paths = appPaths();
    try {
      return await readIndexFile(paths.quarantineIndex);
    } catch {}

    const recoveredAt = new Date().toISOString();
    let evidence = null;
    let evidenceError = null;
    try {
      evidence = await preserveCorruptIndex(originalError);
    } catch (error) {
      evidenceError = error.message;
    }

    let base = emptyIndex();
    let source = "empty";
    try {
      base = await readIndexFile(paths.quarantineIndexBackup);
      source = "last-good-backup";
    } catch {}

    let containers = null;
    let containerScanError = null;
    try {
      containers = await quarantineContainers();
    } catch (error) {
      containerScanError = error.message;
    }
    const recovered = containers
      ? reconcileIndex(base, containers, recoveredAt)
      : base;
    recovered.recovery = {
      recoveredAt,
      source,
      ...(evidence || {}),
      ...(evidenceError ? { evidenceError } : {}),
      ...(containerScanError ? { containerScanError } : {}),
      orphanedItems: recovered.items.filter((item) => item.state === "orphaned").length,
      missingItems: recovered.items.filter((item) => item.state === "missing").length
    };

    let persisted = true;
    try {
      await writeIndex(recovered);
    } catch {
      persisted = false;
    }
    await appendAudit("quarantine.index-recovered", {
      ...recovered.recovery,
      persisted
    }).catch(() => {});
    return recovered;
  });
}

async function readIndex() {
  const paths = appPaths();
  try {
    return await readIndexFile(paths.quarantineIndex);
  } catch (error) {
    if (error.code === "ENOENT") {
      const backupExists = await fileExists(paths.quarantineIndexBackup);
      const containers = backupExists ? [] : await quarantineContainers().catch(() => []);
      if (!backupExists && containers.length === 0) return emptyIndex();
    }
    return recoverIndex(error);
  }
}

async function updateIndex(transform) {
  const operation = indexQueue.then(() => withIndexLock(async () => {
    const paths = appPaths();
    let index;
    try {
      index = await readIndexFile(paths.quarantineIndex);
    } catch (error) {
      if (error.code === "ENOENT") {
        const backupExists = await fileExists(paths.quarantineIndexBackup);
        const containers = backupExists ? [] : await quarantineContainers().catch(() => []);
        if (!backupExists && containers.length === 0) {
          index = emptyIndex();
        } else {
          // Release the writer lock before invoking the recovery path.
          throw Object.assign(error, { quarantineRecoveryRequired: true });
        }
      } else {
        // Release the writer lock before invoking the recovery path.
        throw Object.assign(error, { quarantineRecoveryRequired: true });
      }
    }
    const updated = await transform(index);
    await writeIndex(updated);
    return updated;
  })).catch(async (error) => {
    if (!error.quarantineRecoveryRequired) throw error;
    await recoverIndex(error);
    return withIndexLock(async () => {
      const index = await readIndexFile(appPaths().quarantineIndex);
      const updated = await transform(index);
      await writeIndex(updated);
      return updated;
    });
  });
  indexQueue = operation.catch(() => {});
  return operation;
}

export async function quarantineFile(source, detection = {}) {
  const paths = appPaths();
  await ensureDirectory(paths.quarantine);
  const resolved = path.resolve(source);
  const stat = await fsp.lstat(resolved);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Only regular files can be quarantined");
  const id = crypto.randomUUID();
  const destination = path.join(paths.quarantine, `${id}.sloomq`);
  const temporary = `${destination}.tmp`;
  const key = await getMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const output = fs.createWriteStream(temporary, { flags: "wx", mode: 0o600 });
  output.write(MAGIC);
  output.write(iv);
  try {
    await pipeline(fs.createReadStream(resolved), cipher, output);
    await fsp.appendFile(temporary, cipher.getAuthTag());
    await fsp.rename(temporary, destination);
  } catch (error) {
    await fsp.rm(temporary, { force: true });
    throw error;
  }

  const record = {
    id,
    originalPath: resolved,
    storedFile: path.basename(destination),
    originalSize: stat.size,
    originalModifiedAt: stat.mtime.toISOString(),
    quarantinedAt: new Date().toISOString(),
    sha256: detection.sha256 || null,
    findings: detection.findings || [],
    state: "quarantined"
  };
  await updateIndex((index) => ({
    ...index,
    items: [...index.items.filter((item) => item.id !== id), record]
  }));
  try {
    await fsp.rm(resolved);
  } catch (error) {
    await fsp.rm(destination, { force: true });
    await updateIndex((index) => ({ ...index, items: index.items.filter((item) => item.id !== id) }));
    throw new Error(`Encrypted copy was created, but the source could not be removed: ${error.message}`);
  }
  await appendAudit("quarantine.added", { id, originalPath: resolved, findings: record.findings.map((item) => item.name) });
  return record;
}

export async function listQuarantine() {
  const index = await readIndex();
  return index.items.slice().reverse();
}

async function decryptTo(record, destination) {
  const paths = appPaths();
  const source = path.join(paths.quarantine, record.storedFile);
  const stat = await fsp.stat(source);
  const minimum = MAGIC.length + IV_LENGTH + TAG_LENGTH;
  if (stat.size < minimum) throw new Error("Quarantine container is truncated");
  const handle = await fsp.open(source, "r");
  let header;
  let tag;
  try {
    header = Buffer.alloc(MAGIC.length + IV_LENGTH);
    await handle.read(header, 0, header.length, 0);
    tag = Buffer.alloc(TAG_LENGTH);
    await handle.read(tag, 0, TAG_LENGTH, stat.size - TAG_LENGTH);
  } finally {
    await handle.close();
  }
  const containerMagic = header.subarray(0, MAGIC.length);
  if (!containerMagic.equals(MAGIC) && !containerMagic.equals(LEGACY_MAGIC)) {
    throw new Error("Invalid quarantine container");
  }
  const iv = header.subarray(MAGIC.length);
  const decipher = crypto.createDecipheriv("aes-256-gcm", await getMasterKey(), iv);
  decipher.setAuthTag(tag);
  await pipeline(
    fs.createReadStream(source, { start: MAGIC.length + IV_LENGTH, end: stat.size - TAG_LENGTH - 1 }),
    decipher,
    fs.createWriteStream(destination, { flags: "wx", mode: 0o600 })
  );
}

export async function restoreQuarantine(id, requestedDestination) {
  validateId(id);
  const index = await readIndex();
  const record = index.items.find((item) => item.id === id && item.state === "quarantined");
  if (!record) throw new Error("Quarantine item not found");
  const destination = path.resolve(requestedDestination || record.originalPath);
  if (await fileExists(destination)) throw new Error(`Restore destination already exists: ${destination}`);
  await ensureDirectory(path.dirname(destination));
  const temporary = `${destination}.${id}.restore`;
  try {
    await decryptTo(record, temporary);
    await fsp.rename(temporary, destination);
  } catch (error) {
    await fsp.rm(temporary, { force: true });
    throw new Error(`Restore failed: ${error.message}`, { cause: error });
  }
  await updateIndex((current) => ({
    ...current,
    items: current.items.map((item) => item.id === id
      ? { ...item, state: "restored", restoredAt: new Date().toISOString(), restoredTo: destination }
      : item)
  }));
  await appendAudit("quarantine.restored", { id, destination });
  return destination;
}

export async function deleteQuarantine(id) {
  validateId(id);
  const paths = appPaths();
  const index = await readIndex();
  const record = index.items.find((item) => item.id === id);
  if (!record) throw new Error("Quarantine item not found");
  await fsp.rm(path.join(paths.quarantine, record.storedFile), { force: true });
  await updateIndex((current) => ({
    ...current,
    items: current.items.map((item) => item.id === id
      ? { ...item, state: "deleted", deletedAt: new Date().toISOString() }
      : item)
  }));
  await appendAudit("quarantine.deleted", { id });
}
