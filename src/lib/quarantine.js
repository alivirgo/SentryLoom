import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { pipeline } from "node:stream/promises";
import { appPaths } from "../constants.js";
import { ensureDirectory, fileExists, readJson, writeJsonAtomic } from "./fs-safe.js";
import { getMasterKey } from "./key-store.js";
import { appendAudit } from "./audit-log.js";

const MAGIC = Buffer.from("SLOOMQ1", "ascii");
const LEGACY_MAGIC = Buffer.from("AEGISQ1", "ascii");
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function validateId(id) {
  if (!/^[a-f0-9-]{36}$/i.test(id)) throw new Error("Invalid quarantine identifier");
}

async function readIndex() {
  return readJson(appPaths().quarantineIndex, { schemaVersion: 1, items: [] });
}

async function updateIndex(transform) {
  const paths = appPaths();
  const index = await readIndex();
  const updated = await transform(index);
  await writeJsonAtomic(paths.quarantineIndex, updated);
  return updated;
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
  await updateIndex((index) => ({ ...index, items: [...index.items, record] }));
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
