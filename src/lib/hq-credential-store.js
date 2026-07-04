import fs from "node:fs/promises";
import crypto from "node:crypto";
import { appPaths } from "../constants.js";
import { getMasterKey } from "./key-store.js";
import { ensureDirectory } from "./fs-safe.js";

const MAGIC = Buffer.from("SLOOMHQ1", "ascii");
const PENDING_MAGIC = Buffer.from("SLOOMHQR", "ascii");

async function encryptStore(file, magic, value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", await getMasterKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  const payload = Buffer.concat([magic, iv, cipher.getAuthTag(), encrypted]);
  const paths = appPaths();
  await ensureDirectory(paths.keys);
  const temporary = `${file}.${process.pid}.tmp`;
  await fs.writeFile(temporary, payload, { mode: 0o600, flag: "wx" });
  await fs.rename(temporary, file);
}

async function decryptStore(file, magic) {
  let payload;
  try {
    payload = await fs.readFile(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (payload.length < magic.length + 28 || !payload.subarray(0, magic.length).equals(magic)) {
    throw new Error("HQ credential store is invalid");
  }
  const offset = magic.length;
  const iv = payload.subarray(offset, offset + 12);
  const tag = payload.subarray(offset + 12, offset + 28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", await getMasterKey(), iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([
    decipher.update(payload.subarray(offset + 28)),
    decipher.final()
  ]).toString("utf8"));
}

export async function saveHqCredentials(credentials) {
  const clean = {
    serverUrl: String(credentials.serverUrl),
    fingerprint256: String(credentials.fingerprint256 || ""),
    hqName: String(credentials.hqName || "SentryLoom HQ"),
    deviceId: String(credentials.deviceId),
    token: String(credentials.token),
    enrolledAt: String(credentials.enrolledAt || new Date().toISOString())
  };
  if (!/^https:\/\//i.test(clean.serverUrl) && process.env.SENTRYLOOM_ALLOW_INSECURE_HQ !== "1") {
    throw new Error("SentryLoom HQ must use HTTPS");
  }
  if (!/^[a-f0-9-]{36}$/i.test(clean.deviceId) || clean.token.length < 40) {
    throw new Error("HQ enrollment credentials are invalid");
  }
  await encryptStore(appPaths().hqCredentials, MAGIC, clean);
}

export async function loadHqCredentials() {
  return decryptStore(appPaths().hqCredentials, MAGIC);
}

export async function clearHqCredentials() {
  await fs.rm(appPaths().hqCredentials, { force: true });
}

export async function savePendingHqEnrollment(pending) {
  const clean = {
    serverUrl: String(pending.serverUrl),
    fingerprint256: String(pending.fingerprint256),
    hqName: String(pending.hqName || "SentryLoom HQ"),
    requestId: String(pending.requestId),
    requestSecret: String(pending.requestSecret),
    requestedAt: String(pending.requestedAt || new Date().toISOString()),
    status: String(pending.status || "pending")
  };
  if (!/^[a-f0-9-]{36}$/i.test(clean.requestId) || clean.requestSecret.length < 40) {
    throw new Error("Pending HQ enrollment credentials are invalid");
  }
  await encryptStore(appPaths().hqPendingEnrollment, PENDING_MAGIC, clean);
}

export async function loadPendingHqEnrollment() {
  return decryptStore(appPaths().hqPendingEnrollment, PENDING_MAGIC);
}

export async function clearPendingHqEnrollment() {
  await fs.rm(appPaths().hqPendingEnrollment, { force: true });
}
