import fs from "node:fs/promises";
import crypto from "node:crypto";
import { appPaths } from "../constants.js";
import { getMasterKey } from "./key-store.js";
import { ensureDirectory } from "./fs-safe.js";

const MAGIC = Buffer.from("SLOOMC1", "ascii");

export async function saveThreatCredentials(credentials) {
  const clean = {};
  if (credentials.abuseChAuthKey) {
    const key = String(credentials.abuseChAuthKey).trim();
    if (!/^[A-Za-z0-9._~-]{16,256}$/.test(key)) throw new Error("The abuse.ch Auth-Key format is invalid");
    clean.abuseChAuthKey = key;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", await getMasterKey(), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(clean), "utf8"), cipher.final()]);
  const payload = Buffer.concat([MAGIC, iv, cipher.getAuthTag(), encrypted]);
  const paths = appPaths();
  await ensureDirectory(paths.keys);
  const temporary = `${paths.threatCredentials}.${process.pid}.tmp`;
  await fs.writeFile(temporary, payload, { mode: 0o600, flag: "wx" });
  await fs.rename(temporary, paths.threatCredentials);
}

export async function loadThreatCredentials() {
  let payload;
  try {
    payload = await fs.readFile(appPaths().threatCredentials);
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw error;
  }
  if (payload.length < MAGIC.length + 28 || !payload.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("Threat-intelligence credential store is invalid");
  }
  const offset = MAGIC.length;
  const iv = payload.subarray(offset, offset + 12);
  const tag = payload.subarray(offset + 12, offset + 28);
  const ciphertext = payload.subarray(offset + 28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", await getMasterKey(), iv);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8"));
}

export async function threatCredentialStatus() {
  const credentials = await loadThreatCredentials();
  return { abuseChConfigured: Boolean(credentials.abuseChAuthKey) };
}
