import fs from "node:fs/promises";
import os from "node:os";
import crypto from "node:crypto";
import { appPaths, APP_NAME, APP_VERSION } from "../constants.js";
import { readJson, writeJsonAtomic } from "./fs-safe.js";

export async function getDeviceIdentity() {
  const file = appPaths().deviceIdentity;
  const stored = await readJson(file, null);
  if (stored?.installationId && /^[a-f0-9-]{36}$/i.test(stored.installationId)) {
    return {
      ...stored,
      name: stored.name || os.hostname(),
      hostname: os.hostname(),
      platform: `${os.platform()} ${os.release()}`,
      appVersion: APP_VERSION
    };
  }
  const identity = {
    schemaVersion: 1,
    installationId: crypto.randomUUID(),
    name: os.hostname(),
    hostname: os.hostname(),
    platform: `${os.platform()} ${os.release()}`,
    appName: APP_NAME,
    appVersion: APP_VERSION,
    createdAt: new Date().toISOString()
  };
  await writeJsonAtomic(file, identity);
  return identity;
}

export async function renameManagedDevice(name) {
  const clean = String(name || "").trim();
  if (!clean || clean.length > 100) throw new Error("Device name must contain 1 to 100 characters");
  const identity = await getDeviceIdentity();
  const updated = { ...identity, name: clean };
  await writeJsonAtomic(appPaths().deviceIdentity, updated);
  return updated;
}
