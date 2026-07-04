import fs from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { appPaths } from "../constants.js";
import { fileExists, readJson, writeJsonAtomic } from "./fs-safe.js";
import { appendAudit } from "./audit-log.js";
import { threatIndexStatus } from "./threat-index.js";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const builtInFile = path.resolve(moduleDirectory, "../../signatures/base.json");

function validateDatabase(database) {
  if (database.schemaVersion !== 1 || !Array.isArray(database.hashes) || !Array.isArray(database.patterns)) {
    throw new Error("Unsupported or malformed signature database");
  }
  for (const entry of database.hashes) {
    if (!/^[a-f0-9]{64}$/i.test(entry.sha256) || !entry.name) throw new Error("Malformed hash signature");
  }
  for (const entry of database.patterns) {
    if (!entry.id || !entry.pattern || !["literal", "regex"].includes(entry.kind)) {
      throw new Error("Malformed content signature");
    }
    if (entry.kind === "regex") new RegExp(entry.pattern, entry.flags || "i");
  }
  return database;
}

export async function loadSignatures() {
  const builtIn = validateDatabase(JSON.parse(await fs.readFile(builtInFile, "utf8")));
  const imported = await readJson(appPaths().importedSignatures, {
    schemaVersion: 1,
    version: "none",
    hashes: [],
    patterns: []
  });
  validateDatabase(imported);
  return {
    schemaVersion: 1,
    version: `${builtIn.version}+${imported.version}`,
    hashes: [...builtIn.hashes, ...imported.hashes],
    patterns: [...builtIn.patterns, ...imported.patterns]
  };
}

export function compileSignatures(database) {
  return {
    version: database.version,
    hashes: new Map(database.hashes.map((item) => [item.sha256.toLowerCase(), item])),
    patterns: database.patterns.map((item) => ({
      ...item,
      matcher: item.kind === "regex"
        ? new RegExp(item.pattern, item.flags || "i")
        : item.pattern
    }))
  };
}

export async function importSignedBundle(bundleFile) {
  const bundle = JSON.parse(await fs.readFile(bundleFile, "utf8"));
  if (!bundle.payload || !bundle.signature || !bundle.keyId) throw new Error("Signature bundle envelope is incomplete");
  const trustedKeys = await readJson(appPaths().signatureKeys, { keys: [] });
  const trusted = trustedKeys.keys.find((item) => item.id === bundle.keyId);
  if (!trusted) throw new Error(`Signing key '${bundle.keyId}' is not trusted`);
  const payloadBytes = Buffer.from(bundle.payload, "base64");
  const signatureBytes = Buffer.from(bundle.signature, "base64");
  const publicKey = crypto.createPublicKey(trusted.publicKeyPem);
  if (!crypto.verify(null, payloadBytes, publicKey, signatureBytes)) throw new Error("Signature bundle verification failed");
  const database = validateDatabase(JSON.parse(payloadBytes.toString("utf8")));
  await writeJsonAtomic(appPaths().importedSignatures, database);
  await appendAudit("signatures.imported", { version: database.version, keyId: bundle.keyId });
  return database;
}

export async function trustSignatureKey(keyId, pemFile) {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) throw new Error("Invalid key identifier");
  const pem = await fs.readFile(pemFile, "utf8");
  const key = crypto.createPublicKey(pem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Only Ed25519 signature keys are accepted");
  const paths = appPaths();
  const trusted = await readJson(paths.signatureKeys, { keys: [] });
  const keys = trusted.keys.filter((item) => item.id !== keyId);
  keys.push({ id: keyId, publicKeyPem: key.export({ type: "spki", format: "pem" }), addedAt: new Date().toISOString() });
  await writeJsonAtomic(paths.signatureKeys, { keys });
  await appendAudit("signatures.key-trusted", { keyId });
}

export async function signatureStatus() {
  const database = await loadSignatures();
  const threatIntel = await threatIndexStatus();
  return {
    version: database.version,
    hashCount: database.hashes.length,
    patternCount: database.patterns.length,
    imported: await fileExists(appPaths().importedSignatures),
    threatCount: threatIntel.hashEntries,
    networkIocCount: threatIntel.networkEntries,
    threatIntel
  };
}
