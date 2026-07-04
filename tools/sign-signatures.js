#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const [databaseFile, privateKeyFile, keyId, outputFile] = process.argv.slice(2);
if (!databaseFile || !privateKeyFile || !keyId || !outputFile) {
  console.error("Usage: node tools/sign-signatures.js <database.json> <private-key.pem> <key-id> <bundle.json>");
  process.exit(1);
}
if (!/^[A-Za-z0-9._-]{1,64}$/.test(keyId)) throw new Error("Invalid key identifier");

const payload = await fs.readFile(path.resolve(databaseFile));
JSON.parse(payload.toString("utf8"));
const privateKey = crypto.createPrivateKey(await fs.readFile(path.resolve(privateKeyFile), "utf8"));
if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Only Ed25519 keys are supported");
const bundle = {
  schemaVersion: 1,
  keyId,
  createdAt: new Date().toISOString(),
  payload: payload.toString("base64"),
  signature: crypto.sign(null, payload, privateKey).toString("base64")
};
await fs.writeFile(path.resolve(outputFile), `${JSON.stringify(bundle, null, 2)}\n`, { flag: "wx", mode: 0o600 });
console.log(`Created signed signature bundle: ${path.resolve(outputFile)}`);
