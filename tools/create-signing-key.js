#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const outputDirectory = path.resolve(process.argv[2] || "signing-key");
await fs.mkdir(outputDirectory, { recursive: true, mode: 0o700 });
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
await fs.writeFile(
  path.join(outputDirectory, "signature-public.pem"),
  publicKey.export({ type: "spki", format: "pem" }),
  { mode: 0o644, flag: "wx" }
);
await fs.writeFile(
  path.join(outputDirectory, "signature-private.pem"),
  privateKey.export({ type: "pkcs8", format: "pem" }),
  { mode: 0o600, flag: "wx" }
);
console.log(`Created Ed25519 signing key pair in ${outputDirectory}`);
console.log("Keep signature-private.pem offline and never deploy it to protected endpoints.");
