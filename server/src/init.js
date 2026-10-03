import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { HqStore, hashAdminPassword } from "./store.js";

const configPath = path.resolve(process.argv[2] || path.join("data", "config.json"));
const required = [
  "ENDPOINTWARD_HQ_ADMIN_PASSWORD",
  "ENDPOINTWARD_HQ_PFX_PASSWORD",
  "ENDPOINTWARD_HQ_PFX_PATH",
  "ENDPOINTWARD_HQ_CERT_FINGERPRINT",
  "ENDPOINTWARD_HQ_PUBLIC_HOST"
];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} is required`);
}
const salt = crypto.randomBytes(16).toString("base64");
const iterations = 310000;
const base = path.dirname(configPath);
await fs.mkdir(base, { recursive: true });
const config = {
  schemaVersion: 4,
  hqName: process.env.ENDPOINTWARD_HQ_NAME || "Endpointward HQ",
  host: "0.0.0.0",
  port: Number(process.env.ENDPOINTWARD_HQ_PORT) || 8443,
  publicHost: process.env.ENDPOINTWARD_HQ_PUBLIC_HOST,
  databasePath: "endpointward-hq.sqlite",
  tls: {
    pfxPath: path.relative(base, path.resolve(process.env.ENDPOINTWARD_HQ_PFX_PATH)),
    password: process.env.ENDPOINTWARD_HQ_PFX_PASSWORD,
    fingerprint256: process.env.ENDPOINTWARD_HQ_CERT_FINGERPRINT.replaceAll(":", "").toUpperCase()
  },
  admin: {
    iterations,
    salt,
    passwordHash: hashAdminPassword(process.env.ENDPOINTWARD_HQ_ADMIN_PASSWORD, salt, iterations),
    sessionHours: 12,
    maxLoginAttempts: 10
  },
  discovery: { enabled: true, port: 32110 },
  telemetryRetentionDays: 30,
  alerts: {
    offlineAfterSeconds: 60
  },
  maintenance: {
    defaultMinutes: 10,
    defaultUses: 1
  },
  secrets: {
    path: "hq-secrets.json"
  },
  updates: {
    directory: "updates",
    stagingDirectory: "Z:\\Extreme Control\\Endpointward Updates",
    autoDeploy: false
  }
};
await fs.writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600, flag: "wx" });
const store = await new HqStore(path.join(base, config.databasePath)).open();
store.close();
console.log(`Endpointward HQ initialized: ${configPath}`);
