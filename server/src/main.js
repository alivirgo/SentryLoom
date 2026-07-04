import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHqServer } from "./server.js";

const serverDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const configPath = path.resolve(
  process.env.SENTRYLOOM_HQ_CONFIG || path.join(serverDirectory, "data", "config.json")
);
let config;
try {
  config = JSON.parse(await fs.readFile(configPath, "utf8"));
} catch (error) {
  console.error(`SentryLoom HQ is not initialized. Run .\\Initialize-SentryLoomHq.ps1 first.\n${error.message}`);
  process.exit(1);
}
const base = path.dirname(configPath);
config.databasePath = path.resolve(base, config.databasePath);
config.tls.pfxPath = path.resolve(base, config.tls.pfxPath);
config.updates = {
  directory: path.resolve(base, config.updates?.directory || "updates"),
  autoDeploy: Boolean(config.updates?.autoDeploy)
};

const hq = await createHqServer(config);
const address = await hq.listen();
hq.startDiscovery();
hq.store.pruneTelemetry(config.telemetryRetentionDays);
console.log(`${config.hqName} listening at https://${config.publicHost}:${address.port}`);
console.log(`Certificate SHA-256: ${config.tls.fingerprint256}`);

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await hq.close();
  process.exit(0);
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
