import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { applyHqSettings, createHqServer } from "./server.js";

const serverDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const configPath = path.resolve(
  process.env.SENTRYLOOM_HQ_CONFIG || path.join(serverDirectory, "data", "config.json")
);
let config;
let storedConfigText;
try {
  storedConfigText = await fs.readFile(configPath, "utf8");
  config = JSON.parse(storedConfigText);
} catch (error) {
  console.error(`SentryLoom HQ is not initialized. Run .\\Initialize-SentryLoomHq.ps1 first.\n${error.message}`);
  process.exit(1);
}
const base = path.dirname(configPath);
applyHqSettings(config);
if (JSON.stringify(JSON.parse(storedConfigText)) !== JSON.stringify(config)) {
  const temporary = `${configPath}.${process.pid}.migration.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(config, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx"
  });
  await fs.rename(temporary, configPath);
  console.log(`SentryLoom HQ configuration migrated to schema ${config.schemaVersion}.`);
}
config.databasePath = path.resolve(base, config.databasePath);
config.tls.pfxPath = path.resolve(base, config.tls.pfxPath);
config.updates = {
  directory: path.resolve(base, config.updates?.directory || "updates"),
  autoDeploy: Boolean(config.updates?.autoDeploy)
};

const hq = await createHqServer(config, { configPath });
const address = await hq.listen();
hq.startDiscovery();
const prune = () => hq.store.pruneOperationalData(config.telemetryRetentionDays);
const initialPruning = prune();
console.log(`Data retention: ${config.telemetryRetentionDays} days; pruned ${Object.values(initialPruning.deleted).reduce((sum, value) => sum + value, 0)} expired records.`);
const retentionTimer = setInterval(prune, 6 * 60 * 60 * 1000);
retentionTimer.unref?.();
console.log(`${config.hqName} listening at https://${config.publicHost}:${address.port}`);
console.log(`Certificate SHA-256: ${config.tls.fingerprint256}`);

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  clearInterval(retentionTimer);
  await hq.close();
  process.exit(0);
}
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
