import fs from "node:fs/promises";
import path from "node:path";
import { APP_VERSION, DEFAULT_CONFIG, appPaths } from "../constants.js";
import { ensureDirectory, readJson, writeJsonAtomic } from "./fs-safe.js";
import { getDnsProfile } from "./dns-profiles.js";

function deepMerge(base, update) {
  if (!update || typeof update !== "object" || Array.isArray(update)) return base;
  const result = { ...base };
  for (const [key, value] of Object.entries(update)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      result[key] = deepMerge(base[key] || {}, value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

export function validateConfig(config) {
  const errors = [];
  if (!Number.isInteger(config.scanner?.maxFileBytes) || config.scanner.maxFileBytes < 1024) {
    errors.push("scanner.maxFileBytes must be an integer of at least 1024");
  }
  if (!Number.isInteger(config.scanner?.sampleBytes) || config.scanner.sampleBytes < 1024) {
    errors.push("scanner.sampleBytes must be an integer of at least 1024");
  }
  if (!Number.isInteger(config.scanner?.concurrency) || config.scanner.concurrency < 1 || config.scanner.concurrency > 32) {
    errors.push("scanner.concurrency must be between 1 and 32");
  }
  if (!Number.isInteger(config.scanner?.realtimeConcurrency) ||
      config.scanner.realtimeConcurrency < 1 ||
      config.scanner.realtimeConcurrency > 8) {
    errors.push("scanner.realtimeConcurrency must be between 1 and 8");
  }
  if (!Number.isInteger(config.scanner?.maxPendingRealtimeFiles) ||
      config.scanner.maxPendingRealtimeFiles < 100 ||
      config.scanner.maxPendingRealtimeFiles > 100000) {
    errors.push("scanner.maxPendingRealtimeFiles must be between 100 and 100000");
  }
  if (!Number.isInteger(config.scanner?.clamavFileTimeoutMs) ||
      config.scanner.clamavFileTimeoutMs < 10000 ||
      config.scanner.clamavFileTimeoutMs > 10 * 60 * 1000) {
    errors.push("scanner.clamavFileTimeoutMs must be between 10000 and 600000");
  }
  if (!Number.isInteger(config.scanner?.clamavDirectoryTimeoutMs) ||
      config.scanner.clamavDirectoryTimeoutMs < 60000 ||
      config.scanner.clamavDirectoryTimeoutMs > 4 * 60 * 60 * 1000) {
    errors.push("scanner.clamavDirectoryTimeoutMs must be between 60000 and 14400000");
  }
  if (!Array.isArray(config.scanner?.exclusions)) errors.push("scanner.exclusions must be an array");
  if (!Number.isInteger(config.dashboard?.port) || config.dashboard.port < 1024 || config.dashboard.port > 65535) {
    errors.push("dashboard.port must be between 1024 and 65535");
  }
  if (config.dashboard?.host !== "127.0.0.1" && config.dashboard?.host !== "::1") {
    errors.push("dashboard.host must be a loopback address");
  }
  if (!Number.isInteger(config.protection?.networkPollIntervalMs) ||
      config.protection.networkPollIntervalMs < 1000) {
    errors.push("protection.networkPollIntervalMs must be at least 1000");
  }
  if (!Number.isInteger(config.protection?.dnsPollIntervalMs) ||
      config.protection.dnsPollIntervalMs < 5000) {
    errors.push("protection.dnsPollIntervalMs must be at least 5000");
  }
  if (!Number.isInteger(config.threatIntel?.requestTimeoutMs) ||
      config.threatIntel.requestTimeoutMs < 10000 ||
      config.threatIntel.requestTimeoutMs > 600000) {
    errors.push("threatIntel.requestTimeoutMs must be between 10000 and 600000");
  }
  if (!Number.isInteger(config.threatIntel?.minimumUpdateIntervalMinutes) ||
      config.threatIntel.minimumUpdateIntervalMinutes < 5) {
    errors.push("threatIntel.minimumUpdateIntervalMinutes must be at least 5");
  }
  if (!getDnsProfile(config.dnsFiltering?.selectedProfile)) {
    errors.push("dnsFiltering.selectedProfile must name a supported DNS profile");
  }
  if (config.dnsFiltering?.lastAppliedProfile !== null &&
      !getDnsProfile(config.dnsFiltering?.lastAppliedProfile)) {
    errors.push("dnsFiltering.lastAppliedProfile must be null or a supported DNS profile");
  }
  for (const [key, minimum] of Object.entries({
    processPollIntervalMs: 1000,
    persistencePollIntervalMs: 15000,
    eventPollIntervalMs: 5000,
    removablePollIntervalMs: 2000,
    firewallPollIntervalMs: 30000,
    ransomwareBurstWindowMs: 1000
  })) {
    if (!Number.isInteger(config.monitoring?.[key]) || config.monitoring[key] < minimum) {
      errors.push(`monitoring.${key} must be an integer of at least ${minimum}`);
    }
  }
  if (!Number.isInteger(config.monitoring?.ransomwareBurstEvents) ||
      config.monitoring.ransomwareBurstEvents < 25 ||
      config.monitoring.ransomwareBurstEvents > 100000) {
    errors.push("monitoring.ransomwareBurstEvents must be between 25 and 100000");
  }
  if (errors.length) throw new Error(`Invalid configuration: ${errors.join("; ")}`);
  return config;
}

export async function loadConfig() {
  const paths = appPaths();
  await ensureDirectory(paths.data);
  const stored = await readJson(paths.config, {});
  const storedSchema = Number(stored.schemaVersion) || 1;
  if (storedSchema > DEFAULT_CONFIG.schemaVersion) {
    throw new Error(
      `Configuration schema ${storedSchema} is newer than supported schema ${DEFAULT_CONFIG.schemaVersion}`
    );
  }
  const config = validateConfig(deepMerge(structuredClone(DEFAULT_CONFIG), stored));
  config.schemaVersion = DEFAULT_CONFIG.schemaVersion;
  const upgradeState = await readJson(paths.upgradeState, {});
  const versionChanged = upgradeState.currentVersion !== APP_VERSION;
  const configChanged = JSON.stringify(stored) !== JSON.stringify(config);
  if (Object.keys(stored).length && versionChanged) {
    await ensureDirectory(paths.upgradeBackups);
    const label = new Date().toISOString().replace(/[:.]/g, "-");
    const backup = path.join(
      paths.upgradeBackups,
      `config-${upgradeState.currentVersion || `schema-${storedSchema}`}-${label}.json`
    );
    await fs.copyFile(paths.config, backup);
  }
  if (!Object.keys(stored).length || configChanged) {
    await writeJsonAtomic(paths.config, config);
  }
  if (versionChanged) {
    await writeJsonAtomic(paths.upgradeState, {
      schemaVersion: 1,
      previousVersion: upgradeState.currentVersion || null,
      currentVersion: APP_VERSION,
      configSchemaVersion: config.schemaVersion,
      migratedAt: new Date().toISOString(),
      preservationPolicy: "retain-unless-versioned-migration",
      preservedCategories: [
        "settings",
        "enrollment-and-credentials",
        "quarantine",
        "audit-and-runtime-logs",
        "scan-history",
        "device-identity",
        "threat-intelligence",
        "dns-usb-and-firewall-state",
        "update-state"
      ]
    });
  }
  return config;
}

export async function saveConfig(update) {
  const current = await loadConfig();
  const merged = validateConfig(deepMerge(current, update));
  await writeJsonAtomic(appPaths().config, merged);
  return merged;
}
