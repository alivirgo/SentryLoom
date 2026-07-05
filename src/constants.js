import os from "node:os";
import path from "node:path";

export const APP_NAME = "SentryLoom Endpoint Security";
export const APP_VERSION = "0.16.9";

export function dataDirectory() {
  if (process.env.SENTRYLOOM_DATA_DIR) return path.resolve(process.env.SENTRYLOOM_DATA_DIR);
  if (process.platform === "win32" && process.env.PROGRAMDATA) {
    return path.join(process.env.PROGRAMDATA, "SentryLoom");
  }
  const base = process.env.LOCALAPPDATA || path.join(os.homedir(), ".local", "share");
  return path.join(base, "SentryLoom");
}

export function appPaths() {
  const data = dataDirectory();
  return {
    data,
    config: path.join(data, "config.json"),
    keys: path.join(data, "keys"),
    masterKey: path.join(data, "keys", "master.key"),
    quarantine: path.join(data, "quarantine"),
    quarantineIndex: path.join(data, "quarantine", "index.json"),
    quarantineIndexBackup: path.join(data, "quarantine", "index.last-good.json"),
    quarantineIndexLock: path.join(data, "quarantine", "index.lock"),
    logs: path.join(data, "logs"),
    auditLog: path.join(data, "logs", "audit.jsonl"),
    scanHistory: path.join(data, "scan-history.json"),
    importedSignatures: path.join(data, "signatures", "imported.json"),
    signatureKeys: path.join(data, "signatures", "trusted-keys.json"),
    threatIndex: path.join(data, "threat-intel", "threat-index.sqlite"),
    threatArtifacts: path.join(data, "threat-intel", "downloads"),
    threatCredentials: path.join(data, "keys", "threat-credentials.enc"),
    hqCredentials: path.join(data, "keys", "hq-credentials.enc"),
    hqPendingEnrollment: path.join(data, "keys", "hq-pending-enrollment.enc"),
    hqConnectorLock: path.join(data, "hq-connector.lock"),
    hqConnectorState: path.join(data, "hq-connector-state.json"),
    deviceIdentity: path.join(data, "device-identity.json"),
    clientUpdates: path.join(data, "updates"),
    clientUpdateStatus: path.join(data, "updates", "status.json"),
    dnsBackup: path.join(data, "dns", "adapter-backup.json"),
    usbPolicyBackup: path.join(data, "device-control", "usb-storage-policy.json"),
    canaryManifest: path.join(data, "monitoring", "canaries.json"),
    uiCommand: path.join(data, "ui-command.json"),
    dashboardRuntime: path.join(data, "dashboard-runtime.txt"),
    backgroundRuntime: path.join(data, "background-runtime.json"),
    backgroundOutput: path.join(data, "logs", "background-output.log"),
    backgroundOutputPrevious: path.join(data, "logs", "background-output.previous.log"),
    upgradeState: path.join(data, "upgrade-state.json"),
    upgradeBackups: path.join(data, "upgrade-backups")
  };
}

export const DEFAULT_CONFIG = Object.freeze({
  schemaVersion: 2,
  protection: {
    realtimeEnabled: true,
    monitorAllFixedDrives: true,
    downloadsDeepScanEnabled: true,
    networkMonitoringEnabled: true,
    dnsMonitoringEnabled: true,
    networkPollIntervalMs: 3000,
    dnsPollIntervalMs: 15000,
    autoQuarantineConfirmed: true,
    autoQuarantineHeuristics: false,
    scanOnDashboardStart: false
  },
  scanner: {
    maxFileBytes: 128 * 1024 * 1024,
    sampleBytes: 2 * 1024 * 1024,
    concurrency: 4,
    realtimeConcurrency: 2,
    maxPendingRealtimeFiles: 10000,
    clamavFileTimeoutMs: 2 * 60 * 1000,
    clamavDirectoryTimeoutMs: 30 * 60 * 1000,
    followSymbolicLinks: false,
    scanHiddenFiles: true,
    exclusions: []
  },
  dashboard: {
    host: "127.0.0.1",
    port: 3210
  },
  management: {
    enabled: false
  },
  schedule: {
    quickScan: "daily",
    fullScan: "weekly"
  },
  dnsFiltering: {
    selectedProfile: "adguard-default",
    lastAppliedProfile: null,
    lastAppliedAt: null
  },
  monitoring: {
    processEnabled: true,
    persistenceEnabled: true,
    ransomwareEnabled: true,
    windowsEventsEnabled: true,
    removableMediaEnabled: true,
    firewallIntegrityEnabled: true,
    firewallBlockHighConfidence: false,
    processPollIntervalMs: 3000,
    persistencePollIntervalMs: 60000,
    eventPollIntervalMs: 15000,
    removablePollIntervalMs: 5000,
    firewallPollIntervalMs: 120000,
    ransomwareBurstEvents: 250,
    ransomwareBurstWindowMs: 10000
  },
  threatIntel: {
    clamavEngineEnabled: true,
    sources: {
      clamav: true,
      malwarebazaar: true,
      urlhaus: true,
      feodotracker: true,
      threatfox: true
    },
    requestTimeoutMs: 120000,
    minimumUpdateIntervalMinutes: 15
  }
});

export const SEVERITY_RANK = Object.freeze({
  clean: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5
});
