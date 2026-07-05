import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { gzipSync } from "node:zlib";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { spawnSync } from "node:child_process";

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const sandboxes = [];

const {
  loadConfig
} = await import("../src/lib/config.js");
const {
  scanPath
} = await import("../src/lib/scanner.js");
const {
  quarantineFile,
  listQuarantine,
  restoreQuarantine,
  deleteQuarantine
} = await import("../src/lib/quarantine.js");
const {
  appendAudit,
  readRecentAudit,
  verifyAuditLog
} = await import("../src/lib/audit-log.js");
const {
  trustSignatureKey,
  importSignedBundle,
  loadSignatures
} = await import("../src/lib/signature-store.js");
const { AntivirusEngine } = await import("../src/lib/engine.js");
const { createDashboardServer } = await import("../src/server.js");
const { notificationForEvent } = await import("../src/lib/windows-notifications.js");
const { consumeUiCommand, validDashboardPage } = await import("../src/lib/ui-command.js");
const {
  RealtimeProtection,
  isDownloadsPath,
  waitForStableFile
} = await import("../src/lib/protection.js");
const { HqStore } = await import("../server/src/store.js");
const { createHqServer } = await import("../server/src/server.js");
const {
  acquireHqConnectorLease,
  discoverHqServers,
  hqDiscoveryBroadcastAddresses,
  HqConnector,
  pollHqEnrollment,
  probeHq,
  requestHqEnrollment
} = await import("../src/lib/hq-client.js");
const {
  loadHqCredentials,
  saveHqCredentials,
  loadPendingHqEnrollment
} = await import("../src/lib/hq-credential-store.js");

test("Windows endpoint processes default to one machine-wide data directory", {
  skip: process.platform !== "win32"
}, () => {
  const programData = path.join(os.tmpdir(), "sentryloom-program-data-contract");
  const result = spawnSync(process.execPath, [
    "--input-type=module",
    "--eval",
    "import { dataDirectory } from './src/constants.js'; process.stdout.write(dataDirectory());"
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      SENTRYLOOM_DATA_DIR: "",
      PROGRAMDATA: programData
    }
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, path.join(programData, "SentryLoom"));
});

test("Windows setup protects installed files behind bounded maintenance authorization", async () => {
  const [
    tamperScript,
    authorizationScript,
    registrationScript,
    removalScript,
    installer
  ] = await Promise.all([
    fs.readFile("Set-SentryLoomTamperProtection.ps1", "utf8"),
    fs.readFile("Authorize-SentryLoomMaintenance.ps1", "utf8"),
    fs.readFile("Register-SentryLoom.ps1", "utf8"),
    fs.readFile("Remove-SentryLoom.ps1", "utf8"),
    fs.readFile(path.join("installer", "SentryLoom.iss"), "utf8")
  ]);

  assert.match(tamperScript, /SetAccessRuleProtection\(\$true,\s*\$false\)/);
  assert.match(tamperScript, /S-1-5-18/);
  assert.match(tamperScript, /S-1-5-32-544/);
  assert.match(tamperScript, /AdministratorRights[\s\S]+ReadAndExecute/);
  assert.match(tamperScript, /Register-Relock[\s\S]+Register-ScheduledTask/);
  assert.match(tamperScript, /Refusing to change permissions through a reparse point/);
  assert.match(tamperScript, /Mode -eq 'Disable'[\s\S]+S-1-5-18/);

  assert.match(authorizationScript, /'file-maintenance'/);
  assert.match(authorizationScript, /if \(\$Result\.Accepted\)[\s\S]+Enable-AuthorizedFileMaintenance/);
  assert.match(authorizationScript, /Open Authorized File Maintenance[\s\S]+-UserId 'SYSTEM'/);
  assert.match(registrationScript, /Authorize SentryLoom File Maintenance\.lnk/);
  assert.match(registrationScript, /TamperHelper -Mode Apply/);
  assert.match(removalScript, /SentryLoom - Restore Tamper Protection/);

  assert.match(installer, /Set-SentryLoomTamperProtection\.ps1/);
  assert.match(installer, /InstalledAuthorizer[\s\S]+-Action file-maintenance/);
  assert.match(authorizationScript, /Identity\.User\.Value -eq 'S-1-5-18'/);
  assert.match(installer, /JsonStringValue\(RequestResult, 'verificationCode'\)/);
  assert.match(installer, /hq poll-pending-env/);
  assert.doesNotMatch(installer, /SENTRYLOOM_HQ_VERIFICATION_CODE/);
});

test("resident protection starts HQ management without opening the client UI", async () => {
  const cli = await fs.readFile(path.join("src", "cli.js"), "utf8");
  const protectionBody = cli.match(/async function protection\(\) \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(protectionBody, /await engine\.startProtection\(targets\);[\s\S]+await engine\.startManagement\(\);/);
});

test("Windows upgrades migrate enrolled user state into machine-wide storage", {
  skip: process.platform !== "win32"
}, async () => {
  const root = await sandbox("machine-state-migration");
  const localAppData = path.join(root, "user-local");
  const programData = path.join(root, "program-data");
  const legacy = path.join(localAppData, "SentryLoom");
  await fs.mkdir(path.join(legacy, "keys"), { recursive: true });
  await fs.writeFile(path.join(legacy, "config.json"), JSON.stringify({
    management: { enabled: true }
  }));
  await fs.writeFile(path.join(legacy, "keys", "hq-credentials.enc"), "encrypted-unit-state");
  await fs.writeFile(path.join(legacy, "device-identity.json"), JSON.stringify({
    deviceId: "preserved-device-identity"
  }));
  const result = spawnSync("powershell.exe", [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    path.resolve("Backup-SentryLoomState.ps1"),
    "-TargetVersion",
    "test"
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      LOCALAPPDATA: localAppData,
      PROGRAMDATA: programData
    }
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(
    await fs.readFile(
      path.join(programData, "SentryLoom", "keys", "hq-credentials.enc"),
      "utf8"
    ),
    "encrypted-unit-state"
  );
  assert.deepEqual(
    JSON.parse(await fs.readFile(
      path.join(programData, "SentryLoom", "device-identity.json"),
      "utf8"
    )),
    { deviceId: "preserved-device-identity" }
  );
});

test("HQ discovery targets every active IPv4 subnet and ignores internal adapters", () => {
  assert.deepEqual(hqDiscoveryBroadcastAddresses({
    Ethernet: [{
      address: "192.168.50.24",
      netmask: "255.255.255.0",
      family: "IPv4",
      internal: false
    }],
    Vpn: [{
      address: "10.44.7.9",
      netmask: "255.255.0.0",
      family: 4,
      internal: false
    }],
    Loopback: [{
      address: "127.0.0.1",
      netmask: "255.0.0.0",
      family: "IPv4",
      internal: true
    }]
  }), [
    "255.255.255.255",
    "127.0.0.1",
    "192.168.50.255",
    "10.44.255.255"
  ]);
});

test("HQ discovery cannot replace or clear enrolled credentials", async () => {
  await sandbox("discovery-read-only");
  const credentials = {
    serverUrl: "https://hq.example:8443",
    fingerprint256: "A".repeat(64),
    hqName: "Existing HQ",
    deviceId: crypto.randomUUID(),
    token: crypto.randomBytes(48).toString("base64url"),
    enrolledAt: new Date().toISOString()
  };
  await saveHqCredentials(credentials);
  await discoverHqServers({
    timeoutMs: 500,
    broadcastAddresses: []
  });
  assert.deepEqual(await loadHqCredentials(), credentials);
});

test("Setup preserves an approved enrollment instead of requesting it again", async () => {
  const root = await sandbox("setup-preserves-enrollment");
  const resultFile = path.join(root, "hq-request-result.json");
  const credentials = {
    serverUrl: "https://hq.example:8443",
    fingerprint256: "B".repeat(64),
    hqName: "Existing HQ",
    deviceId: crypto.randomUUID(),
    token: crypto.randomBytes(48).toString("base64url"),
    enrolledAt: new Date().toISOString()
  };
  await saveHqCredentials(credentials);
  const result = spawnSync(process.execPath, [
    "--disable-warning=ExperimentalWarning",
    "src/cli.js",
    "hq",
    "request-env"
  ], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      SENTRYLOOM_HQ_URL: credentials.serverUrl,
      SENTRYLOOM_HQ_RESULT_FILE: resultFile
    }
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Existing enrollment with Existing HQ preserved/);
  assert.deepEqual(JSON.parse(await fs.readFile(resultFile, "utf8")), {
    status: "preserved",
    hqName: credentials.hqName,
    serverUrl: credentials.serverUrl,
    deviceId: credentials.deviceId
  });
  assert.deepEqual(await loadHqCredentials(), credentials);
});

const {
  parseClamHashLine,
  parseClamCvd,
  malwareBazaarEntries,
  urlhausEntries,
  feodoTrackerEntries,
  threatFoxEntries
} = await import("../src/lib/threat-feeds.js");
const {
  scanWithClamAv
} = await import("../src/lib/clamav-engine.js");
const { withThreatDatabase } = await import("../src/lib/threat-index.js");
const {
  saveThreatCredentials,
  loadThreatCredentials,
  threatCredentialStatus
} = await import("../src/lib/credential-store.js");
const { updateThreatFeeds } = await import("../src/lib/threat-updater.js");
const { parseNetstatOutput } = await import("../src/lib/network-monitor.js");
const { parsePowerShellStringArray } = await import("../src/lib/windows-monitoring.js");
const { parseAdapterJson } = await import("../src/lib/windows-dns.js");
const { DNS_PROFILES, getDnsProfile } = await import("../src/lib/dns-profiles.js");
const {
  parseProcessSnapshot,
  parseTelemetryArray
} = await import("../src/lib/windows-telemetry.js");
const {
  persistenceExecutableCandidates
} = await import("../src/lib/scan-targets.js");
const {
  calculateSecurityPosture
} = await import("../src/lib/security-posture.js");
const {
  readScanHistory
} = await import("../src/lib/history.js");
const {
  parseUsbPolicyStatus
} = await import("../src/lib/windows-usb-control.js");
const {
  validatePickerKind
} = await import("../src/lib/windows-path-picker.js");
const {
  stageClientUpdate,
  validateClientUpdateManifest
} = await import("../src/lib/client-update.js");

async function sandbox(name) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), `sentryloom-${name}-`));
  sandboxes.push(root);
  process.env.SENTRYLOOM_DATA_DIR = path.join(root, "data");
  return root;
}

test.afterEach(async () => {
  while (sandboxes.length) {
    const root = path.resolve(sandboxes.pop());
    if (path.dirname(root) !== path.resolve(os.tmpdir()) || !path.basename(root).startsWith("sentryloom-")) {
      throw new Error(`Refusing to clean unexpected test path: ${root}`);
    }
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("client upgrades preserve stored settings and record a versioned migration", async () => {
  await sandbox("config-upgrade");
  const data = process.env.SENTRYLOOM_DATA_DIR;
  await fs.mkdir(data, { recursive: true });
  await fs.writeFile(path.join(data, "config.json"), JSON.stringify({
    schemaVersion: 1,
    protection: {
      realtimeEnabled: false
    },
    scanner: {
      exclusions: ["C:\\Preserve-Me"]
    }
  }));
  await fs.writeFile(path.join(data, "upgrade-state.json"), JSON.stringify({
    currentVersion: "0.16.1"
  }));
  const config = await loadConfig();
  assert.equal(config.schemaVersion, 2);
  assert.equal(config.protection.realtimeEnabled, false);
  assert.equal(config.protection.downloadsDeepScanEnabled, true);
  assert.deepEqual(config.scanner.exclusions, ["C:\\Preserve-Me"]);
  const migration = JSON.parse(await fs.readFile(path.join(data, "upgrade-state.json"), "utf8"));
  assert.equal(migration.previousVersion, "0.16.1");
  assert.equal(migration.currentVersion, "0.16.8");
  const backups = await fs.readdir(path.join(data, "upgrade-backups"));
  assert.equal(backups.some((name) => name.startsWith("config-0.16.1-")), true);
});

test("exact EICAR signature is confirmed and clean files remain clean", async () => {
  const root = await sandbox("scanner");
  const samples = path.join(root, "samples");
  await fs.mkdir(samples);
  await fs.writeFile(path.join(samples, "eicar.com"), EICAR);
  await fs.writeFile(path.join(samples, "notes.txt"), "ordinary project notes");
  const config = await loadConfig();
  const report = await scanPath(samples, { config: config.scanner });
  assert.equal(report.scanned, 2);
  assert.equal(report.detections, 1);
  const detection = report.results.find((item) => item.status === "detected");
  assert.equal(detection.sha256, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
  assert.equal(detection.findings.some((item) => item.name === "EICAR-Test-File" && item.confirmed), true);
});

test("double-extension heuristic reports but does not claim confirmation", async () => {
  const root = await sandbox("heuristic");
  await fs.writeFile(path.join(root, "invoice.pdf.exe"), "not an executable");
  const config = await loadConfig();
  const report = await scanPath(root, { config: config.scanner });
  const detection = report.results.find((item) => item.status === "detected");
  assert.equal(detection.findings.some((item) => item.id === "heuristic-double-extension"), true);
  assert.equal(detection.findings.every((item) => !item.confirmed), true);
});

test("FortiGuard published test markers are detected without executing samples", async () => {
  const root = await sandbox("fortiguard-tests");
  const samples = path.join(root, "samples");
  await fs.mkdir(samples);
  const sandboxSample = path.join(samples, "sandbox-test.bat");
  const outbreakSample = path.join(samples, "outbreak-test.com");
  await fs.writeFile(sandboxSample, 'echo "Fortinet FortiSandbox Suspicious Test File."');
  await fs.writeFile(outbreakSample, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$ZERO-HOUR-VIRUS-OUTBREAK-TEST-FILE!$H+H*");
  const config = await loadConfig();
  const report = await scanPath(samples, { config: config.scanner, clamavEngineEnabled: false });
  assert.equal(report.detections, 2);
  assert.equal(report.results.every((item) => item.findings.some((finding) => (
    finding.category === "test" && finding.confirmed
  ))), true);
});

test("native Python modules are recognized as executable containers", async () => {
  const root = await sandbox("pyd");
  const moduleFile = path.join(root, "native.cp312-win_amd64.pyd");
  await fs.writeFile(moduleFile, Buffer.concat([Buffer.from("MZ"), Buffer.alloc(4094)]));
  const config = await loadConfig();
  const report = await scanPath(moduleFile, { config: config.scanner });
  assert.equal(report.detections, 0);
  assert.equal(report.errors.length, 0);
});

test("quarantine encrypts, removes, restores, and permanently deletes files", async () => {
  const root = await sandbox("quarantine");
  const first = path.join(root, "sample.bin");
  await fs.writeFile(first, "quarantine round trip");
  const item = await quarantineFile(first, { sha256: "abc", findings: [{ name: "Test" }] });
  await assert.rejects(fs.access(first));
  const encrypted = path.join(process.env.SENTRYLOOM_DATA_DIR, "quarantine", item.storedFile);
  const container = await fs.readFile(encrypted);
  assert.equal(container.includes(Buffer.from("quarantine round trip")), false);
  const restored = await restoreQuarantine(item.id);
  assert.equal(restored, first);
  assert.equal(await fs.readFile(first, "utf8"), "quarantine round trip");

  const second = path.join(root, "delete.bin");
  await fs.writeFile(second, "delete me");
  const doomed = await quarantineFile(second);
  await deleteQuarantine(doomed.id);
  const records = await listQuarantine();
  assert.equal(records.find((entry) => entry.id === doomed.id).state, "deleted");
});

test("quarantine recovers a corrupt index from its last-known-good copy", async () => {
  const root = await sandbox("quarantine-index-recovery");
  const source = path.join(root, "recover.bin");
  await fs.writeFile(source, "preserve this encrypted item");
  const item = await quarantineFile(source, {
    sha256: "recovery-hash",
    findings: [{ name: "Recovery test" }]
  });
  const quarantine = path.join(process.env.SENTRYLOOM_DATA_DIR, "quarantine");
  const indexFile = path.join(quarantine, "index.json");
  await fs.writeFile(indexFile, Buffer.alloc(96));

  const records = await listQuarantine();
  const recovered = records.find((entry) => entry.id === item.id);
  assert.equal(recovered.state, "quarantined");
  assert.equal(recovered.originalPath, source);

  const repairedIndex = JSON.parse(await fs.readFile(indexFile, "utf8"));
  assert.equal(repairedIndex.recovery.source, "last-good-backup");
  assert.equal(repairedIndex.recovery.evidenceSha256.length, 64);
  const files = await fs.readdir(quarantine);
  assert.equal(files.some((name) => name.startsWith("index-evidence-") && name.endsWith(".bin")), true);
  const audit = await readRecentAudit(10);
  assert.equal(audit.some((record) => record.event === "quarantine.index-recovered"), true);
});

test("quarantine discovers encrypted containers when all index metadata is lost", async () => {
  const root = await sandbox("quarantine-orphan-recovery");
  const source = path.join(root, "orphan.bin");
  await fs.writeFile(source, "orphaned encrypted item");
  const item = await quarantineFile(source);
  const quarantine = path.join(process.env.SENTRYLOOM_DATA_DIR, "quarantine");
  await fs.rm(path.join(quarantine, "index.last-good.json"));
  await fs.writeFile(path.join(quarantine, "index.json"), Buffer.from([0, 0, 0, 0, 1, 2, 3]));

  const records = await listQuarantine();
  const recovered = records.find((entry) => entry.id === item.id);
  assert.equal(recovered.state, "orphaned");
  assert.equal(recovered.metadataLost, true);
  assert.equal(recovered.storedFile, item.storedFile);

  await deleteQuarantine(item.id);
  await assert.rejects(fs.access(path.join(quarantine, item.storedFile)));
});

test("detection events produce actionable quarantine notifications", () => {
  const file = notificationForEvent({
    id: "event-1",
    type: "detection",
    result: {
      path: "C:\\Downloads\\sample.exe",
      sha256: "abc",
      findings: [{ name: "Win.Test.Sample" }]
    }
  });
  assert.equal(file.title, "Threat detected");
  assert.equal(file.page, "quarantine");
  assert.match(file.message, /sample\.exe/);

  const scan = notificationForEvent({
    type: "scan.completed",
    result: { id: "scan-1", type: "custom", detections: 2 }
  });
  assert.equal(scan.page, "quarantine");
  assert.match(scan.title, /2 threats detected/);
  assert.equal(notificationForEvent({
    type: "scan.completed",
    result: { id: "scan-2", detections: 0 }
  }), null);

  const disconnected = notificationForEvent({
    type: "hq.connection-lost",
    serverUrl: "https://hq.example",
    error: "Network unreachable"
  });
  assert.equal(disconnected.page, "settings");
  assert.equal(disconnected.severity, "Warning");
  assert.match(disconnected.message, /reconnection is automatic/i);

  const failed = notificationForEvent({
    type: "scan.failed",
    error: "Access denied"
  });
  assert.equal(failed.page, "scan");
  assert.equal(failed.severity, "Error");
});

test("HQ connector backs off, reports outages, and reconnects after resume", async () => {
  const events = [];
  const states = [];
  let failing = true;
  const connector = new HqConnector({
    serverUrl: "https://hq.example",
    fingerprint256: "A".repeat(64),
    hqName: "Test HQ",
    deviceId: crypto.randomUUID(),
    token: "token",
    enrolledAt: new Date().toISOString()
  }, {
    intervalMs: 1000,
    telemetryIntervalMs: 2000,
    maximumRetryMs: 8000,
    failureThreshold: 2,
    resumeThresholdMs: 5000,
    metricsProvider: async () => ({ security: { score: 100 } }),
    commandExecutor: async () => ({}),
    onEvent: (event) => events.push(event),
    stateWriter: async (state) => states.push(state)
  });
  connector.request = async (route) => {
    if (failing) throw new Error("Network unreachable");
    return route.endsWith("/commands") ? { commands: [] } : {};
  };
  connector.running = true;

  assert.equal(await connector.pulse(), 1000);
  assert.equal(connector.status().connectionState, "reconnecting");
  assert.equal(await connector.pulse(), 2000);
  assert.equal(connector.status().connectionState, "offline");
  assert.equal(events.filter((event) => event.type === "hq.connection-lost").length, 1);

  failing = false;
  assert.equal(await connector.pulse(), 1000);
  assert.equal(connector.status().connected, true);
  assert.equal(events.filter((event) => event.type === "hq.connection-restored").length, 1);

  connector.lastPulseAt = Date.now() - 10000;
  await connector.pulse();
  assert.equal(events.some((event) => event.type === "system.resume-detected"), true);
  assert.equal(states.at(-1).connectionState, "online");
  connector.stop();
});

test("UI navigation commands are validated and consumed once", async () => {
  const root = await sandbox("ui-command");
  const commandFile = path.join(root, "data", "ui-command.json");
  await fs.mkdir(path.dirname(commandFile), { recursive: true });
  await fs.writeFile(commandFile, JSON.stringify({
    page: "quarantine",
    requestedAt: "2026-07-03T00:00:00.000Z"
  }));
  assert.equal(validDashboardPage("quarantine"), "quarantine");
  assert.equal(validDashboardPage("unknown", "overview"), "overview");
  assert.deepEqual(await consumeUiCommand(), {
    page: "quarantine",
    requestedAt: "2026-07-03T00:00:00.000Z"
  });
  assert.equal(await consumeUiCommand(), null);
});

test("Downloads deep protection stabilizes files and uses the full scan pipeline", async () => {
  const root = await sandbox("downloads-deep");
  const downloads = path.join(root, "Downloads");
  const sample = path.join(downloads, "new-download.exe");
  await fs.mkdir(downloads, { recursive: true });
  await fs.writeFile(sample, "downloaded content");

  assert.equal(isDownloadsPath(sample, downloads), true);
  assert.equal(isDownloadsPath(path.join(root, "Desktop", "other.exe"), downloads), false);
  assert.equal((await waitForStableFile(sample, { intervalMs: 25, stableChecks: 1 })).isFile(), true);

  const config = await loadConfig();
  config.protection.downloadsDeepScanEnabled = true;
  config.protection.autoQuarantineConfirmed = false;
  config.protection.autoQuarantineHeuristics = false;
  const events = [];
  let deepOptions = null;
  const protection = new RealtimeProtection(config, (event) => events.push(event), {
    stabilizeFile: (file) => fs.lstat(file),
    deepScanPath: async (_file, options) => {
      deepOptions = options;
      return {
        scanned: 1,
        errors: [],
        results: [{
          path: sample,
          status: "detected",
          findings: [{ name: "Deep-Test", confirmed: true }]
        }]
      };
    }
  });
  protection.downloadsTarget = downloads;
  await protection.inspect(sample, { deep: true });

  assert.equal(deepOptions.clamavEngineEnabled, config.threatIntel.clamavEngineEnabled);
  assert.equal(events.some((event) =>
    event.type === "detection" && event.source === "downloads-deep-scan"), true);
  assert.equal(protection.status().downloadsDeepScan.filesInspected, 1);
  assert.equal(protection.status().downloadsDeepScan.detections, 1);
});

test("managed client replaces a preserved HQ target, encrypts enrollment, and executes allowlisted commands", async () => {
  const root = await sandbox("hq-client");
  process.env.SENTRYLOOM_ALLOW_INSECURE_HQ = "1";
  const store = await new HqStore(path.join(root, "hq.sqlite")).open();
  const hq = await createHqServer({
    hqName: "Test HQ",
    host: "127.0.0.1",
    port: 0,
    databasePath: path.join(root, "hq.sqlite"),
    tls: { fingerprint256: "" },
    admin: {
      salt: Buffer.alloc(16).toString("base64"),
      iterations: 1000,
      passwordHash: Buffer.alloc(32).toString("base64")
    },
    discovery: { enabled: false, port: 32110 },
    telemetryRetentionDays: 30
  }, { store, httpOnly: true });
  const address = await hq.listen("127.0.0.1", 0);
  try {
    await saveHqCredentials({
      serverUrl: "http://192.168.1.9:8443",
      fingerprint256: "",
      hqName: "Previous HQ",
      deviceId: crypto.randomUUID(),
      token: crypto.randomBytes(32).toString("base64url"),
      enrolledAt: new Date().toISOString()
    });
    const oldConnectorState = path.join(
      process.env.SENTRYLOOM_DATA_DIR,
      "hq-connector-state.json"
    );
    await fs.mkdir(path.dirname(oldConnectorState), { recursive: true });
    await fs.writeFile(oldConnectorState, JSON.stringify({
      serverUrl: "http://192.168.1.9:8443",
      updatedAt: new Date().toISOString()
    }));
    assert.equal((await loadHqCredentials()).serverUrl, "http://192.168.1.9:8443");
    await saveThreatCredentials({ abuseChAuthKey: "legacy-local-auth-key-123456" });
    const identity = await probeHq(`http://127.0.0.1:${address.port}`, { allowHttp: true });
    assert.equal(identity.hqName, "Test HQ");
    let pending = await requestHqEnrollment({
      serverUrl: `http://127.0.0.1:${address.port}`,
      allowHttp: true
    });
    assert.match(pending.verificationCode, /^\d{6}$/);
    const listedRequest = store.listEnrollmentRequests()
      .find((item) => item.id === pending.requestId);
    assert.equal(listedRequest.device.verificationCode, undefined);
    assert.equal(listedRequest.device.verificationChallenge, undefined);
    assert.equal(listedRequest.device.verificationProof, undefined);
    assert.equal(listedRequest.verificationRequired, true);
    assert.equal(
      await loadHqCredentials(),
      null,
      "the newly requested HQ must replace preserved credentials for a previous server"
    );
    assert.deepEqual(
      await loadThreatCredentials(),
      {},
      "managed enrollment must remove any locally stored abuse.ch key"
    );
    assert.equal(pending.serverUrl, `http://127.0.0.1:${address.port}`);
    await assert.rejects(fs.stat(oldConnectorState), { code: "ENOENT" });
    const request = store.listEnrollmentRequests().find((item) => item.id === pending.requestId);
    assert.equal(request.status, "pending");
    store.reviewEnrollmentRequest(pending.requestId, true, "000000" === pending.verificationCode ? "000001" : "000000");
    await assert.rejects(
      pollHqEnrollment(pending),
      /wrong verification code/
    );
    assert.equal(await loadHqCredentials(), null);

    pending = await requestHqEnrollment({
      serverUrl: `http://127.0.0.1:${address.port}`,
      allowHttp: true
    });
    store.reviewEnrollmentRequest(pending.requestId, true, pending.verificationCode);
    const approval = await pollHqEnrollment(pending);
    assert.equal(approval.status, "approved");
    const credentials = approval.credentials;
    assert.equal((await loadHqCredentials()).deviceId, credentials.deviceId);
    const encrypted = await fs.readFile(path.join(
      process.env.SENTRYLOOM_DATA_DIR,
      "keys",
      "hq-credentials.enc"
    ));
    assert.equal(encrypted.includes(Buffer.from(credentials.token)), false);

    store.createCommand(credentials.deviceId, "scan.quick", {});
    let executed = 0;
    const connector = new HqConnector(credentials, {
      allowHttp: true,
      metricsProvider: async () => ({ security: { score: 96, quarantineCount: 0 } }),
      commandExecutor: async (command) => {
        assert.equal(command.type, "scan.quick");
        executed += 1;
        return { scanned: 4, detections: 0 };
      }
    });
    connector.running = true;
    await connector.pulse();
    assert.equal(connector.status().enrolled, true);
    assert.equal(connector.status().hqVersion, "0.4.4");
    assert.equal(connector.status().maintenanceAuthorizationSupported, true);
    assert.equal(connector.status().abuseChGatewayConfigured, false);
    for (let attempt = 0; attempt < 20 &&
         store.listCommands(credentials.deviceId)[0].status !== "completed"; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    connector.stop();
    assert.equal(executed, 1);
    assert.equal(store.listCommands(credentials.deviceId)[0].status, "completed");
    assert.equal(store.listDevices()[0].status.security.score, 96);
  } finally {
    delete process.env.SENTRYLOOM_ALLOW_INSECURE_HQ;
    await hq.close();
    store.close();
  }
});

test("only one local process lease can own the HQ connector", async () => {
  await sandbox("hq-lease");
  const release = await acquireHqConnectorLease();
  assert.equal(typeof release, "function");
  assert.equal(await acquireHqConnectorLease(), null);
  await release();
  const reacquired = await acquireHqConnectorLease();
  assert.equal(typeof reacquired, "function");
  await reacquired();
});

test("terminal enrollment failures release the background management lease", async () => {
  const root = await sandbox("hq-terminal-lease");
  process.env.SENTRYLOOM_ALLOW_INSECURE_HQ = "1";
  const databasePath = path.join(root, "hq.sqlite");
  const store = await new HqStore(databasePath).open();
  const hq = await createHqServer({
    hqName: "Terminal Test HQ",
    host: "127.0.0.1",
    port: 0,
    databasePath,
    tls: { fingerprint256: "" },
    admin: {
      salt: Buffer.alloc(16).toString("base64"),
      iterations: 1000,
      passwordHash: Buffer.alloc(32).toString("base64"),
      sessionHours: 12,
      maxLoginAttempts: 10
    },
    discovery: { enabled: false, port: 32110 },
    telemetryRetentionDays: 30,
    alerts: { offlineAfterSeconds: 60 },
    maintenance: { defaultMinutes: 10, defaultUses: 1 },
    updates: {}
  }, { store, httpOnly: true });
  const address = await hq.listen("127.0.0.1", 0);
  try {
    const pending = await requestHqEnrollment({
      serverUrl: `http://127.0.0.1:${address.port}`,
      allowHttp: true,
      verificationCode: "123456"
    });
    store.reviewEnrollmentRequest(pending.requestId, true, "654321");

    const engine = await new AntivirusEngine().initialize();
    await engine.updateConfig({ management: { enabled: true } });
    await engine.startManagement();
    assert.ok(engine.hqLeaseRelease);
    assert.ok(engine.hqEnrollmentPoller);

    engine.hqEnrollmentPoller.stop();
    engine.hqEnrollmentPoller.running = true;
    await engine.hqEnrollmentPoller.pulse();

    assert.equal(engine.hqEnrollmentPoller, null);
    assert.equal(engine.hqLeaseRelease, null);
    assert.equal((await engine.getHqStatus()).verificationFailed, true);
    assert.ok(engine.events.some((event) =>
      event.type === "hq.enrollment-verification-failed"
    ));
  } finally {
    delete process.env.SENTRYLOOM_ALLOW_INSECURE_HQ;
    await hq.close();
    store.close();
  }
});

test("CLI writes sanitized setup diagnostics when HQ enrollment cannot start", async () => {
  const root = await sandbox("hq-diagnostics");
  const failureLog = path.join(root, "hq-error.txt");
  const environment = {
    ...process.env,
    SENTRYLOOM_FAILURE_LOG: failureLog,
    SENTRYLOOM_HQ_URL: "",
    SENTRYLOOM_HQ_ENROLLMENT_CODE: "",
    SENTRYLOOM_HQ_FINGERPRINT: ""
  };
  const result = spawnSync(process.execPath, [
    "--disable-warning=ExperimentalWarning",
    path.resolve("src", "cli.js"),
    "hq",
    "enroll-env"
  ], {
    cwd: path.resolve("."),
    env: environment,
    encoding: "utf8",
    windowsHide: true
  });
  assert.equal(result.status, 1);
  const diagnostic = await fs.readFile(failureLog, "utf8");
  assert.match(diagnostic, /SENTRYLOOM_HQ_URL.*required/);
  assert.doesNotMatch(diagnostic, /token|enrollment code:/i);
});

test("audit log detects tampering", async () => {
  await sandbox("audit");
  await appendAudit("test.one", { safe: true });
  await appendAudit("test.two", { safe: true });
  assert.deepEqual(await verifyAuditLog(), { valid: true, records: 2 });
  const auditFile = path.join(process.env.SENTRYLOOM_DATA_DIR, "logs", "audit.jsonl");
  const content = await fs.readFile(auditFile, "utf8");
  await fs.writeFile(auditFile, content.replace('"safe":true', '"safe":false'));
  const result = await verifyAuditLog();
  assert.equal(result.valid, false);
  assert.equal(result.failedAt, 1);
});

test("malformed audit chains are archived as hashed evidence and protection continues", async () => {
  const root = await sandbox("audit-recovery");
  const logs = path.join(root, "data", "logs");
  await fs.mkdir(logs, { recursive: true });
  const damaged = "'malformed audit tail";
  await fs.writeFile(path.join(logs, "audit.jsonl"), damaged, "utf8");
  const engine = await new AntivirusEngine().initialize();
  assert.ok(engine);
  const verification = await verifyAuditLog();
  assert.equal(verification.valid, true);
  assert.equal(verification.recovered, true);
  assert.equal(verification.originalFailedAt, 1);
  assert.equal(verification.originalFailureReason, "malformed-record");
  assert.equal(
    verification.evidenceSha256,
    crypto.createHash("sha256").update(damaged, "utf8").digest("hex")
  );
  assert.equal(await fs.readFile(path.join(logs, verification.evidenceFile), "utf8"), damaged);
  const recent = await readRecentAudit(10);
  assert.equal(recent.some((record) => record.event === "audit.chain-recovered"), true);
  assert.equal(recent.some((record) => record.event === "application.initialized"), true);
});

test("audit chain mismatches are archived before a new valid chain is written", async () => {
  const root = await sandbox("audit-mismatch-recovery");
  await appendAudit("test.one", { safe: true });
  await appendAudit("test.two", { safe: true });
  const auditFile = path.join(root, "data", "logs", "audit.jsonl");
  const damaged = (await fs.readFile(auditFile, "utf8")).replace('"safe":true', '"safe":false');
  await fs.writeFile(auditFile, damaged, "utf8");
  assert.equal((await verifyAuditLog()).valid, false);
  await new AntivirusEngine().initialize();
  const verification = await verifyAuditLog();
  assert.equal(verification.valid, true);
  assert.equal(verification.recovered, true);
  assert.equal(verification.originalFailureReason, "chain-mismatch");
  assert.equal(await fs.readFile(path.join(root, "data", "logs", verification.evidenceFile), "utf8"), damaged);
});

test("only bundles signed by a trusted Ed25519 key can update signatures", async () => {
  const root = await sandbox("signatures");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicFile = path.join(root, "public.pem");
  await fs.writeFile(publicFile, publicKey.export({ type: "spki", format: "pem" }));
  await trustSignatureKey("test-key", publicFile);
  const database = {
    schemaVersion: 1,
    version: "test.1",
    hashes: [],
    patterns: [{
      id: "local-test",
      name: "Local-Test",
      kind: "literal",
      pattern: "LOCAL-SIGNATURE-TEST",
      severity: "medium",
      confirmed: false,
      category: "test",
      extensions: []
    }]
  };
  const payload = Buffer.from(JSON.stringify(database));
  const bundle = {
    keyId: "test-key",
    payload: payload.toString("base64"),
    signature: crypto.sign(null, payload, privateKey).toString("base64")
  };
  const bundleFile = path.join(root, "bundle.json");
  await fs.writeFile(bundleFile, JSON.stringify(bundle));
  assert.equal((await importSignedBundle(bundleFile)).version, "test.1");
  assert.equal((await loadSignatures()).patterns.some((entry) => entry.id === "local-test"), true);
  bundle.signature = Buffer.alloc(64).toString("base64");
  await fs.writeFile(bundleFile, JSON.stringify(bundle));
  await assert.rejects(importSignedBundle(bundleFile), /verification failed/);
});

test("dashboard requires a launch session and CSRF for writes", async () => {
  const root = await sandbox("server");
  await fs.mkdir(path.join(root, "data", "logs"), { recursive: true });
  await fs.writeFile(
    path.join(root, "data", "logs", "background-output.log"),
    "background command completed\n"
  );
  await fs.writeFile(
    path.join(root, "data", "background-runtime.json"),
    JSON.stringify({
      launcherPid: 100,
      workerPid: 101,
      updatedAt: new Date(Date.now() + 60000).toISOString()
    })
  );
  const engine = await new AntivirusEngine().initialize();
  await fs.writeFile(
    path.join(root, "data", "background-runtime.json"),
    JSON.stringify({
      launcherPid: 100,
      workerPid: 101,
      updatedAt: new Date(Date.now() + 60000).toISOString()
    })
  );
  await fs.mkdir(path.join(root, "data", "quarantine"), { recursive: true });
  await fs.writeFile(
    path.join(root, "data", "quarantine", "index.json"),
    Buffer.alloc(128)
  );
  const dashboard = createDashboardServer(engine);
  const address = await dashboard.listen("127.0.0.1", 0);
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const denied = await fetch(`${origin}/api/status`);
    assert.equal(denied.status, 401);
    const sessionResponse = await fetch(`${origin}/session?token=${dashboard.launchToken}`, { redirect: "manual" });
    assert.equal(sessionResponse.status, 302);
    assert.equal(sessionResponse.headers.get("location"), "/");
    const notificationSession = await fetch(
      `${origin}/session?token=${dashboard.launchToken}&page=quarantine`,
      { redirect: "manual" }
    );
    assert.equal(notificationSession.headers.get("location"), "/?page=quarantine");
    const cookie = sessionResponse.headers.get("set-cookie").split(";")[0];
    const bootstrapResponse = await fetch(`${origin}/api/bootstrap`, { headers: { Cookie: cookie } });
    assert.equal(bootstrapResponse.status, 200);
    const bootstrap = await bootstrapResponse.json();
    const uiResponse = await fetch(origin, { headers: { Cookie: cookie } });
    const ui = await uiResponse.text();
    assert.match(ui, /id="enroll-hq"[^>]*>Save server and request approval<\/button>/);
    assert.match(ui, /id="submit-maintenance-password"[^>]*>Submit password for next change<\/button>/);
    const appResponse = await fetch(`${origin}/app.js`, { headers: { Cookie: cookie } });
    const appSource = await appResponse.text();
    assert.match(appSource, /Discovery completed without changing the active HQ/);
    const iconResponse = await fetch(`${origin}/sentryloom-icon.png`, { headers: { Cookie: cookie } });
    assert.equal(iconResponse.status, 200);
    assert.equal(iconResponse.headers.get("content-type"), "image/png");
    assert.deepEqual(
      Buffer.from(await iconResponse.arrayBuffer()).subarray(0, 8),
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    );
    const quarantineResponse = await fetch(`${origin}/api/quarantine`, { headers: { Cookie: cookie } });
    assert.equal(quarantineResponse.status, 200);
    assert.deepEqual(await quarantineResponse.json(), []);
    const backgroundResponse = await fetch(`${origin}/api/background-output`, {
      headers: { Cookie: cookie }
    });
    const background = await backgroundResponse.json();
    assert.equal(backgroundResponse.status, 200);
    assert.equal(background.running, true);
    assert.equal(background.workerPid, 101);
    assert.match(background.current.text, /background command completed/);
    const rejectedWrite = await fetch(`${origin}/api/scans/cancel`, { method: "POST", headers: { Cookie: cookie } });
    assert.equal(rejectedWrite.status, 403);
    const acceptedWrite = await fetch(`${origin}/api/scans/cancel`, {
      method: "POST",
      headers: { Cookie: cookie, "X-SentryLoom-CSRF": bootstrap.csrf }
    });
    assert.equal(acceptedWrite.status, 409);
  } finally {
    await dashboard.close();
  }
});

test("managed HQ server changes require maintenance authorization", async () => {
  const calls = [];
  let hqStatus = { enrolled: true };
  const engine = {
    async getDashboardData() {
      return {};
    },
    async getHqStatus() {
      return hqStatus;
    },
    async authorizeMaintenance(password, action) {
      calls.push({ type: "authorize", password, action });
      if (password !== "valid-maintenance-password") {
        throw new Error("Maintenance password is invalid, expired, used, or revoked");
      }
    },
    async requestHqEnrollment(options) {
      calls.push({ type: "request", options });
      return {
        pending: true,
        hqName: "Replacement HQ",
        serverUrl: options.serverUrl
      };
    },
    async reEnrollHq() {
      calls.push({ type: "reenroll" });
      return {
        pending: true,
        hqName: "Original HQ",
        serverUrl: "https://original-hq:8443"
      };
    },
    async disconnectHq() {
      calls.push({ type: "disconnect" });
      return { enrolled: false, pending: false };
    }
  };
  const dashboard = createDashboardServer(engine);
  const address = await dashboard.listen("127.0.0.1", 0);
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const sessionResponse = await fetch(
      `${origin}/session?token=${dashboard.launchToken}`,
      { redirect: "manual" }
    );
    const cookie = sessionResponse.headers.get("set-cookie").split(";")[0];
    const bootstrapResponse = await fetch(`${origin}/api/bootstrap`, {
      headers: { Cookie: cookie }
    });
    const { csrf } = await bootstrapResponse.json();
    const submit = (
      maintenancePassword,
      serverUrl = "https://replacement-hq:8443",
      reEnroll = false
    ) =>
      fetch(`${origin}/api/hq/request`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/json",
        "X-SentryLoom-CSRF": csrf
      },
      body: JSON.stringify({
        serverUrl,
        fingerprint256: "A".repeat(64),
        reEnroll,
        maintenancePassword
      })
    });

    const invalidTarget = await submit("valid-maintenance-password", "not-a-server-url");
    assert.equal(invalidTarget.status, 500);
    assert.match((await invalidTarget.json()).error, /Invalid URL/);
    assert.deepEqual(calls, [], "invalid targets must not consume a maintenance password");

    const denied = await submit("wrong-password");
    assert.equal(denied.status, 500);
    assert.match((await denied.json()).error, /invalid, expired, used, or revoked/);
    assert.deepEqual(calls, [{
      type: "authorize",
      password: "wrong-password",
      action: "change-hq-server"
    }]);

    const accepted = await submit("valid-maintenance-password");
    assert.equal(accepted.status, 202);
    assert.equal((await accepted.json()).serverUrl, "https://replacement-hq:8443");
    assert.deepEqual(calls.slice(1), [
      {
        type: "authorize",
        password: "valid-maintenance-password",
        action: "change-hq-server"
      },
      {
        type: "request",
        options: {
          serverUrl: "https://replacement-hq:8443",
          fingerprint256: "A".repeat(64)
        }
      }
    ]);

    calls.length = 0;
    hqStatus = {
      enrolled: true,
      reEnrollmentRequired: true,
      serverUrl: "https://original-hq:8443"
    };
    const wrongReEnrollmentTarget = await submit(
      "",
      "https://replacement-hq:8443",
      true
    );
    assert.equal(wrongReEnrollmentTarget.status, 409);
    assert.deepEqual(calls, []);

    const reEnrollment = await submit("", "https://original-hq:8443", true);
    assert.equal(reEnrollment.status, 202);
    assert.deepEqual(calls, [{ type: "reenroll" }]);

    calls.length = 0;
    hqStatus = { enrolled: false, pending: true };
    const cancelledPending = await fetch(`${origin}/api/hq/disconnect`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        "Content-Type": "application/json",
        "X-SentryLoom-CSRF": csrf
      },
      body: "{}"
    });
    assert.equal(cancelledPending.status, 200);
    assert.deepEqual(calls, [{ type: "disconnect" }]);
  } finally {
    await dashboard.close();
  }
});

test("threat feed parsers preserve source confidence policy", () => {
  const clam = parseClamHashLine(`${"a".repeat(64)}:12:Win.Malware.UnitTest`);
  assert.equal(clam.algorithm, "sha256");
  assert.equal(clam.confirmed, true);
  const bazaar = malwareBazaarEntries({
    query_status: "ok",
    data: [{
      sha256_hash: "b".repeat(64),
      sha1_hash: "c".repeat(40),
      md5_hash: "d".repeat(32),
      file_size: 25,
      signature: "UnitFamily",
      first_seen: "2026-01-01"
    }]
  });
  assert.equal(bazaar.length, 3);
  assert.equal(bazaar.every((entry) => entry.confirmed), true);
  const urlhaus = urlhausEntries({
    query_status: "ok",
    payloads: [{ sha256_hash: "e".repeat(64), md5_hash: "f".repeat(32), file_size: 30 }]
  });
  assert.equal(urlhaus.length, 2);
  assert.equal(urlhaus.every((entry) => !entry.confirmed), true);
});

test("Feodo Tracker and ThreatFox split network IOCs from file hashes", () => {
  const feodo = feodoTrackerEntries([{
    ip_address: "203.0.113.10",
    port: 443,
    status: "online",
    malware: "QakBot",
    first_seen: "2026-01-01",
    last_online: "2026-01-02"
  }]);
  assert.equal(feodo.hashes.length, 0);
  assert.equal(feodo.iocs[0].type, "ipv4");
  assert.equal(feodo.iocs[0].confidence, 100);

  const threatFox = threatFoxEntries({
    query_status: "ok",
    data: [
      {
        ioc: "a".repeat(64),
        ioc_type: "sha256_hash",
        malware_printable: "UnitMalware",
        confidence_level: 90
      },
      {
        ioc: "c2.example.test",
        ioc_type: "domain",
        malware_printable: "UnitMalware",
        confidence_level: 80
      }
    ]
  });
  assert.equal(threatFox.hashes.length, 1);
  assert.equal(threatFox.hashes[0].confirmed, true);
  assert.equal(threatFox.iocs.length, 1);
  assert.equal(threatFox.iocs[0].value, "c2.example.test");
});

test("ClamAV CVD parser verifies integrity and extracts file hashes", async () => {
  const root = await sandbox("cvd");
  const signature = `${"1".repeat(32)}:68:Win.Test.Cvd\n`;
  const content = Buffer.from(signature);
  const header = Buffer.alloc(512);
  header.write("test.hdb");
  header.write("0000644\0", 100);
  header.write("0000000\0", 108);
  header.write("0000000\0", 116);
  header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124);
  header.write("00000000000\0", 136);
  header.fill(0x20, 148, 156);
  header.write("0", 156);
  header.write("ustar\0", 257);
  header.write("00", 263);
  const checksum = [...header].reduce((sum, byte) => sum + byte, 0);
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148);
  const padding = Buffer.alloc((512 - (content.length % 512)) % 512);
  const tar = Buffer.concat([header, content, padding, Buffer.alloc(1024)]);
  const compressed = gzipSync(tar);
  const cvdHeaderText = `ClamAV-VDB:01 Jul 2026:1:1:1:${crypto.createHash("md5").update(compressed).digest("hex")}:signature:unit:0`;
  const cvdHeader = Buffer.alloc(512, 0x20);
  cvdHeader.write(cvdHeaderText);
  const file = path.join(root, "unit.cvd");
  await fs.writeFile(file, Buffer.concat([cvdHeader, compressed]));
  const entries = [];
  const result = await parseClamCvd(file, (entry) => entries.push(entry));
  assert.equal(result.version, "1");
  assert.equal(result.imported, 1);
  assert.equal(entries[0].name, "Win.Test.Cvd");
});

test("indexed threat hashes participate in the next local scan", async () => {
  const root = await sandbox("threat-index");
  const sample = path.join(root, "sample.bin");
  const content = Buffer.from("known threat index fixture");
  await fs.writeFile(sample, content);
  const sha256 = crypto.createHash("sha256").update(content).digest("hex");
  await withThreatDatabase((database) => {
    database.prepare(`
      INSERT INTO threat_hashes
        (algorithm, hash, size, name, source, severity, confirmed, details, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run("sha256", sha256, content.length, "MalwareBazaar.UnitFamily", "malwarebazaar", "critical", 1, null, new Date().toISOString());
  });
  const config = await loadConfig();
  const report = await scanPath(sample, { config: config.scanner });
  assert.equal(report.detections, 1);
  const finding = report.results[0].findings.find((entry) => entry.source === "malwarebazaar");
  assert.equal(finding.name, "MalwareBazaar.UnitFamily");
  assert.equal(finding.confirmed, true);
});

test("abuse.ch credential is encrypted at rest", async () => {
  await sandbox("credentials");
  const key = "unit-test-auth-key-123456789";
  await saveThreatCredentials({ abuseChAuthKey: key });
  assert.deepEqual(await threatCredentialStatus(), { abuseChConfigured: true });
  assert.equal((await loadThreatCredentials()).abuseChAuthKey, key);
  const encrypted = await fs.readFile(path.join(process.env.SENTRYLOOM_DATA_DIR, "keys", "threat-credentials.enc"));
  assert.equal(encrypted.includes(Buffer.from(key)), false);
});

test("managed clients update authenticated abuse.ch feeds through HQ without a local key", async () => {
  await sandbox("hq-threat-gateway");
  let requestedSource = null;
  const result = await updateThreatFeeds({
    sources: ["malwarebazaar"],
    config: { requestTimeoutMs: 10000, minimumUpdateIntervalMinutes: 0 },
    credentials: {},
    hqCredentials: {
      serverUrl: "https://hq.example.test:8443",
      fingerprint256: "A".repeat(64),
      deviceId: crypto.randomUUID(),
      token: "t".repeat(48)
    },
    hqFetchImpl: async (unusedCredentials, source) => {
      requestedSource = source;
      return {
        query_status: "ok",
        data: [{
          sha256_hash: "a".repeat(64),
          sha1_hash: "b".repeat(40),
          md5_hash: "c".repeat(32),
          file_size: 1234,
          signature: "UnitGateway"
        }]
      };
    },
    force: true
  });
  assert.equal(requestedSource, "malwarebazaar");
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].imported, 3);
  assert.deepEqual(await loadThreatCredentials(), {});
});

test("managed client UI identifies server-maintained abuse.ch access", async () => {
  const [html, app] = await Promise.all([
    fs.readFile(path.join("src", "ui", "index.html"), "utf8"),
    fs.readFile(path.join("src", "ui", "app.js"), "utf8")
  ]);
  assert.match(html, /id="abuse-auth-key-state"/);
  assert.match(app, /Auth-Key is added and maintained by SentryLoom HQ/);
  assert.match(app, /key is never sent to or stored on this client/);
});

test("provider rate limits skip without degrading a healthy feed state", async () => {
  await sandbox("rate-limit");
  const timestamp = new Date().toISOString();
  await withThreatDatabase((database) => {
    database.prepare(`
      INSERT INTO feed_status
        (source, state, last_attempt, last_success, version, entry_count, last_import_count, error, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run("clamav", "ready", timestamp, timestamp, "unit", 10, 10, null, null);
  });
  const result = await updateThreatFeeds({
    sources: ["clamav"],
    config: { requestTimeoutMs: 10000, minimumUpdateIntervalMinutes: 15 },
    credentials: {},
    force: false
  });
  assert.equal(result.results[0].ok, true);
  assert.equal(result.results[0].skipped, true);
  await withThreatDatabase((database) => {
    assert.equal(database.prepare("SELECT state FROM feed_status WHERE source = 'clamav'").get().state, "ready");
  });
});

test("Windows drive and TCP connection telemetry parsers are deterministic", () => {
  assert.deepEqual(parsePowerShellStringArray('["C:\\\\","D:\\\\"]'), ["C:\\", "D:\\"]);
  const connections = parseNetstatOutput(`
    TCP    10.0.0.5:50000       50.16.16.211:443       ESTABLISHED     1234
    TCP    [2001:db8::2]:51000  [2001:db8::3]:8443     SYN_SENT        5678
    TCP    127.0.0.1:9000       127.0.0.1:9001         ESTABLISHED     9999
  `);
  assert.equal(connections.length, 2);
  assert.equal(connections[0].remote.host, "50.16.16.211");
  assert.equal(connections[1].remote.port, 8443);
});

test("DNS filtering profiles and adapter state are validated deterministically", () => {
  assert.equal(DNS_PROFILES.length, 3);
  assert.equal(getDnsProfile("adguard-default").dohTemplate.startsWith("https://"), true);
  assert.equal(getDnsProfile("not-a-profile"), null);
  const adapters = parseAdapterJson(JSON.stringify({
    interfaceIndex: 20,
    alias: "Wi-Fi",
    description: "Unit adapter",
    dnsServers: ["192.168.1.1", "2001:db8::53"],
    automatic: true
  }));
  assert.deepEqual(adapters, [{
    interfaceIndex: 20,
    alias: "Wi-Fi",
    description: "Unit adapter",
    dnsServers: ["192.168.1.1", "2001:db8::53"],
    automatic: true
  }]);
});

test("Windows process and persistence telemetry parsers reject malformed records", () => {
  const processes = parseProcessSnapshot(JSON.stringify([
    { pid: 42, parentPid: 7, name: "unit.exe", executablePath: "C:\\unit.exe", commandLine: "unit.exe --safe" },
    { pid: "invalid", name: "bad.exe" }
  ]));
  assert.equal(processes.length, 1);
  assert.equal(processes[0].parentPid, 7);
  assert.equal(processes[0].commandLine, "unit.exe --safe");
  assert.deepEqual(parseTelemetryArray('{"type":"run-key","id":"unit","value":"safe"}'), [
    { type: "run-key", id: "unit", value: "safe" }
  ]);
});

test("startup target discovery extracts executable persistence paths without arguments", () => {
  assert.deepEqual(persistenceExecutableCandidates([
    { type: "run-key", id: "unit", value: "\"C:\\Program Files\\Unit\\agent.exe\" --background" },
    { type: "service", id: "service", value: "C:\\Tools\\service.exe -k unit|LocalSystem" },
    { type: "startup-file", id: "C:\\Users\\Unit\\Startup\\launch.cmd", value: "12|today" },
    { type: "run-key", id: "duplicate", value: "\"C:\\Program Files\\Unit\\agent.exe\" --again" },
    { type: "wmi-consumer", id: "ignored", value: "not an executable path" }
  ]), [
    "C:\\Program Files\\Unit\\agent.exe",
    "C:\\Tools\\service.exe",
    "C:\\Users\\Unit\\Startup\\launch.cmd"
  ]);
});

test("security posture reports fixable gaps without enabling aggressive policies", async () => {
  const config = await loadConfig();
  config.protection.realtimeEnabled = false;
  config.protection.autoQuarantineConfirmed = false;
  config.monitoring.ransomwareEnabled = false;
  const posture = calculateSecurityPosture({
    protection: {
      file: { running: false },
      network: { running: true },
      advanced: { running: true }
    },
    audit: { valid: true },
    signatures: { hashCount: 1, patternCount: 0, threatCount: 0 },
    clamavEngine: { signatureCount: 0 }
  }, config);
  assert.equal(posture.score, 56);
  assert.equal(posture.state, "critical");
  assert.equal(posture.issues.some((item) => item.id === "realtime-disabled" && item.fixable), true);
  assert.equal(posture.issues.some((item) => item.id === "ransomware-disabled" && item.fixable), true);
  assert.equal(posture.issues.some((item) => item.id === "automatic-quarantine-disabled"), true);
});

test("local reputation lookup returns indexed hashes without network access", async () => {
  await sandbox("reputation");
  const hash = "9".repeat(64);
  await withThreatDatabase((database) => {
    database.prepare(`
      INSERT INTO threat_hashes
        (algorithm, hash, size, name, source, severity, confirmed, details, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run("sha256", hash, -1, "Unit.Reputation", "unit", "critical", 1, null, new Date().toISOString());
  });
  const engine = await new AntivirusEngine().initialize();
  const result = await engine.lookupReputation(hash);
  assert.equal(result.localOnly, true);
  assert.equal(result.verdict, "malicious");
  assert.equal(result.matches[0].name, "Unit.Reputation");
});

test("engine scan modes write one normalized job history record", async () => {
  const root = await sandbox("job-history");
  const sample = path.join(root, "clean.txt");
  await fs.writeFile(sample, "clean job history fixture");
  const engine = await new AntivirusEngine().initialize();
  engine.config.threatIntel.clamavEngineEnabled = false;
  const result = await engine.runScan("path", sample, { autoQuarantine: false });
  assert.equal(result.scanned, 1);
  const history = await readScanHistory();
  assert.equal(history.length, 1);
  assert.equal(history[0].type, "path");
  assert.deepEqual(history[0].targets, [sample]);
});

test("USB storage policy status parsing preserves block state", () => {
  assert.deepEqual(parseUsbPolicyStatus('{"configured":true,"value":1}'), {
    blocked: true,
    configured: true
  });
  assert.deepEqual(parseUsbPolicyStatus('{"configured":false,"value":0}'), {
    blocked: false,
    configured: false
  });
});

test("native scan picker accepts only file and folder modes", () => {
  assert.equal(validatePickerKind("file"), "file");
  assert.equal(validatePickerKind("folder"), "folder");
  assert.throws(() => validatePickerKind("drive"), /file or folder/);
});

test("client update manifests reject path traversal and invalid hashes", () => {
  assert.throws(() => validateClientUpdateManifest({
    version: "1.2.3",
    fileName: "../SentryLoom-Setup-1.2.3.exe",
    size: 4096,
    sha256: "a".repeat(64),
    signerThumbprint: "b".repeat(40)
  }), /package name/);
  assert.throws(() => validateClientUpdateManifest({
    version: "1.2.3",
    fileName: "SentryLoom-Setup-1.2.3.exe",
    size: 4096,
    sha256: "not-a-hash",
    signerThumbprint: "b".repeat(40)
  }), /update hash/);
  assert.throws(() => validateClientUpdateManifest({
    version: "1.2.3",
    fileName: "SentryLoom-Setup-1.2.4.exe",
    size: 4096,
    sha256: "a".repeat(64),
    signerThumbprint: "b".repeat(40)
  }), /does not match its version/);
});

test("signed HQ client updates stage silently and reject the wrong publisher", async () => {
  await sandbox("client-update");
  const manifest = {
    version: "9.8.7",
    fileName: "SentryLoom-Setup-9.8.7.exe",
    size: 4096,
    sha256: "A".repeat(64),
    signerThumbprint: "B".repeat(40),
    signerSubject: "CN=NUC7 Studios",
    publishedAt: new Date().toISOString()
  };
  const credentials = {
    serverUrl: "http://127.0.0.1:1",
    fingerprint256: "",
    deviceId: crypto.randomUUID(),
    token: "t".repeat(48)
  };
  let launched = 0;
  const options = {
    allowHttp: true,
    request: async () => ({ body: { update: manifest } }),
    download: async (unusedCredentials, unusedRoute, destination) => {
      await fs.writeFile(destination, Buffer.alloc(manifest.size));
      return { path: destination, bytes: manifest.size, sha256: manifest.sha256 };
    },
    verify: async () => ({
      status: "Valid",
      thumbprint: manifest.signerThumbprint,
      subject: manifest.signerSubject,
      version: manifest.version
    }),
    isElevated: async () => true,
    launch: async () => { launched += 1; }
  };
  const result = await stageClientUpdate(credentials, options);
  assert.equal(result.state, "scheduled");
  assert.equal(result.targetVersion, manifest.version);
  assert.equal(launched, 1);
  const status = JSON.parse(await fs.readFile(path.join(
    process.env.SENTRYLOOM_DATA_DIR,
    "updates",
    "status.json"
  ), "utf8"));
  assert.equal(status.state, "staged");

  await assert.rejects(stageClientUpdate(credentials, {
    ...options,
    verify: async () => ({
      status: "Valid",
      thumbprint: manifest.signerThumbprint,
      subject: "CN=Untrusted Publisher",
      version: manifest.version
    })
  }), /publisher or version/);
});

test("ClamAV timeout returns a bounded scan error instead of hanging", async () => {
  const child = new EventEmitter();
  child.pid = 4242;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => queueMicrotask(() => child.emit("close", null));
  const result = await scanWithClamAv("unit-clean-file.txt", {
    enabled: true,
    maxFileBytes: 1024,
    timeoutMs: 20,
    status: {
      installed: true,
      databasesReady: true,
      executable: "clamscan-unit",
      databaseDirectory: "unit-database"
    },
    spawnImpl: () => child,
    terminateImpl: (processToStop) => processToStop.kill()
  });
  assert.equal(result.available, true);
  assert.match(result.errors[0].error, /timed out/);
});

test("revoked clients automatically re-enroll with their pinned HQ", async () => {
  await sandbox("hq-reauth");
  const dbFile = path.join(process.env.SENTRYLOOM_DATA_DIR, "db", "hq-test-reauth.db");
  await fs.mkdir(path.dirname(dbFile), { recursive: true }).catch(() => {});
  const store = await new HqStore(dbFile).open();
  const config = {
    hqName: "Test HQ",
    host: "127.0.0.1",
    port: 0,
    databasePath: dbFile,
    tls: { fingerprint256: "" },
    admin: {
      salt: Buffer.alloc(16).toString("base64"),
      iterations: 1000,
      passwordHash: Buffer.alloc(32).toString("base64"),
      sessionHours: 12,
      maxLoginAttempts: 10
    },
    discovery: { enabled: false, port: 32110 },
    telemetryRetentionDays: 30,
    alerts: { offlineAfterSeconds: 60 },
    maintenance: { defaultMinutes: 10, defaultUses: 1 },
    updates: {}
  };
  const hq = await createHqServer(config, { store, httpOnly: true });
  const address = await hq.listen("127.0.0.1", 0);
  process.env.SENTRYLOOM_ALLOW_INSECURE_HQ = "1";

  try {
    const pending = await requestHqEnrollment({
      serverUrl: `http://127.0.0.1:${address.port}`,
      allowHttp: true,
      verificationCode: "123456"
    });

    store.reviewEnrollmentRequest(pending.requestId, true, "123456");
    const approval = await pollHqEnrollment(pending);
    const credentials = approval.credentials;

    const engine = await new AntivirusEngine().initialize();
    await engine.updateConfig({ management: { enabled: true } });
    engine.activateHqConnector(credentials);
    engine.hqConnector.stop();
    engine.hqConnector.metricsProvider = async () => ({
      security: { score: 96, quarantineCount: 0 }
    });
    engine.hqConnector.allowHttp = true;
    engine.hqConnector.running = true;
    store.revokeDevice(credentials.deviceId);

    await engine.hqConnector.pulse();

    let newPending = null;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      newPending = await loadPendingHqEnrollment();
      if (newPending &&
          engine.events.some((event) => event.type === "hq.reenrollment-pending")) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.ok(engine.events.some((event) => event.type === "hq.reauthorization-required"));
    assert.ok(engine.events.some((event) => event.type === "hq.reenrollment-pending"));
    assert.equal(await loadHqCredentials(), null);
    assert.ok(newPending);
    assert.equal(newPending.status, "pending");
    assert.match(newPending.verificationCode, /^\d{6}$/);
    await engine.stopManagement();
    store.reviewEnrollmentRequest(
      newPending.requestId,
      true,
      newPending.verificationCode
    );
    const reEnrollment = await pollHqEnrollment(newPending);
    assert.equal(reEnrollment.status, "approved");
    assert.equal(reEnrollment.credentials.deviceId, credentials.deviceId);
    assert.notEqual(reEnrollment.credentials.token, credentials.token);

    await engine.stopManagement();
  } finally {
    delete process.env.SENTRYLOOM_ALLOW_INSECURE_HQ;
    await hq.close();
    store.close();
    await fs.rm(dbFile, { force: true }).catch(() => {});
  }
});
