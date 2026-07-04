#!/usr/bin/env node
import path from "node:path";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { AntivirusEngine, highestSeverity } from "./lib/engine.js";
import { createDashboardServer } from "./server.js";
import { listQuarantine, restoreQuarantine, deleteQuarantine } from "./lib/quarantine.js";
import { importSignedBundle, trustSignatureKey, signatureStatus } from "./lib/signature-store.js";
import { verifyAuditLog } from "./lib/audit-log.js";
import { appPaths, APP_NAME, APP_VERSION } from "./constants.js";
import { openThreatIndex } from "./lib/threat-index.js";
import { validDashboardPage } from "./lib/ui-command.js";
import {
  enrollWithHq,
  discoverHqServers,
  probeHq,
  requestHqEnrollment
} from "./lib/hq-client.js";

const args = process.argv.slice(2);
const command = args.shift() || "help";

function takeOption(name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  args.splice(index, 2);
  return value;
}

function hasFlag(name) {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

async function authorizeCriticalAction(engine, action) {
  await engine.authorizeMaintenance(
    process.env.SENTRYLOOM_MAINTENANCE_PASSWORD,
    action
  );
}

function printHelp() {
  console.log(`${APP_NAME} ${APP_VERSION}

Usage:
  sentryloom dashboard [--no-open] [--port 3210] [--page quarantine]
  sentryloom quick|full|startup|processes|external [--json] [--no-quarantine]
  sentryloom scan <file-or-directory> [--json] [--no-quarantine]
  sentryloom protect [path ...]
  sentryloom status [--json]
  sentryloom quarantine list|restore|delete
  sentryloom signatures status|trust|import
  sentryloom update [all|clamav|malwarebazaar|urlhaus|feodotracker|threatfox] [--force]
  sentryloom ioc lookup <ip-domain-url>
  sentryloom credentials import-env
  sentryloom dns status|apply|restore
  sentryloom firewall status|clear
  sentryloom audit verify
  sentryloom hq discover|enroll-env|status|disconnect|maintenance-authorize-env

Scanning and signature verification happen locally. Network access is used only for an explicitly requested database update.`);
}

function printScan(result) {
  console.log(`\n${result.type.toUpperCase()} SCAN COMPLETE`);
  console.log(`Scanned: ${result.scanned}  Skipped: ${result.skipped}  Detections: ${result.detections}  Errors: ${result.errorCount}`);
  for (const report of result.reports) {
    for (const item of report.results.filter((entry) => entry.status === "detected")) {
      console.log(`\n[${highestSeverity(item.findings).toUpperCase()}] ${item.path}`);
      for (const finding of item.findings) console.log(`  - ${finding.name}${finding.confirmed ? " (confirmed)" : " (heuristic)"}`);
      if (item.quarantine) console.log(`  Quarantined: ${item.quarantine.id}`);
      if (item.quarantineError) console.log(`  Quarantine error: ${item.quarantineError}`);
    }
    for (const error of report.errors) console.error(`ERROR ${error.path}: ${error.error}`);
  }
}

async function launchBrowser(url) {
  if (process.platform === "win32") {
    const edgeCandidates = [
      path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"),
      path.join(process.env.ProgramFiles || "C:\\Program Files", "Microsoft", "Edge", "Application", "msedge.exe")
    ];
    const edge = edgeCandidates.find((candidate) => fs.existsSync(candidate));
    const executable = edge || "rundll32.exe";
    const argumentsList = edge
      ? [`--app=${url}`, "--no-first-run", "--disable-features=msEdgeSidebarV2"]
      : ["url.dll,FileProtocolHandler", url];
    const child = spawn(executable, argumentsList, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });
    child.unref();
  } else {
    const executable = process.platform === "darwin" ? "open" : "xdg-open";
    const child = spawn(executable, [url], { detached: true, stdio: "ignore" });
    child.unref();
  }
}

async function dashboard() {
  const noOpen = hasFlag("--no-open");
  const requestedPort = Number(takeOption("--port", 0));
  const requestedPage = validDashboardPage(takeOption("--page", "overview"), "overview");
  const engine = await new AntivirusEngine().initialize();
  if (engine.config.protection.realtimeEnabled) {
    await engine.startProtection();
  }
  await engine.startManagement();
  let stopping = false;
  let dashboardServer;
  let dashboardRuntimeUrl = null;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    if (dashboardRuntimeUrl) {
      try {
        const runtimeFile = appPaths().dashboardRuntime;
        if (fs.readFileSync(runtimeFile, "utf8").trim() === dashboardRuntimeUrl) {
          fs.rmSync(runtimeFile, { force: true });
        }
      } catch {}
    }
    await engine.stopProtection().catch(() => {});
    await engine.stopManagement();
    await dashboardServer?.close().catch(() => {});
    process.exit(0);
  };
  dashboardServer = createDashboardServer(engine, { onExit: stop });
  const port = requestedPort || engine.config.dashboard.port;
  const address = await dashboardServer.listen(engine.config.dashboard.host, port);
  dashboardRuntimeUrl = `http://${engine.config.dashboard.host}:${address.port}/session?token=${dashboardServer.launchToken}`;
  fs.mkdirSync(path.dirname(appPaths().dashboardRuntime), { recursive: true });
  fs.writeFileSync(appPaths().dashboardRuntime, `${dashboardRuntimeUrl}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
  const url = `${dashboardRuntimeUrl}&page=${encodeURIComponent(requestedPage)}`;
  console.log(`${APP_NAME} dashboard: ${url}`);
  console.log("Press Ctrl+C to stop the dashboard and realtime monitor.");
  if (!noOpen) await launchBrowser(url);

  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

async function runScan(type, target) {
  const json = hasFlag("--json");
  const noQuarantine = hasFlag("--no-quarantine");
  const engine = await new AntivirusEngine().initialize();
  const result = await engine.runScan(type, target, {
    autoQuarantine: !noQuarantine,
    onProgress: (progress) => {
      if (!json && process.stdout.isTTY) {
        process.stdout.write(`\rScanning ${progress.completed}/${progress.total}: ${progress.current.slice(-70).padEnd(70)}`);
      }
    }
  });
  if (!json && process.stdout.isTTY) process.stdout.write("\n");
  if (json) console.log(JSON.stringify(result, null, 2));
  else printScan(result);
  process.exitCode = result.detections ? 2 : result.errorCount ? 1 : 0;
}

async function protection() {
  const engine = await new AntivirusEngine().initialize();
  const targets = args.length ? args.map((item) => path.resolve(item)) : undefined;
  const emit = engine.emit.bind(engine);
  engine.emit = (event) => {
    const enriched = emit(event);
    console.log(JSON.stringify(enriched));
    return enriched;
  };
  await engine.startProtection(targets);
  const status = await engine.getStatus();
  console.log(`Realtime file protection active for: ${status.protection.file.targets.join(", ")}`);
  console.log(`Network connection monitoring: ${status.protection.network.running ? "active" : "inactive"} (packet inspection: no)`);
  const stop = async () => {
    await engine.stopProtection();
    await engine.stopManagement();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}

async function main() {
  switch (command) {
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    case "dashboard":
      await dashboard();
      break;
    case "quick":
      await runScan("quick");
      break;
    case "full":
      await runScan("full");
      break;
    case "startup":
      await runScan("startup");
      break;
    case "processes":
      await runScan("processes");
      break;
    case "external":
      await runScan("external");
      break;
    case "scan": {
      const target = args.shift();
      if (!target) throw new Error("Provide a file or directory to scan");
      await runScan("path", target);
      break;
    }
    case "protect":
      await protection();
      break;
    case "status": {
      const asJson = hasFlag("--json");
      const engine = await new AntivirusEngine().initialize();
      const status = await engine.getStatus();
      if (asJson) console.log(JSON.stringify({ ...status, dataDirectory: appPaths().data }, null, 2));
      else {
        console.log(`${APP_NAME} ${APP_VERSION}`);
        console.log(`Data: ${appPaths().data}`);
        console.log(`Audit integrity: ${status.audit.valid ? "valid" : "FAILED"}`);
        console.log(`File monitoring: ${status.protection.file.running ? status.protection.file.targets.join(", ") : "inactive"} (${status.protection.elevated ? "administrator" : "current-user"} access)`);
        console.log(`Network monitoring: ${status.protection.network.running ? "TCP connections + DNS cache" : "inactive"} (packet payload inspection: no)`);
        console.log(`Behavior monitoring: ${status.protection.advanced.running ? `${status.protection.advanced.processesObserved} processes · ${status.protection.advanced.canaries} canaries · ${status.protection.advanced.securityEvents} security events` : "inactive"}`);
        console.log(`Firewall IOC enforcement: ${status.protection.firewallEnforcement.enabled ? "enabled" : "report-only"}`);
        const signatureTotal = status.signatures.hashCount + status.signatures.patternCount + status.signatures.threatCount;
        console.log(`Signatures: ${status.signatures.version} (${signatureTotal} indicators)`);
        console.log(`Network IOCs: ${status.signatures.networkIocCount}`);
        for (const feed of status.signatures.threatIntel.feeds) {
          console.log(`  ${feed.source}: ${feed.entryCount} · ${feed.state}${feed.lastSuccess ? ` · ${feed.lastSuccess}` : ""}`);
        }
        console.log(`Quarantine: ${status.quarantineCount} active item(s)`);
      }
      break;
    }
    case "quarantine": {
      const action = args.shift() || "list";
      if (action === "list") console.log(JSON.stringify(await listQuarantine(), null, 2));
      else if (action === "restore") {
        const id = args.shift();
        if (!id) throw new Error("Provide a quarantine item ID");
        console.log(`Restored to ${await restoreQuarantine(id, args.shift())}`);
      } else if (action === "delete") {
        const id = args.shift();
        if (!id) throw new Error("Provide a quarantine item ID");
        await deleteQuarantine(id);
        console.log("Quarantine item permanently deleted");
      } else throw new Error(`Unknown quarantine action: ${action}`);
      break;
    }
    case "hq": {
      const action = args.shift() || "status";
      if (action === "discover") {
        console.log(JSON.stringify(await discoverHqServers(), null, 2));
      } else if (action === "probe-env") {
        const serverUrl = process.env.SENTRYLOOM_HQ_URL;
        if (!serverUrl) throw new Error("SENTRYLOOM_HQ_URL is required");
        const identity = await probeHq(serverUrl, {
          fingerprint256: process.env.SENTRYLOOM_HQ_FINGERPRINT || undefined
        });
        const probeFile = process.env.SENTRYLOOM_HQ_PROBE_FILE;
        if (probeFile) {
          fs.writeFileSync(probeFile, `${identity.fingerprint256}\n`, {
            encoding: "utf8",
            mode: 0o600,
            flag: "w"
          });
        }
        console.log(JSON.stringify(identity, null, 2));
      } else if (action === "enroll-env") {
        const serverUrl = process.env.SENTRYLOOM_HQ_URL;
        const code = process.env.SENTRYLOOM_HQ_ENROLLMENT_CODE;
        if (!serverUrl || !code) throw new Error("SENTRYLOOM_HQ_URL and SENTRYLOOM_HQ_ENROLLMENT_CODE are required");
        const credentials = await enrollWithHq({
          serverUrl,
          code,
          fingerprint256: process.env.SENTRYLOOM_HQ_FINGERPRINT,
          trustOnFirstUse: !process.env.SENTRYLOOM_HQ_FINGERPRINT
        });
        const engine = await new AntivirusEngine().initialize();
        await engine.updateConfig({ management: { enabled: true } });
        console.log(`Enrolled with ${credentials.hqName}`);
      } else if (action === "request-env") {
        const pending = await requestHqEnrollment({
          serverUrl: process.env.SENTRYLOOM_HQ_URL || undefined,
          fingerprint256: process.env.SENTRYLOOM_HQ_FINGERPRINT || undefined
        });
        const engine = await new AntivirusEngine().initialize();
        await engine.updateConfig({ management: { enabled: true } });
        console.log(`Enrollment approval requested from ${pending.hqName}`);
      } else if (action === "maintenance-authorize-env") {
        const password = process.env.SENTRYLOOM_MAINTENANCE_PASSWORD;
        const maintenanceAction = process.env.SENTRYLOOM_MAINTENANCE_ACTION || "uninstall";
        const engine = await new AntivirusEngine().initialize();
        await engine.authorizeMaintenance(password, maintenanceAction);
        console.log("Maintenance authorization accepted");
      } else {
        const engine = await new AntivirusEngine().initialize();
        if (action === "status") console.log(JSON.stringify(await engine.getHqStatus(), null, 2));
        else if (action === "disconnect") {
          await authorizeCriticalAction(engine, "disconnect-hq");
          console.log(JSON.stringify(await engine.disconnectHq(), null, 2));
        }
        else throw new Error(`Unknown HQ action: ${action}`);
      }
      break;
    }
    case "signatures": {
      const action = args.shift() || "status";
      if (action === "status") console.log(JSON.stringify(await signatureStatus(), null, 2));
      else if (action === "trust") {
        const [keyId, keyFile] = args;
        if (!keyId || !keyFile) throw new Error("Provide a key ID and public key file");
        await trustSignatureKey(keyId, keyFile);
        console.log(`Trusted signature key: ${keyId}`);
      } else if (action === "import") {
        const bundle = args.shift();
        if (!bundle) throw new Error("Provide a signed signature bundle");
        const imported = await importSignedBundle(bundle);
        console.log(`Imported signature database: ${imported.version}`);
      } else throw new Error(`Unknown signature action: ${action}`);
      break;
    }
    case "update": {
      const source = args.shift() || "all";
      const sources = source === "all"
        ? ["clamav", "malwarebazaar", "urlhaus", "feodotracker", "threatfox"]
        : [source];
      const force = hasFlag("--force");
      const engine = await new AntivirusEngine().initialize();
      engine.threatUpdates.onEvent = (event) => {
        const progress = event.progress;
        if (progress?.message) console.log(`[${progress.source}] ${progress.message}`);
        else if (progress) console.log(`[${progress.source}] ${progress.phase}${progress.imported ? `: ${progress.imported} indexed` : ""}`);
      };
      const result = await engine.updateThreatIntel(sources, { force });
      console.log(JSON.stringify(result, null, 2));
      if (result.results.some((item) => !item.ok)) process.exitCode = 1;
      break;
    }
    case "ioc": {
      const action = args.shift();
      const value = args.shift();
      if (action !== "lookup" || !value) throw new Error("Usage: sentryloom ioc lookup <ip-domain-url>");
      const index = await openThreatIndex();
      try {
        console.log(JSON.stringify(index.lookupIoc(value), null, 2));
      } finally {
        index.close();
      }
      break;
    }
    case "credentials": {
      const action = args.shift();
      if (action !== "import-env") throw new Error("Usage: sentryloom credentials import-env");
      const key = process.env.SENTRYLOOM_ABUSECH_KEY;
      if (!key) throw new Error("SENTRYLOOM_ABUSECH_KEY is not set");
      const engine = await new AntivirusEngine().initialize();
      await engine.saveThreatCredentials({ abuseChAuthKey: key });
      console.log("Threat-intelligence credential encrypted and stored");
      break;
    }
    case "dns": {
      const action = args.shift() || "status";
      const engine = await new AntivirusEngine().initialize();
      if (action === "status") {
        console.log(JSON.stringify(await engine.getDnsFilteringStatus(), null, 2));
      } else if (action === "apply") {
        const profileId = args.shift();
        if (!profileId) throw new Error("Provide a DNS filtering profile ID");
        await authorizeCriticalAction(engine, "dns-filtering-change");
        console.log(JSON.stringify(await engine.applyDnsFiltering(profileId), null, 2));
      } else if (action === "restore") {
        await authorizeCriticalAction(engine, "dns-filtering-change");
        console.log(JSON.stringify(await engine.restoreDnsFiltering(), null, 2));
      } else {
        throw new Error(`Unknown DNS action: ${action}`);
      }
      break;
    }
    case "firewall": {
      const action = args.shift() || "status";
      const engine = await new AntivirusEngine().initialize();
      if (action === "status") {
        console.log(JSON.stringify(await engine.getFirewallPolicyStatus(), null, 2));
      } else if (action === "clear") {
        await authorizeCriticalAction(engine, "firewall-policy-change");
        console.log(JSON.stringify(await engine.clearFirewallPolicy(), null, 2));
      } else {
        throw new Error(`Unknown firewall action: ${action}`);
      }
      break;
    }
    case "audit": {
      const action = args.shift() || "verify";
      if (action !== "verify") throw new Error(`Unknown audit action: ${action}`);
      const result = await verifyAuditLog();
      console.log(JSON.stringify(result, null, 2));
      if (!result.valid) process.exitCode = 3;
      break;
    }
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  const message = `SentryLoom error: ${error.message}`;
  console.error(message);
  const failureLog = process.env.SENTRYLOOM_FAILURE_LOG;
  if (failureLog) {
    try {
      fs.writeFileSync(failureLog, `${message}\n`, {
        encoding: "utf8",
        mode: 0o600,
        flag: "w"
      });
    } catch {}
  }
  process.exitCode = 1;
});
