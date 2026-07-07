import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { appPaths } from "../constants.js";
import { ensureDirectory, writeJsonAtomic } from "./fs-safe.js";
import { appendAudit } from "./audit-log.js";
import { compileSignatures, loadSignatures } from "./signature-store.js";
import { scanFile } from "./scanner.js";
import { openThreatIndex } from "./threat-index.js";
import { runPowerShell } from "./windows-monitoring.js";
import {
  discoverRemovableDrives,
  readExecutableTrustStatus,
  readFirewallSnapshot,
  readPersistenceSnapshot,
  readProcessSnapshot,
  readSecurityEvents
} from "./platform-telemetry.js";

function stableValue(value) {
  const canonical = (item) => {
    if (Array.isArray(item)) return item.map(canonical);
    if (item && typeof item === "object") {
      return Object.fromEntries(Object.keys(item).sort().map((key) => [key, canonical(item[key])]));
    }
    return item;
  };
  return JSON.stringify(canonical(value));
}

function mapSnapshot(items) {
  return new Map(items.map((item) => [`${item.type}|${item.id}`, stableValue(item)]));
}

function isUserWritableExecutable(file) {
  if (!file) return false;
  const normalized = path.resolve(file).toLowerCase();
  return [
    os.homedir(),
    os.tmpdir(),
    process.env.LOCALAPPDATA,
    process.env.APPDATA
  ].filter(Boolean).some((root) => normalized.startsWith(path.resolve(root).toLowerCase()));
}

function isCollectorProcess(processInfo) {
  if (!/^(powershell|pwsh)\.exe$/i.test(processInfo.name) || !processInfo.commandLine) return false;
  return /Get-CimInstance Win32_Process|Get-WinEvent -FilterHashtable|Get-NetFirewall(Profile|Rule)|Get-ScheduledTask|ConvertTo-Json -Compress/.test(processInfo.commandLine);
}

export class AdvancedMonitoring {
  constructor(config, onEvent = () => {}, options = {}) {
    this.config = config;
    this.onEvent = onEvent;
    this.onRemovableDrive = options.onRemovableDrive || (() => {});
    this.running = false;
    this.timers = new Set();
    this.errors = 0;
    this.processesObserved = 0;
    this.processStarts = 0;
    this.processDetections = 0;
    this.persistenceChanges = 0;
    this.securityEvents = 0;
    this.canaryAlerts = 0;
    this.ransomwareBurstAlerts = 0;
    this.removableArrivals = 0;
    this.firewallChanges = 0;
    this.lastPolls = {};
    this.fileEvents = [];
    this.lastBurstAlert = 0;
    this.canaryFiles = [];
    this.authenticodeCache = new Map();
    this.seenSecurityEvents = new Set();
  }

  schedule(channel, delay, interval, work) {
    if (!this.running) return;
    const timer = setTimeout(async () => {
      this.timers.delete(timer);
      try {
        await work();
        this.lastPolls[channel] = new Date().toISOString();
      } catch (error) {
        this.errors += 1;
        if (this.errors <= 5 || this.errors % 25 === 0) {
          this.onEvent({ type: "monitoring.error", channel, error: error.message });
        }
      }
      this.schedule(channel, interval, interval, work);
    }, delay);
    this.timers.add(timer);
  }

  async start() {
    if (this.running) return;
    this.running = true;
    if (this.config.monitoring.processEnabled) {
      this.signatures = compileSignatures(await loadSignatures());
      this.threatIndex = await openThreatIndex();
      this.signatures.threatIndex = this.threatIndex;
      this.processBaseline = new Map((await readProcessSnapshot()).map((item) => [item.pid, item]));
      this.schedule("process", 0, this.config.monitoring.processPollIntervalMs, () => this.pollProcesses());
    }
    if (this.config.monitoring.persistenceEnabled) {
      this.persistenceBaseline = mapSnapshot(await readPersistenceSnapshot());
      this.schedule("persistence", 0, this.config.monitoring.persistencePollIntervalMs, () => this.pollPersistence());
    }
    if (this.config.monitoring.windowsEventsEnabled) {
      this.eventsSince = new Date().toISOString();
      this.schedule("securityEvents", 1000, this.config.monitoring.eventPollIntervalMs, () => this.pollSecurityEvents());
    }
    if (this.config.monitoring.ransomwareEnabled) await this.initializeCanaries();
    if (this.config.monitoring.removableMediaEnabled) {
      this.removableBaseline = new Set((await discoverRemovableDrives()).map((drive) => drive.root.toLowerCase()));
      this.schedule("removable", 1000, this.config.monitoring.removablePollIntervalMs, () => this.pollRemovable());
    }
    if (this.config.monitoring.firewallIntegrityEnabled) {
      this.firewallBaseline = await readFirewallSnapshot();
      this.schedule("firewall", 1000, this.config.monitoring.firewallPollIntervalMs, () => this.pollFirewall());
    }
    await appendAudit("advanced-monitoring.started", {
      process: this.config.monitoring.processEnabled,
      persistence: this.config.monitoring.persistenceEnabled,
      ransomware: this.config.monitoring.ransomwareEnabled,
      windowsEvents: this.config.monitoring.windowsEventsEnabled,
      removableMedia: this.config.monitoring.removableMediaEnabled,
      firewallIntegrity: this.config.monitoring.firewallIntegrityEnabled
    });
  }

  async pollProcesses() {
    const current = await readProcessSnapshot();
    this.processesObserved = current.length;
    const next = new Map(current.map((item) => [item.pid, item]));
    for (const processInfo of current) {
      if (isCollectorProcess(processInfo)) continue;
      const prior = this.processBaseline.get(processInfo.pid);
      if (prior?.creationDate === processInfo.creationDate) continue;
      this.processStarts += 1;
      const event = {
        type: "process.started",
        process: {
          ...processInfo,
          commandLineHash: processInfo.commandLine
            ? crypto.createHash("sha256").update(processInfo.commandLine).digest("hex")
            : null,
          commandLine: undefined
        }
      };
      this.onEvent(event);
      if (processInfo.executablePath) this.inspectProcessImage(processInfo).catch((error) => {
        if (["ENOENT", "EACCES", "EPERM", "EBUSY"].includes(error.code)) return;
        this.errors += 1;
        this.onEvent({ type: "process.inspect-error", pid: processInfo.pid, error: error.message });
      });
    }
    this.processBaseline = next;
  }

  async inspectProcessImage(processInfo) {
    const file = processInfo.executablePath;
    try {
      await fsp.access(file);
    } catch {
      return;
    }
    let signature = this.authenticodeCache.get(file.toLowerCase());
    if (!signature) {
      signature = await readExecutableTrustStatus(file);
      this.authenticodeCache.set(file.toLowerCase(), signature);
      if (this.authenticodeCache.size > 2000) this.authenticodeCache.delete(this.authenticodeCache.keys().next().value);
    }
    const result = await scanFile(file, { config: this.config.scanner, signatures: this.signatures });
    if (result.status === "detected") {
      this.processDetections += 1;
      const event = { type: "process.detection", process: { ...processInfo, commandLine: undefined }, signature, result };
      this.onEvent(event);
      await appendAudit("process.detection", {
        pid: processInfo.pid,
        parentPid: processInfo.parentPid,
        executablePath: file,
        signerStatus: signature.status,
        findings: result.findings.map((finding) => finding.name)
      });
    } else if (signature.status === "NotSigned" && isUserWritableExecutable(file)) {
      this.onEvent({
        type: "process.unsigned-user-path",
        process: { ...processInfo, commandLine: undefined },
        signature
      });
    }
  }

  async pollPersistence() {
    const items = await readPersistenceSnapshot();
    const next = mapSnapshot(items);
    for (const item of items) {
      const key = `${item.type}|${item.id}`;
      const prior = this.persistenceBaseline.get(key);
      const value = stableValue(item);
      if (prior === undefined || prior !== value) {
        this.persistenceChanges += 1;
        const change = prior === undefined ? "added" : "changed";
        this.onEvent({ type: "persistence.change", change, item });
        await appendAudit("persistence.change", { change, type: item.type, id: item.id, value: item.value });
      }
    }
    for (const key of this.persistenceBaseline.keys()) {
      if (!next.has(key)) {
        this.persistenceChanges += 1;
        const [type, ...rest] = key.split("|");
        this.onEvent({ type: "persistence.change", change: "removed", item: { type, id: rest.join("|") } });
        await appendAudit("persistence.change", { change: "removed", type, id: rest.join("|") });
      }
    }
    this.persistenceBaseline = next;
  }

  async pollSecurityEvents() {
    const now = new Date().toISOString();
    const events = await readSecurityEvents(this.eventsSince);
    this.eventsSince = new Date(Date.now() - 2000).toISOString();
    for (const event of events) {
      const key = `${event.log}|${event.recordId}`;
      if (this.seenSecurityEvents.has(key)) continue;
      this.seenSecurityEvents.add(key);
      this.securityEvents += 1;
      const eventType = process.platform === "win32"
        ? "windows.security-event"
        : process.platform === "darwin"
          ? "macos.security-event"
          : "linux.security-event";
      this.onEvent({ type: eventType, event });
      if (event.level <= 2 || [1116, 1117, 5001, 3077, 4697, 7045].includes(event.eventId)) {
        await appendAudit(eventType, {
          log: event.log,
          eventId: event.eventId,
          level: event.level,
          provider: event.provider,
          at: event.at
        });
      }
    }
    if (this.seenSecurityEvents.size > 5000) this.seenSecurityEvents = new Set([...this.seenSecurityEvents].slice(-2500));
    this.lastPolls.securityEvents = now;
  }

  canaryTargets() {
    return ["Desktop", "Documents", "Pictures"]
      .map((name) => path.join(os.homedir(), name))
      .filter((directory) => fs.existsSync(directory));
  }

  async initializeCanaries() {
    const marker = "SentryLoom ransomware behavior canary. Changes to this file trigger a security alert.\n";
    for (const directory of this.canaryTargets()) {
      const file = path.join(directory, ".sentryloom-ransomware-canary.txt");
      try {
        if (!fs.existsSync(file)) await fsp.writeFile(file, marker, { encoding: "utf8", flag: "wx", mode: 0o444 });
        const expected = crypto.createHash("sha256").update(await fsp.readFile(file)).digest("hex");
        this.canaryFiles.push({ file, expected, alerting: false });
        if (process.platform === "win32") {
          const literal = file.replaceAll("'", "''");
          await runPowerShell(`attrib +H +S '${literal}'`, 10000).catch(() => {});
        }
        fs.watchFile(file, { interval: 1500, persistent: false }, () => this.checkCanary(file));
      } catch (error) {
        this.onEvent({ type: "ransomware.canary-error", path: file, error: error.message });
      }
    }
    await ensureDirectory(path.dirname(appPaths().canaryManifest));
    await writeJsonAtomic(appPaths().canaryManifest, {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      files: this.canaryFiles.map(({ file, expected }) => ({ file, expected }))
    });
  }

  async checkCanary(file) {
    if (!this.running) return;
    const canary = this.canaryFiles.find((item) => item.file === file);
    if (!canary || canary.alerting) return;
    let actual = null;
    try {
      actual = crypto.createHash("sha256").update(await fsp.readFile(file)).digest("hex");
    } catch {}
    if (actual === canary.expected) return;
    canary.alerting = true;
    this.canaryAlerts += 1;
    this.onEvent({ type: "ransomware.canary-tampered", path: file, missing: actual === null });
    await appendAudit("ransomware.canary-tampered", { path: file, missing: actual === null });
  }

  observeFileEvent(file) {
    if (!this.config.monitoring.ransomwareEnabled) return;
    const now = Date.now();
    this.fileEvents.push({ at: now, file });
    const cutoff = now - this.config.monitoring.ransomwareBurstWindowMs;
    while (this.fileEvents[0]?.at < cutoff) this.fileEvents.shift();
    if (this.fileEvents.length >= this.config.monitoring.ransomwareBurstEvents &&
        now - this.lastBurstAlert > 60000) {
      this.lastBurstAlert = now;
      this.ransomwareBurstAlerts += 1;
      const uniqueDirectories = new Set(this.fileEvents.map((item) => path.dirname(item.file))).size;
      this.onEvent({
        type: "ransomware.write-burst",
        events: this.fileEvents.length,
        uniqueDirectories,
        windowMs: this.config.monitoring.ransomwareBurstWindowMs
      });
      appendAudit("ransomware.write-burst", {
        events: this.fileEvents.length,
        uniqueDirectories,
        windowMs: this.config.monitoring.ransomwareBurstWindowMs
      }).catch(() => {});
    }
  }

  async pollRemovable() {
    const drives = await discoverRemovableDrives();
    const next = new Set(drives.map((drive) => drive.root.toLowerCase()));
    for (const drive of drives) {
      if (this.removableBaseline.has(drive.root.toLowerCase())) continue;
      this.removableArrivals += 1;
      this.onEvent({ type: "removable.arrived", drive });
      await appendAudit("removable.arrived", drive);
      this.onRemovableDrive(drive);
    }
    this.removableBaseline = next;
  }

  async pollFirewall() {
    const snapshot = await readFirewallSnapshot();
    const priorProfiles = stableValue(this.firewallBaseline.profiles);
    const nextProfiles = stableValue(snapshot.profiles);
    const priorRules = new Map(this.firewallBaseline.inboundAllows.map((item) => [item.Name, stableValue(item)]));
    const changes = [];
    if (priorProfiles !== nextProfiles) changes.push({ kind: "profiles", profiles: snapshot.profiles });
    for (const rule of snapshot.inboundAllows) {
      if (!priorRules.has(rule.Name)) changes.push({ kind: "inbound-allow-added", rule });
    }
    for (const change of changes.slice(0, 50)) {
      this.firewallChanges += 1;
      this.onEvent({ type: "firewall.change", change });
      await appendAudit("firewall.change", change);
    }
    this.firewallBaseline = snapshot;
  }

  status() {
    return {
      running: this.running,
      enabled: {
        process: this.config.monitoring.processEnabled,
        persistence: this.config.monitoring.persistenceEnabled,
        ransomware: this.config.monitoring.ransomwareEnabled,
        windowsEvents: this.config.monitoring.windowsEventsEnabled,
        removableMedia: this.config.monitoring.removableMediaEnabled,
        firewallIntegrity: this.config.monitoring.firewallIntegrityEnabled
      },
      processesObserved: this.processesObserved,
      processStarts: this.processStarts,
      processDetections: this.processDetections,
      persistenceChanges: this.persistenceChanges,
      securityEvents: this.securityEvents,
      canaries: this.canaryFiles.length,
      canaryAlerts: this.canaryAlerts,
      ransomwareBurstAlerts: this.ransomwareBurstAlerts,
      removableArrivals: this.removableArrivals,
      firewallChanges: this.firewallChanges,
      errors: this.errors,
      lastPolls: this.lastPolls
    };
  }

  async stop() {
    this.running = false;
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    for (const { file } of this.canaryFiles) fs.unwatchFile(file);
    this.threatIndex?.close();
    this.threatIndex = null;
    await appendAudit("advanced-monitoring.stopped");
  }
}
