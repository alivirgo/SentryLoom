import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { scanFile, scanPath } from "./scanner.js";
import { compileSignatures, loadSignatures } from "./signature-store.js";
import { quarantineFile } from "./quarantine.js";
import { appendAudit } from "./audit-log.js";
import { appPaths } from "../constants.js";
import { isPathInside, matchesExclusion } from "./fs-safe.js";
import { openThreatIndex } from "./threat-index.js";

export function isDownloadsPath(file, downloadsDirectory = path.join(os.homedir(), "Downloads")) {
  return isPathInside(path.resolve(file), path.resolve(downloadsDirectory));
}

export async function waitForStableFile(file, options = {}) {
  const intervalMs = Math.max(25, Number(options.intervalMs) || 300);
  const stableChecks = Math.max(1, Number(options.stableChecks) || 2);
  const timeoutMs = Math.max(intervalMs, Number(options.timeoutMs) || 30000);
  const expiresAt = Date.now() + timeoutMs;
  let previous = null;
  let unchanged = 0;

  while (Date.now() <= expiresAt) {
    const stat = await fsp.lstat(file).catch(() => null);
    if (!stat?.isFile() || stat.isSymbolicLink()) return null;
    const fingerprint = `${stat.size}:${stat.mtimeMs}`;
    if (fingerprint === previous) {
      unchanged += 1;
      if (unchanged >= stableChecks) return stat;
    } else {
      previous = fingerprint;
      unchanged = 0;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  const error = new Error("File did not finish writing before the deep-scan timeout");
  error.code = "EBUSY";
  throw error;
}

export class RealtimeProtection {
  constructor(config, onEvent = () => {}, options = {}) {
    this.config = config;
    this.onEvent = onEvent;
    this.onFileChange = options.onFileChange || (() => {});
    this.deepScanPath = options.deepScanPath || scanPath;
    this.stabilizeFile = options.stabilizeFile || waitForStableFile;
    this.watchers = [];
    this.downloadWatcher = null;
    this.downloadsTarget = path.join(os.homedir(), "Downloads");
    this.pending = new Map();
    this.scanQueue = [];
    this.priorityScanQueue = [];
    this.recentDeepScans = new Map();
    this.activeDeepFiles = new Set();
    this.deepRescanRequested = new Set();
    this.activeScans = 0;
    this.droppedEvents = 0;
    this.filesInspected = 0;
    this.detections = 0;
    this.downloadsDeepScans = 0;
    this.downloadsDeepDetections = 0;
    this.targets = [];
    this.running = false;
  }

  async start(targets) {
    if (this.running) return;
    if (!Array.isArray(targets) || !targets.length) throw new Error("At least one realtime monitoring target is required");
    this.signatures = compileSignatures(await loadSignatures());
    this.threatIndex = await openThreatIndex();
    this.signatures.threatIndex = this.threatIndex;
    for (const target of targets) {
      try {
        if (!(await fsp.stat(target)).isDirectory()) continue;
        const watcher = fs.watch(target, { recursive: true }, (_event, filename) => {
          if (!filename) return;
          this.queue(path.join(target, String(filename)));
        });
        watcher.on("error", (error) => this.onEvent({ type: "watch.error", target, error: error.message }));
        this.watchers.push(watcher);
      } catch (error) {
        this.onEvent({ type: "watch.error", target, error: error.message });
      }
    }
    if (this.config.protection.downloadsDeepScanEnabled) {
      try {
        if ((await fsp.stat(this.downloadsTarget)).isDirectory()) {
          this.downloadWatcher = fs.watch(
            this.downloadsTarget,
            { recursive: true },
            (_event, filename) => {
              if (!filename) return;
              this.queue(path.join(this.downloadsTarget, String(filename)), { deep: true });
            }
          );
          this.downloadWatcher.on("error", (error) => this.onEvent({
            type: "downloads.watch-error",
            target: this.downloadsTarget,
            error: error.message
          }));
        }
      } catch (error) {
        if (error.code !== "ENOENT") {
          this.onEvent({ type: "downloads.watch-error", target: this.downloadsTarget, error: error.message });
        }
      }
    }
    this.targets = targets.slice();
    this.running = this.watchers.length > 0 || Boolean(this.downloadWatcher);
    await appendAudit("protection.started", {
      targets,
      activeWatchers: this.watchers.length,
      downloadsDeepScan: Boolean(this.downloadWatcher),
      downloadsTarget: this.downloadsTarget
    });
  }

  queue(file, options = {}) {
    const resolved = path.resolve(file);
    const existing = this.pending.get(resolved);
    const deep = Boolean(
      this.config.protection.downloadsDeepScanEnabled &&
      (options.deep || isDownloadsPath(resolved, this.downloadsTarget))
    );
    this.onFileChange(resolved);
    clearTimeout(existing?.timeout);
    if (!existing && this.pending.size >= this.config.scanner.maxPendingRealtimeFiles) {
      const [oldest, entry] = this.pending.entries().next().value;
      clearTimeout(entry.timeout);
      this.pending.delete(oldest);
      this.droppedEvents += 1;
    }
    const work = { file: resolved, deep: deep || Boolean(existing?.deep) };
    work.timeout = setTimeout(() => {
      this.pending.delete(resolved);
      const queue = work.deep ? this.priorityScanQueue : this.scanQueue;
      queue.push({ file: work.file, deep: work.deep });
      this.pump();
    }, work.deep ? 250 : 1000);
    this.pending.set(resolved, work);
  }

  pump() {
    while (this.running &&
           this.activeScans < this.config.scanner.realtimeConcurrency &&
           (this.priorityScanQueue.length || this.scanQueue.length)) {
      const work = this.priorityScanQueue.shift() || this.scanQueue.shift();
      this.activeScans += 1;
      this.inspect(work.file, { deep: work.deep }).catch((error) => {
        if (!["ENOENT", "EBUSY", "EACCES", "EPERM"].includes(error.code)) {
          this.onEvent({ type: "scan.error", path: work.file, error: error.message });
        }
      }).finally(() => {
        this.activeScans -= 1;
        this.pump();
      });
    }
  }

  async handleDetection(result, source, deep = false) {
    this.detections += 1;
    if (deep) this.downloadsDeepDetections += 1;
    this.onEvent({ type: "detection", result, source: deep ? "downloads-deep-scan" : "realtime" });
    const confirmed = result.findings.some((finding) => finding.confirmed);
    const shouldQuarantine = confirmed
      ? this.config.protection.autoQuarantineConfirmed
      : this.config.protection.autoQuarantineHeuristics;
    if (shouldQuarantine && !result.virtual) {
      try {
        const item = await quarantineFile(source, result);
        this.onEvent({ type: "quarantined", result, item });
      } catch (error) {
        this.onEvent({ type: "quarantine.error", result, error: error.message });
      }
    }
  }

  async inspect(file, options = {}) {
    if (isPathInside(file, appPaths().data) || matchesExclusion(file, this.config.scanner.exclusions)) return;
    const deep = Boolean(options.deep && this.config.protection.downloadsDeepScanEnabled);
    const stat = deep
      ? await this.stabilizeFile(file)
      : await fsp.lstat(file).catch(() => null);
    if (!stat?.isFile() || stat.isSymbolicLink()) return;

    if (deep) {
      if (this.activeDeepFiles.has(file)) {
        this.deepRescanRequested.add(file);
        return;
      }
      this.activeDeepFiles.add(file);
      try {
        const fingerprint = `${stat.size}:${stat.mtimeMs}`;
        if (this.recentDeepScans.get(file) === fingerprint) return;
        const report = await this.deepScanPath(file, {
          config: this.config.scanner,
          clamavEngineEnabled: this.config.threatIntel.clamavEngineEnabled
        });
        this.recentDeepScans.set(file, fingerprint);
        if (this.recentDeepScans.size > 2000) {
          this.recentDeepScans.delete(this.recentDeepScans.keys().next().value);
        }
        this.filesInspected += report.scanned;
        this.downloadsDeepScans += report.scanned;
        if (report.errors.length) {
          this.onEvent({
            type: "downloads.deep-scan-warning",
            path: file,
            errors: report.errors.slice(0, 5)
          });
        }
        for (const result of report.results.filter((item) => item.status === "detected")) {
          await this.handleDetection(result, result.virtual ? file : result.path, true);
        }
      } finally {
        this.activeDeepFiles.delete(file);
        if (this.deepRescanRequested.delete(file) && this.running) {
          this.queue(file, { deep: true });
        }
      }
      return;
    }

    const result = await scanFile(file, {
      config: this.config.scanner,
      signatures: this.signatures
    });
    this.filesInspected += 1;
    if (result.status !== "detected") return;
    await this.handleDetection(result, file);
  }

  async stop() {
    for (const watcher of this.watchers) watcher.close();
    this.downloadWatcher?.close();
    for (const entry of this.pending.values()) clearTimeout(entry.timeout);
    this.watchers = [];
    this.downloadWatcher = null;
    this.pending.clear();
    this.scanQueue = [];
    this.priorityScanQueue = [];
    this.recentDeepScans.clear();
    this.activeDeepFiles.clear();
    this.deepRescanRequested.clear();
    this.activeScans = 0;
    this.targets = [];
    this.threatIndex?.close();
    this.threatIndex = null;
    this.running = false;
    await appendAudit("protection.stopped");
  }

  status() {
    return {
      running: this.running,
      watchers: this.watchers.length,
      targets: this.targets,
      queuedFiles: this.pending.size + this.scanQueue.length + this.priorityScanQueue.length,
      activeScans: this.activeScans,
      droppedEvents: this.droppedEvents,
      filesInspected: this.filesInspected,
      detections: this.detections,
      downloadsDeepScan: {
        enabled: this.config.protection.downloadsDeepScanEnabled,
        running: Boolean(this.downloadWatcher),
        target: this.downloadsTarget,
        queuedFiles: this.priorityScanQueue.length +
          [...this.pending.values()].filter((entry) => entry.deep).length,
        filesInspected: this.downloadsDeepScans,
        detections: this.downloadsDeepDetections
      }
    };
  }
}
