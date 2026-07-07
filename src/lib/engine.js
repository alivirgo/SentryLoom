import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { loadConfig, saveConfig } from "./config.js";
import { scanPath, quickScanTargets } from "./scanner.js";
import { quarantineFile, listQuarantine, restoreQuarantine, deleteQuarantine } from "./quarantine.js";
import { saveScanJobSummary, readScanHistory } from "./history.js";
import { appendAudit, readRecentAudit, verifyAuditLog } from "./audit-log.js";
import { signatureStatus } from "./signature-store.js";
import { RealtimeProtection } from "./protection.js";
import { APP_VERSION, SEVERITY_RANK, appPaths } from "../constants.js";
import { ThreatUpdateManager } from "./threat-update-manager.js";
import { saveThreatCredentials, threatCredentialStatus } from "./credential-store.js";
import { clamAvEngineStatus } from "./clamav-engine.js";
import { NetworkMonitor } from "./network-monitor.js";
import { discoverFixedDrives, isProcessElevated } from "./windows-monitoring.js";
import {
  applyDnsProfile,
  dnsFilteringStatus,
  restoreDnsConfiguration
} from "./windows-dns.js";
import { AdvancedMonitoring } from "./advanced-monitoring.js";
import {
  blockThreatIp,
  clearThreatFirewallRules,
  firewallPolicyStatus
} from "./firewall-policy.js";
import { isIP } from "node:net";
import { openThreatIndex } from "./threat-index.js";
import {
  discoverExternalDriveTargets,
  discoverProcessImageTargets,
  discoverStartupTargets
} from "./scan-targets.js";
import {
  calculateSecurityPosture,
  RECOMMENDED_PROTECTION_CONFIG
} from "./security-posture.js";
import { setUsbStorageBlocked, usbStorageStatus } from "./windows-usb-control.js";
import { showPlatformPathPicker } from "./platform-path-picker.js";
import { notificationForEvent, showDetectionNotification } from "./platform-notifications.js";
import { consumeUiCommand } from "./ui-command.js";
import {
  acquireHqConnectorLease,
  authorizeHqMaintenance,
  discoverHqServers,
  enrollWithHq,
  HqEnrollmentPoller,
  HqConnector,
  recoverHqAddress,
  relocateHq as relocateHqCredentials,
  requestHqEnrollment,
  requestHqMaintenancePassword
} from "./hq-client.js";
import {
  clearHqCredentials,
  clearPendingHqEnrollment,
  loadHqCredentials,
  loadPendingHqEnrollment
} from "./hq-credential-store.js";
import { getDeviceIdentity } from "./device-identity.js";
import { getClientUpdateStatus, stageClientUpdate } from "./client-update.js";
import { readJson, writeJsonAtomic } from "./fs-safe.js";
import { collectWakeNetworkInterfaces } from "./network-identity.js";
import { platformDescriptor, supportedCommands } from "./platform-capabilities.js";
import { collectSystemInformation } from "./system-information.js";

const HQ_SENSITIVE_FIELD = /(?:password|secret|token|authkey|credential|masterkey|privatekey|controller)/i;

function sanitizeHqValue(value, depth = 0) {
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") {
    return value ?? null;
  }
  if (typeof value === "string") return value.slice(0, 2048);
  if (depth >= 6) return "[nested data omitted]";
  if (Array.isArray(value)) return value.slice(0, 25).map((item) => sanitizeHqValue(item, depth + 1));
  if (Buffer.isBuffer(value)) return `[binary data: ${value.length} bytes]`;
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !HQ_SENSITIVE_FIELD.test(key))
        .map(([key, item]) => [key, sanitizeHqValue(item, depth + 1)])
    );
  }
  return String(value).slice(0, 4096);
}

function summarizeScan(scan) {
  if (!scan) return null;
  return {
    id: scan.id,
    type: scan.type || null,
    target: scan.target || null,
    targets: scan.targets || null,
    signatureVersion: scan.signatureVersion || null,
    startedAt: scan.startedAt,
    endedAt: scan.endedAt || null,
    durationMs: scan.durationMs ?? null,
    scanned: scan.scanned ?? 0,
    skipped: scan.skipped ?? 0,
    detections: scan.detections ?? 0,
    errorCount: scan.errorCount ?? 0,
    detectedFiles: (scan.detectedFiles || []).slice(0, 25).map((file) => ({
      path: file.path,
      status: file.status,
      sha256: file.sha256 || null,
      size: file.size ?? null,
      findings: sanitizeHqValue(file.findings || [])
    }))
  };
}

export class AntivirusEngine {
  constructor() {
    this.config = null;
    this.protection = null;
    this.events = [];
    this.activeScan = null;
    this.lastScanProgress = null;
    this.notificationKeys = new Map();
    this.hqConnector = null;
    this.hqEnrollmentPoller = null;
    this.hqLeaseRelease = null;
    this.hqDelegated = false;
    this.hqManagementRetryTimer = null;
    this.hqReEnrollmentPromise = null;
    this.hqControlTelemetry = null;
  }

  async initialize() {
    this.config = await loadConfig();
    this.elevated = await isProcessElevated();
    this.threatUpdates = new ThreatUpdateManager(this.config, (event) => this.emit(event));
    this.firewallBlocks = 0;
    await appendAudit("application.initialized", { version: APP_VERSION });
    return this;
  }

  emit(event) {
    const enriched = { id: crypto.randomUUID(), at: new Date().toISOString(), ...event };
    this.events.unshift(enriched);
    this.events = this.events.slice(0, 200);
    this.notifyForEvent(enriched);
    return enriched;
  }

  notifyForEvent(event) {
    const notification = notificationForEvent(event);
    if (!notification) return;
    const now = Date.now();
    for (const [key, at] of this.notificationKeys) {
      if (now - at > 5 * 60 * 1000) this.notificationKeys.delete(key);
    }
    if (this.notificationKeys.has(notification.key)) return;
    this.notificationKeys.set(notification.key, now);
    showDetectionNotification(notification);
  }

  async startProtection(targets) {
    if (this.protection?.running && this.networkMonitor?.running && this.advancedMonitoring?.running) return;
    const resolvedTargets = targets?.length
      ? targets.map((target) => path.resolve(target))
      : this.config.protection.monitorAllFixedDrives
        ? await discoverFixedDrives()
        : [os.homedir()];
    if (!this.advancedMonitoring?.running) {
      this.advancedMonitoring = new AdvancedMonitoring(this.config, (event) => this.emit(event), {
        onRemovableDrive: (drive) => this.handleRemovableDrive(drive)
      });
      await this.advancedMonitoring.start();
    }
    if (!this.protection?.running) {
      this.protection = new RealtimeProtection(this.config, (event) => this.emit(event), {
        onFileChange: (file) => this.advancedMonitoring?.observeFileEvent(file)
      });
      await this.protection.start(resolvedTargets);
    }
    if (!this.networkMonitor?.running) {
      this.networkMonitor = new NetworkMonitor(this.config, (event) => this.emit(event), {
        onDetection: (detection) => this.handleNetworkDetection(detection)
      });
      await this.networkMonitor.start();
    }
    await this.startManagement();
  }

  async stopProtection() {
    await this.protection?.stop();
    await this.networkMonitor?.stop();
    await this.advancedMonitoring?.stop();
  }

  async startManagement() {
    if (!this.config.management.enabled || this.hqConnector?.running || this.hqEnrollmentPoller?.running) return;
    const credentials = await loadHqCredentials();
    const pending = credentials ? null : await loadPendingHqEnrollment();
    if (!credentials && !pending) {
      this.emit({ type: "hq.connection-error", error: "Managed mode is enabled but enrollment credentials are missing" });
      return;
    }
    this.hqLeaseRelease = await acquireHqConnectorLease();
    if (!this.hqLeaseRelease) {
      this.hqDelegated = true;
      this.scheduleManagementRetry();
      return;
    }
    clearTimeout(this.hqManagementRetryTimer);
    this.hqManagementRetryTimer = null;
    this.hqDelegated = false;
    if (credentials) {
      this.activateHqConnector(credentials);
    } else {
      const poller = new HqEnrollmentPoller(pending, {
        onApproved: async (approvedCredentials) => {
          this.hqEnrollmentPoller = null;
          this.activateHqConnector(approvedCredentials);
          this.emit({ type: "hq.enrollment-approved", hqName: approvedCredentials.hqName });
          await appendAudit("hq.enrollment-approved", {
            hqName: approvedCredentials.hqName,
            deviceId: approvedCredentials.deviceId
          });
        },
        onTerminal: async (result) => {
          this.emit({
            type: `hq.enrollment-${result.status}`,
            hqName: pending.hqName,
            serverUrl: pending.serverUrl,
            message: result.message
          });
          try {
            await appendAudit(`hq.enrollment-${result.status}`, {
              hqName: pending.hqName,
              serverUrl: pending.serverUrl,
              requestId: pending.requestId
            });
          } finally {
            if (this.hqEnrollmentPoller === poller) {
              await this.stopManagement();
            }
          }
        }
      });
      this.hqEnrollmentPoller = poller;
      poller.start();
    }
  }

  activateHqConnector(credentials) {
    const connector = new HqConnector(credentials, {
      metricsProvider: () => this.getHqTelemetry(),
      commandExecutor: (command) => this.executeHqCommand(command),
      addressRecovery: (currentCredentials) => recoverHqAddress(currentCredentials),
      onEvent: (event) => {
        this.emit(event);
        if (event.type === "hq.reauthorization-required") {
          void this.beginHqReEnrollment(connector.credentials).catch(() => {});
        }
      },
      stateWriter: (state) => writeJsonAtomic(appPaths().hqConnectorState, state)
    });
    this.hqConnector = connector;
    connector.start();
  }

  beginHqReEnrollment(credentials) {
    if (this.hqReEnrollmentPromise) return this.hqReEnrollmentPromise;
    this.hqReEnrollmentPromise = (async () => {
      await this.stopManagement();
      try {
        const pending = await requestHqEnrollment({
          serverUrl: credentials.serverUrl,
          fingerprint256: credentials.fingerprint256
        });
        await appendAudit("hq.reenrollment-requested", {
          hqName: pending.hqName,
          serverUrl: pending.serverUrl,
          requestId: pending.requestId,
          reason: "saved device credential was rejected"
        });
        await this.startManagement();
        this.emit({
          type: "hq.reenrollment-pending",
          hqName: pending.hqName,
          serverUrl: pending.serverUrl,
          message: "HQ re-enrollment is waiting for administrator approval"
        });
        return pending;
      } catch (error) {
        this.emit({
          type: "hq.reenrollment-error",
          hqName: credentials.hqName,
          serverUrl: credentials.serverUrl,
          error: error.message
        });
        throw error;
      }
    })().finally(() => {
      this.hqReEnrollmentPromise = null;
    });
    return this.hqReEnrollmentPromise;
  }

  scheduleManagementRetry() {
    clearTimeout(this.hqManagementRetryTimer);
    if (!this.config.management.enabled || !this.hqDelegated) return;
    this.hqManagementRetryTimer = setTimeout(async () => {
      this.hqManagementRetryTimer = null;
      try {
        await this.startManagement();
      } catch (error) {
        this.emit({ type: "hq.connection-error", error: error.message });
        this.scheduleManagementRetry();
      }
    }, 5000);
    this.hqManagementRetryTimer.unref?.();
  }

  async stopManagement() {
    clearTimeout(this.hqManagementRetryTimer);
    this.hqManagementRetryTimer = null;
    this.hqConnector?.stop();
    this.hqConnector = null;
    this.hqEnrollmentPoller?.stop();
    this.hqEnrollmentPoller = null;
    await this.hqLeaseRelease?.();
    this.hqLeaseRelease = null;
    this.hqDelegated = false;
  }

  handleRemovableDrive(drive) {
    if (this.activeScan) {
      this.emit({ type: "removable.scan-deferred", drive, reason: "another scan is active" });
      return;
    }
    this.runScan("path", drive.root).catch((error) => {
      this.emit({ type: "removable.scan-error", drive, error: error.message });
    });
  }

  async handleNetworkDetection({ observation, matches }) {
    if (!this.config.monitoring.firewallBlockHighConfidence) return;
    const address = observation.remote?.host;
    if (!isIP(address)) return;
    const highConfidence = matches.filter((match) => Number(match.confidence || 0) >= 90);
    if (!highConfidence.length) return;
    const result = await blockThreatIp(address, highConfidence);
    if (result.blocked) {
      this.firewallBlocks += 1;
      this.emit({ type: "firewall.ioc-blocked", address, matches: highConfidence });
    } else {
      this.emit({ type: "firewall.block-unavailable", address, reason: result.reason });
    }
  }

  async scanTargetsForType(type, requestedPath) {
    if (type === "quick") return quickScanTargets();
    if (type === "full") {
      const drive = process.env.SystemDrive || path.parse(process.cwd()).root;
      return [drive.endsWith(path.sep) ? drive : `${drive}${path.sep}`];
    }
    if (type === "path" && requestedPath) return [path.resolve(requestedPath)];
    if (type === "startup") return discoverStartupTargets();
    if (type === "processes") return discoverProcessImageTargets();
    if (type === "external") return discoverExternalDriveTargets();
    throw new Error("Scan type must be quick, full, startup, processes, external, or path with a target");
  }

  async runScan(type, requestedPath, options = {}) {
    if (this.activeScan) throw new Error("A scan is already running");
    const job = {
      id: crypto.randomUUID(),
      type,
      targets: [],
      startedAt: new Date().toISOString(),
      status: "discovering",
      controller: new AbortController()
    };
    this.activeScan = job;
    this.lastScanProgress = { completed: 0, total: 0, current: null };
    const reports = [];
    try {
      const targets = await this.scanTargetsForType(type, requestedPath);
      job.targets = targets;
      job.status = "running";
      this.emit({ type: "scan.started", job: { ...job, controller: undefined } });
      for (const target of targets) {
        try {
          const report = await scanPath(target, {
            config: this.config.scanner,
            clamavEngineEnabled: this.config.threatIntel.clamavEngineEnabled,
            signal: job.controller.signal,
            onProgress: (progress) => {
              this.lastScanProgress = progress;
              options.onProgress?.(progress);
            }
          });
          for (const result of report.results.filter((item) => item.status === "detected")) {
            const confirmed = result.findings.some((finding) => finding.confirmed);
            const auto = confirmed
              ? this.config.protection.autoQuarantineConfirmed
              : this.config.protection.autoQuarantineHeuristics;
            if (auto && options.autoQuarantine !== false && !result.virtual) {
              try {
                result.quarantine = await quarantineFile(result.path, result);
              } catch (error) {
                result.quarantineError = error.message;
              }
            }
          }
          reports.push(report);
        } catch (error) {
          if (error.code === "ENOENT") {
            reports.push({ target, scanned: 0, skipped: 0, detections: 0, errors: [{ path: target, error: "Target not found" }], results: [] });
          } else {
            throw error;
          }
        }
      }
      const result = {
        id: job.id,
        type,
        targets: job.targets,
        startedAt: job.startedAt,
        endedAt: new Date().toISOString(),
        scanned: reports.reduce((sum, report) => sum + report.scanned, 0),
        skipped: reports.reduce((sum, report) => sum + report.skipped, 0),
        detections: reports.reduce((sum, report) => sum + report.detections, 0),
        errorCount: reports.reduce((sum, report) => sum + report.errors.length, 0),
        reports
      };
      job.status = "completed";
      await saveScanJobSummary(result);
      await appendAudit("scan.completed", {
        id: job.id,
        type,
        scanned: result.scanned,
        detections: result.detections,
        errors: result.errorCount
      });
      this.emit({ type: "scan.completed", result });
      return result;
    } catch (error) {
      job.status = job.controller.signal.aborted ? "cancelled" : "failed";
      await appendAudit(`scan.${job.status}`, { id: job.id, type, error: error.message });
      this.emit({ type: `scan.${job.status}`, error: error.message });
      throw error;
    } finally {
      this.activeScan = null;
    }
  }

  cancelScan() {
    if (!this.activeScan) return false;
    this.activeScan.controller.abort();
    return true;
  }

  async getStatus(options = {}) {
    const [signatures, audit, quarantine, history, credentials, clamavEngine, navigation] = await Promise.all([
      signatureStatus(),
      verifyAuditLog(),
      listQuarantine(),
      readScanHistory(10),
      threatCredentialStatus(),
      clamAvEngineStatus(),
      options.consumeNavigation === false ? null : consumeUiCommand()
    ]);
    const active = this.activeScan
      ? { ...this.activeScan, controller: undefined }
      : null;
    const status = {
      healthy: audit.valid,
      protection: {
        enabled: this.config.protection.realtimeEnabled,
        monitorAllFixedDrives: this.config.protection.monitorAllFixedDrives,
        elevated: this.elevated,
        file: this.protection?.status() || {
          running: false,
          watchers: 0,
          targets: [],
          queuedFiles: 0,
          activeScans: 0,
          droppedEvents: 0,
          filesInspected: 0,
          detections: 0,
          downloadsDeepScan: {
            enabled: this.config.protection.downloadsDeepScanEnabled,
            running: false,
            target: path.join(os.homedir(), "Downloads"),
            queuedFiles: 0,
            filesInspected: 0,
            detections: 0
          }
        },
        network: this.networkMonitor?.status() || {
          enabled: this.config.protection.networkMonitoringEnabled,
          running: false,
          tcpConnectionMetadata: true,
          dnsCacheMonitoring: this.config.protection.dnsMonitoringEnabled,
          packetInspection: false,
          connectionsObserved: 0,
          dnsEntriesObserved: 0,
          detections: 0,
          errors: 0,
          lastConnectionPoll: null,
          lastDnsPoll: null
        },
        advanced: this.advancedMonitoring?.status() || {
          running: false,
          enabled: {
            process: this.config.monitoring.processEnabled,
            persistence: this.config.monitoring.persistenceEnabled,
            ransomware: this.config.monitoring.ransomwareEnabled,
            windowsEvents: this.config.monitoring.windowsEventsEnabled,
            removableMedia: this.config.monitoring.removableMediaEnabled,
            firewallIntegrity: this.config.monitoring.firewallIntegrityEnabled
          },
          processesObserved: 0,
          processStarts: 0,
          processDetections: 0,
          persistenceChanges: 0,
          securityEvents: 0,
          canaries: 0,
          canaryAlerts: 0,
          ransomwareBurstAlerts: 0,
          removableArrivals: 0,
          firewallChanges: 0,
          errors: 0,
          lastPolls: {}
        },
        firewallEnforcement: {
          enabled: this.config.monitoring.firewallBlockHighConfidence,
          blockedThisSession: this.firewallBlocks,
          implementation: process.platform === "win32"
            ? "Windows Defender Firewall (WFP)"
            : process.platform === "linux" ? "Linux nftables" : "Platform firewall monitoring"
        },
        running: Boolean(this.protection?.running),
        watchers: this.protection?.watchers.length || 0
      },
      signatures,
      clamavEngine,
      threatUpdates: {
        running: this.threatUpdates?.running || false,
        progress: this.threatUpdates?.progress || null,
        lastResult: this.threatUpdates?.lastResult || null,
        credentials
      },
      audit,
      quarantineCount: quarantine.filter((item) => (
        item.state === "quarantined" || item.state === "orphaned"
      )).length,
      lastScan: history[0] || null,
      activeScan: active,
      progress: active ? this.lastScanProgress : null,
      events: this.events.slice(0, 30),
      navigation,
      management: await this.getHqStatus(),
      runtime: {
        rssBytes: process.memoryUsage().rss,
        heapUsedBytes: process.memoryUsage().heapUsed,
        uptimeSeconds: Math.round(process.uptime())
      }
    };
    status.posture = calculateSecurityPosture(status, this.config);
    return status;
  }

  async getDashboardData() {
    const [status, quarantine, history, audit, dnsFiltering, firewallPolicy, deviceControl] = await Promise.all([
      this.getStatus(),
      listQuarantine(),
      readScanHistory(30),
      readRecentAudit(50),
      this.getDnsFilteringStatus(),
      this.getFirewallPolicyStatus(),
      this.getDeviceControlStatus()
    ]);
    return { status, quarantine, history, audit, config: this.config, dnsFiltering, firewallPolicy, deviceControl };
  }

  async updateConfig(update) {
    this.config = await saveConfig(update);
    await appendAudit("configuration.updated", { sections: Object.keys(update) });
    return this.config;
  }

  async getHqStatus() {
    const credentials = await loadHqCredentials().catch(() => null);
    if (this.hqConnector) return this.hqConnector.status();
    if (this.hqEnrollmentPoller) return this.hqEnrollmentPoller.status();
    const pending = credentials ? null : await loadPendingHqEnrollment().catch(() => null);
    const delegatedState = this.hqDelegated
      ? await readJson(appPaths().hqConnectorState, null).catch(() => null)
      : null;
    const delegatedStateFresh = delegatedState?.updatedAt &&
      Date.now() - new Date(delegatedState.updatedAt).getTime() < 60000;
    return {
      enabled: this.config.management.enabled,
      running: Boolean(delegatedStateFresh && delegatedState.running),
      delegated: this.hqDelegated,
      enrolled: Boolean(credentials),
      pending: pending?.status === "pending",
      rejected: pending?.status === "rejected",
      verificationFailed: pending?.status === "verification-failed",
      verificationCode: pending?.verificationCode || null,
      approvalStatus: pending?.status || null,
      hqName: credentials?.hqName || pending?.hqName || null,
      serverUrl: credentials?.serverUrl || pending?.serverUrl || null,
      deviceId: credentials?.deviceId || null,
      enrolledAt: credentials?.enrolledAt || null,
      connectionState: delegatedStateFresh
        ? delegatedState.connectionState
        : this.hqDelegated ? "offline" : "stopped",
      connected: Boolean(delegatedStateFresh && delegatedState.running && delegatedState.connected),
      consecutiveFailures: delegatedStateFresh ? delegatedState.consecutiveFailures || 0 : 0,
      lastAttemptAt: delegatedStateFresh ? delegatedState.lastAttemptAt || null : null,
      lastConnectedAt: delegatedState?.lastConnectedAt || null,
      lastErrorAt: delegatedStateFresh ? delegatedState.lastErrorAt || null : null,
      lastResumeAt: delegatedStateFresh ? delegatedState.lastResumeAt || null : null,
      lastError: delegatedStateFresh
        ? delegatedState.lastError || null
        : this.hqDelegated ? "Background protection agent is not reporting management status" : null,
      nextRetryAt: delegatedStateFresh ? delegatedState.nextRetryAt || null : null,
      activeCommands: delegatedStateFresh ? delegatedState.activeCommands || 0 : 0,
      hqVersion: delegatedStateFresh ? delegatedState.hqVersion || null : null,
      hqCapabilities: delegatedStateFresh && Array.isArray(delegatedState.hqCapabilities)
        ? delegatedState.hqCapabilities
        : [],
      maintenanceAuthorizationSupported: delegatedStateFresh
        ? delegatedState.maintenanceAuthorizationSupported === true
          ? true
          : delegatedState.maintenanceAuthorizationSupported === false ? false : null
        : null,
      reEnrollmentRequired: Boolean(
        delegatedStateFresh && delegatedState.reEnrollmentRequired
      ),
      lastAddressRecoveryAt: delegatedStateFresh
        ? delegatedState.lastAddressRecoveryAt || null
        : null
    };
  }

  async discoverHq() {
    return discoverHqServers();
  }

  async enrollHq(options) {
    const credentials = await enrollWithHq(options);
    this.config = await saveConfig({ management: { enabled: true } });
    await this.stopManagement();
    await this.startManagement();
    await appendAudit("hq.enrolled", {
      hqName: credentials.hqName,
      serverUrl: credentials.serverUrl,
      deviceId: credentials.deviceId,
      fingerprint256: credentials.fingerprint256
    });
    return this.getHqStatus();
  }

  async requestHqEnrollment(options = {}) {
    await this.stopManagement();
    try {
      const pending = await requestHqEnrollment(options);
      this.config = await saveConfig({ management: { enabled: true } });
      await this.startManagement();
      await appendAudit("hq.enrollment-requested", {
        hqName: pending.hqName,
        serverUrl: pending.serverUrl,
        requestId: pending.requestId,
        fingerprint256: pending.fingerprint256
      });
      return this.getHqStatus();
    } catch (error) {
      // A typo, unreachable replacement server, or rejected certificate must
      // not leave the current HQ connector stopped. Credentials are removed
      // only after the new server accepts the enrollment request.
      await this.startManagement().catch(() => {});
      throw error;
    }
  }

  async reEnrollHq() {
    const credentials = await loadHqCredentials();
    if (!credentials) {
      throw new Error("The pinned HQ credential needed for re-enrollment is missing");
    }
    return this.requestHqEnrollment({
      serverUrl: credentials.serverUrl,
      fingerprint256: credentials.fingerprint256
    });
  }

  async relocateHq(serverUrl) {
    const credentials = await loadHqCredentials();
    if (!credentials) {
      throw new Error("The pinned HQ credential needed for address recovery is missing");
    }
    await this.stopManagement();
    try {
      const relocated = await relocateHqCredentials(credentials, { serverUrl });
      await appendAudit("hq.address-relocated", {
        hqName: relocated.hqName,
        previousServerUrl: credentials.serverUrl,
        serverUrl: relocated.serverUrl,
        deviceId: relocated.deviceId,
        fingerprint256: relocated.fingerprint256
      });
      await this.startManagement();
      return this.getHqStatus();
    } catch (error) {
      await this.startManagement().catch(() => {});
      throw error;
    }
  }

  async disconnectHq() {
    const status = await this.getHqStatus();
    await this.stopManagement();
    await clearHqCredentials();
    await clearPendingHqEnrollment();
    this.config = await saveConfig({ management: { enabled: false } });
    await appendAudit("hq.disconnected", {
      hqName: status.hqName,
      deviceId: status.deviceId
    });
    return this.getHqStatus();
  }

  async authorizeMaintenance(password, action = "critical-settings") {
    if (!this.config.management.enabled) return { authorized: true, standalone: true };
    const credentials = await loadHqCredentials();
    if (!credentials) {
      throw new Error("HQ maintenance authorization requires an approved managed endpoint");
    }
    const result = await authorizeHqMaintenance(credentials, password, action);
    await appendAudit("hq.maintenance-authorized", {
      action,
      authorizationId: result.authorizationId
    });
    return result;
  }

  async requestMaintenancePassword(options = {}) {
    if (!this.config.management.enabled) {
      throw new Error("This endpoint is not managed by SentryLoom HQ");
    }
    const credentials = await loadHqCredentials();
    if (!credentials) {
      throw new Error("This endpoint must be approved by HQ before requesting maintenance access");
    }
    const result = await requestHqMaintenancePassword(credentials, options);
    await appendAudit("hq.maintenance-password-approved", {
      action: options.action || "critical-settings",
      requestId: result.requestId,
      expiresAt: result.expiresAt
    });
    return result;
  }

  async getHqTelemetry() {
    const systemPromise = this.systemTelemetry &&
      Date.now() - this.systemTelemetry.collectedAt < 60000
      ? Promise.resolve(this.systemTelemetry.value)
      : collectSystemInformation().then((value) => {
        this.systemTelemetry = { collectedAt: Date.now(), value };
        return value;
      });
    const controlTelemetry = this.hqControlTelemetry &&
      Date.now() - this.hqControlTelemetry.collectedAt < 15000
      ? this.hqControlTelemetry.value
      : await Promise.all([
        this.getDnsFilteringStatus(),
        this.getFirewallPolicyStatus(),
        this.getDeviceControlStatus()
      ]).then(([dnsFiltering, firewallPolicy, deviceControl]) => {
        const value = { dnsFiltering, firewallPolicy, deviceControl };
        this.hqControlTelemetry = { collectedAt: Date.now(), value };
        return value;
      });
    const [status, identity, quarantine, history, audit, clientUpdate, system] = await Promise.all([
      this.getStatus({ consumeNavigation: false }),
      getDeviceIdentity(),
      listQuarantine(),
      readScanHistory(20),
      readRecentAudit(50),
      getClientUpdateStatus(),
      systemPromise
    ]);
    return {
      schemaVersion: 2,
      sentAt: new Date().toISOString(),
      device: {
        installationId: identity.installationId,
        name: identity.name,
        hostname: identity.hostname,
        platform: identity.platform,
        appVersion: APP_VERSION,
        networkInterfaces: collectWakeNetworkInterfaces(),
        ...platformDescriptor()
      },
      capabilities: {
        features: platformDescriptor().capabilities,
        commands: supportedCommands()
      },
      system: sanitizeHqValue(system),
      security: {
        score: status.posture.score,
        grade: status.posture.grade,
        state: status.posture.state,
        issues: status.posture.issues.map((item) => ({
          id: item.id,
          severity: item.severity,
          title: item.title,
          detail: item.detail || null,
          action: item.action || null,
          fixable: item.fixable !== false
        })),
        quarantineCount: status.quarantineCount,
        audit: {
          valid: status.audit.valid,
          records: status.audit.records ?? null,
          failedAt: status.audit.failedAt ?? null,
          recovered: status.audit.recovered || false,
          recoveredAt: status.audit.recoveredAt || null,
          evidenceFile: status.audit.evidenceFile || null,
          evidenceSha256: status.audit.evidenceSha256 || null,
          originalFailedAt: status.audit.originalFailedAt ?? null,
          originalFailureReason: status.audit.originalFailureReason || null
        }
      },
      policy: {
        protection: sanitizeHqValue(this.config.protection),
        monitoring: sanitizeHqValue(this.config.monitoring),
        schedule: sanitizeHqValue(this.config.schedule),
        dnsFiltering: sanitizeHqValue(this.config.dnsFiltering),
        threatIntel: {
          clamavEngineEnabled: this.config.threatIntel.clamavEngineEnabled,
          sources: sanitizeHqValue(this.config.threatIntel.sources),
          minimumUpdateIntervalMinutes: this.config.threatIntel.minimumUpdateIntervalMinutes
        },
        scanner: {
          maxFileBytes: this.config.scanner.maxFileBytes,
          sampleBytes: this.config.scanner.sampleBytes,
          concurrency: this.config.scanner.concurrency,
          realtimeConcurrency: this.config.scanner.realtimeConcurrency,
          followSymbolicLinks: this.config.scanner.followSymbolicLinks,
          scanHiddenFiles: this.config.scanner.scanHiddenFiles,
          exclusionsCount: this.config.scanner.exclusions.length
        }
      },
      protection: sanitizeHqValue(status.protection),
      signatures: {
        version: status.signatures.version,
        updatedAt: status.signatures.updatedAt || null,
        hashCount: status.signatures.hashCount,
        patternCount: status.signatures.patternCount,
        networkIocCount: status.signatures.networkIocCount,
        clamav: sanitizeHqValue(status.clamavEngine),
        updates: sanitizeHqValue(status.threatUpdates)
      },
      scan: {
        active: sanitizeHqValue(status.activeScan),
        progress: sanitizeHqValue(status.progress),
        last: summarizeScan(status.lastScan),
        history: history.map(summarizeScan)
      },
      controls: {
        dnsFiltering: sanitizeHqValue(controlTelemetry.dnsFiltering),
        firewallPolicy: sanitizeHqValue(controlTelemetry.firewallPolicy),
        deviceControl: sanitizeHqValue(controlTelemetry.deviceControl),
        collectedAt: new Date(this.hqControlTelemetry.collectedAt).toISOString()
      },
      quarantine: quarantine.slice(0, 100).map((item) => ({
        id: item.id,
        originalPath: item.originalPath,
        originalSize: item.originalSize,
        originalModifiedAt: item.originalModifiedAt,
        quarantinedAt: item.quarantinedAt,
        sha256: item.sha256,
        state: item.state,
        findings: sanitizeHqValue(item.findings || [])
      })),
      runtime: status.runtime,
      clientUpdate: sanitizeHqValue(clientUpdate),
      events: status.events.slice(0, 50).map((event) => sanitizeHqValue(event)),
      audit: audit.map((entry) => sanitizeHqValue(entry))
    };
  }

  async executeHqCommand(command) {
    const type = command.type;
    if (!supportedCommands().includes(type)) {
      throw new Error(`HQ command ${type} is not supported on ${process.platform}`);
    }
    if (type.startsWith("scan.") && type !== "scan.cancel") {
      const scanType = type.slice("scan.".length);
      const result = await this.runScan(scanType);
      return {
        scanId: result.id,
        type: result.type,
        scanned: result.scanned,
        detections: result.detections,
        errors: result.errorCount,
        endedAt: result.endedAt
      };
    }
    if (type === "scan.cancel") return { cancelled: this.cancelScan() };
    if (type === "update.databases") {
      const result = await this.updateThreatIntel(undefined, { force: true });
      return { updated: true, sources: result.results?.map((item) => item.source) || [] };
    }
    if (type === "client.update") {
      const credentials = await loadHqCredentials();
      if (!credentials) throw new Error("This endpoint is not enrolled with SentryLoom HQ");
      const result = await stageClientUpdate(credentials);
      await appendAudit("client.update-scheduled", {
        fromVersion: APP_VERSION,
        targetVersion: result.targetVersion,
        sha256: result.sha256 || null
      });
      return result;
    }
    if (type === "protection.fix-all") {
      const status = await this.applyRecommendedProtection();
      return { score: status.posture.score, state: status.posture.state };
    }
    if (type === "protection.restart") {
      await this.stopProtection();
      await this.startProtection();
      return { restartedAt: new Date().toISOString() };
    }
    throw new Error(`HQ command is not allowed: ${type}`);
  }

  async applyRecommendedProtection() {
    this.config = await saveConfig(RECOMMENDED_PROTECTION_CONFIG);
    await this.stopProtection();
    await this.startProtection();
    await appendAudit("action-center.fix-all", {
      enabled: [
        "realtime-file",
        "all-fixed-drives",
        "network-ioc",
        "dns-ioc",
        "process",
        "persistence",
        "ransomware",
        "windows-events",
        "removable-media",
        "firewall-integrity",
        "automatic-confirmed-quarantine"
      ],
      excluded: ["heuristic-auto-quarantine", "automatic-firewall-blocking"]
    });
    this.emit({ type: "action-center.fixed", message: "Recommended protection controls enabled" });
    return this.getStatus();
  }

  async getDnsFilteringStatus() {
    return dnsFilteringStatus(this.config);
  }

  async applyDnsFiltering(profileId) {
    await applyDnsProfile(profileId, {
      preserveBackup: Boolean(this.config.dnsFiltering.lastAppliedProfile)
    });
    const appliedAt = new Date().toISOString();
    this.config = await saveConfig({
      dnsFiltering: {
        selectedProfile: profileId,
        lastAppliedProfile: profileId,
        lastAppliedAt: appliedAt
      }
    });
    await appendAudit("dns-filtering.applied", { profileId, appliedAt });
    return this.getDnsFilteringStatus();
  }

  async restoreDnsFiltering() {
    const previousProfile = this.config.dnsFiltering.lastAppliedProfile;
    await restoreDnsConfiguration();
    this.config = await saveConfig({
      dnsFiltering: {
        lastAppliedProfile: null,
        lastAppliedAt: null
      }
    });
    await appendAudit("dns-filtering.restored", { previousProfile });
    return this.getDnsFilteringStatus();
  }

  async getFirewallPolicyStatus() {
    return {
      ...(await firewallPolicyStatus()),
      enforcementEnabled: this.config.monitoring.firewallBlockHighConfidence
    };
  }

  async clearFirewallPolicy() {
    this.firewallBlocks = 0;
    return clearThreatFirewallRules();
  }

  async getDeviceControlStatus() {
    return { usbStorage: await usbStorageStatus() };
  }

  async setUsbStorageBlocked(blocked) {
    const status = await setUsbStorageBlocked(blocked);
    await appendAudit(blocked ? "device-control.usb-storage-blocked" : "device-control.usb-storage-restored", {
      keyboardsAndMiceAffected: false
    });
    this.emit({ type: blocked ? "device-control.usb-storage-blocked" : "device-control.usb-storage-restored" });
    return { usbStorage: status };
  }

  async chooseScanTarget(kind) {
    return { path: await showPlatformPathPicker(kind), kind };
  }

  async lookupReputation(value) {
    const query = String(value || "").trim();
    if (!query || query.length > 2048) throw new Error("Enter a hash, IP address, domain, URL, or IP:port value");
    const index = await openThreatIndex();
    try {
      const isHash = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(query);
      const matches = isHash ? index.lookupHashValue(query) : index.lookupIoc(query);
      return {
        query,
        kind: isHash ? "file-hash" : "network-indicator",
        matches,
        verdict: matches.length
          ? matches.some((item) => item.confirmed || Number(item.confidence || 0) >= 90) ? "malicious" : "suspicious"
          : "unknown",
        localOnly: true,
        evaluatedAt: new Date().toISOString()
      };
    } finally {
      index.close();
    }
  }

  async saveThreatCredentials(credentials) {
    if (this.config.management.enabled) {
      throw new Error("Managed endpoints receive abuse.ch access through SentryLoom HQ; no key is stored on this client");
    }
    await saveThreatCredentials(credentials);
    await appendAudit("threat-intel.credentials-updated", { abuseChConfigured: Boolean(credentials.abuseChAuthKey) });
    return threatCredentialStatus();
  }

  async updateThreatIntel(sources, options = {}) {
    const enabled = this.config.threatIntel.sources;
    const requested = (sources?.length ? sources : Object.keys(enabled)).filter((source) => enabled[source] !== false);
    return this.threatUpdates.update(requested, options);
  }

  async quarantine(pathname, detection) {
    return quarantineFile(pathname, detection);
  }

  async listQuarantine() {
    return listQuarantine();
  }

  async restore(id, destination) {
    return restoreQuarantine(id, destination);
  }

  async deleteQuarantine(id) {
    return deleteQuarantine(id);
  }
}

export function highestSeverity(findings) {
  return findings.reduce((highest, finding) => (
    SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest
  ), "clean");
}
