import path from "node:path";
import { execFile } from "node:child_process";
import { isIP } from "node:net";
import { openThreatIndex } from "./threat-index.js";
import { appendAudit } from "./audit-log.js";
import { readDnsCacheEntries } from "./windows-monitoring.js";

function parseEndpoint(value) {
  if (!value) return null;
  if (value.startsWith("[")) {
    const end = value.lastIndexOf("]:");
    if (end === -1) return null;
    const host = value.slice(1, end).split("%")[0];
    const port = Number(value.slice(end + 2));
    return isIP(host) && Number.isInteger(port) ? { host: host.toLowerCase(), port } : null;
  }
  const separator = value.lastIndexOf(":");
  if (separator === -1) return null;
  const host = value.slice(0, separator).split("%")[0];
  const port = Number(value.slice(separator + 1));
  return isIP(host) && Number.isInteger(port) ? { host: host.toLowerCase(), port } : null;
}

export function parseNetstatOutput(output) {
  const connections = [];
  for (const line of output.split(/\r?\n/)) {
    const fields = line.trim().split(/\s+/);
    if (fields[0]?.toUpperCase() !== "TCP" || fields.length < 5) continue;
    const local = parseEndpoint(fields[1]);
    const remote = parseEndpoint(fields[2]);
    const state = fields[3]?.toUpperCase();
    const pid = Number(fields[4]);
    if (!local || !remote || !Number.isInteger(pid)) continue;
    if (!["ESTABLISHED", "SYN_SENT", "SYN_RECEIVED"].includes(state)) continue;
    if (["0.0.0.0", "::", "127.0.0.1", "::1"].includes(remote.host)) continue;
    connections.push({ protocol: "tcp", local, remote, state, pid });
  }
  return connections;
}

function runNetstat() {
  const executable = process.platform === "win32"
    ? path.join(process.env.SystemRoot || "C:\\Windows", "System32", "NETSTAT.EXE")
    : "netstat";
  return new Promise((resolve, reject) => {
    execFile(executable, ["-ano", "-p", "TCP"], {
      windowsHide: true,
      timeout: 15000,
      maxBuffer: 16 * 1024 * 1024
    }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr.trim() || error.message, { cause: error }));
      else resolve(stdout);
    });
  });
}

export class NetworkMonitor {
  constructor(config, onEvent = () => {}, options = {}) {
    this.config = config;
    this.onEvent = onEvent;
    this.onDetection = options.onDetection || (() => {});
    this.running = false;
    this.connectionsObserved = 0;
    this.dnsEntriesObserved = 0;
    this.detections = 0;
    this.errors = 0;
    this.seenConnections = new Map();
    this.seenDns = new Map();
    this.lastConnectionPoll = null;
    this.lastDnsPoll = null;
  }

  async start() {
    if (this.running || !this.config.protection.networkMonitoringEnabled) return;
    this.index = await openThreatIndex();
    this.running = true;
    this.scheduleConnections(0);
    if (this.config.protection.dnsMonitoringEnabled) this.scheduleDns(0);
    await appendAudit("network-monitor.started", {
      tcpConnections: true,
      dnsCache: this.config.protection.dnsMonitoringEnabled,
      packetInspection: false
    });
  }

  scheduleConnections(delay) {
    if (!this.running) return;
    this.connectionTimer = setTimeout(async () => {
      try { await this.pollConnections(); } catch (error) { this.recordError("tcp", error); }
      this.scheduleConnections(this.config.protection.networkPollIntervalMs);
    }, delay);
  }

  scheduleDns(delay) {
    if (!this.running) return;
    this.dnsTimer = setTimeout(async () => {
      try { await this.pollDns(); } catch (error) { this.recordError("dns", error); }
      this.scheduleDns(this.config.protection.dnsPollIntervalMs);
    }, delay);
  }

  recordError(channel, error) {
    this.errors += 1;
    if (this.errors <= 3 || this.errors % 20 === 0) {
      this.onEvent({ type: "network.error", channel, error: error.message });
    }
  }

  pruneSeen(map) {
    const cutoff = Date.now() - 30 * 60 * 1000;
    for (const [key, observedAt] of map) {
      if (observedAt < cutoff) map.delete(key);
    }
  }

  async pollConnections() {
    const connections = parseNetstatOutput(await runNetstat());
    this.connectionsObserved = connections.length;
    this.lastConnectionPoll = new Date().toISOString();
    for (const connection of connections) {
      const key = `${connection.pid}|${connection.remote.host}|${connection.remote.port}`;
      if (this.seenConnections.has(key)) continue;
      this.seenConnections.set(key, Date.now());
      const endpoint = isIP(connection.remote.host) === 6
        ? `[${connection.remote.host}]:${connection.remote.port}`
        : `${connection.remote.host}:${connection.remote.port}`;
      const matches = [
        ...this.index.lookupIoc(connection.remote.host),
        ...this.index.lookupIoc(endpoint)
      ];
      if (matches.length) await this.reportDetection("connection", { ...connection, endpoint }, matches);
    }
    this.pruneSeen(this.seenConnections);
  }

  async pollDns() {
    const entries = await readDnsCacheEntries();
    this.dnsEntriesObserved = entries.length;
    this.lastDnsPoll = new Date().toISOString();
    for (const domain of entries) {
      if (this.seenDns.has(domain)) continue;
      this.seenDns.set(domain, Date.now());
      const matches = this.index.lookupIoc(domain);
      if (matches.length) await this.reportDetection("dns", { domain }, matches);
    }
    this.pruneSeen(this.seenDns);
  }

  async reportDetection(channel, observation, matches) {
    this.detections += 1;
    const event = { type: "network.detection", channel, observation, matches };
    this.onEvent(event);
    await appendAudit("network.detection", {
      channel,
      remote: observation.endpoint || observation.domain,
      pid: observation.pid || null,
      sources: [...new Set(matches.map((match) => match.source))],
      names: [...new Set(matches.map((match) => match.name))]
    });
    try {
      await this.onDetection({ channel, observation, matches });
    } catch (error) {
      this.recordError("enforcement", error);
    }
  }

  status() {
    return {
      enabled: this.config.protection.networkMonitoringEnabled,
      running: this.running,
      tcpConnectionMetadata: true,
      dnsCacheMonitoring: this.config.protection.dnsMonitoringEnabled,
      packetInspection: false,
      connectionsObserved: this.connectionsObserved,
      dnsEntriesObserved: this.dnsEntriesObserved,
      detections: this.detections,
      errors: this.errors,
      lastConnectionPoll: this.lastConnectionPoll,
      lastDnsPoll: this.lastDnsPoll
    };
  }

  async stop() {
    this.running = false;
    clearTimeout(this.connectionTimer);
    clearTimeout(this.dnsTimer);
    this.index?.close();
    this.index = null;
    await appendAudit("network-monitor.stopped");
  }
}
