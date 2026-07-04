import https from "node:https";
import http from "node:http";
import dgram from "node:dgram";
import fs from "node:fs/promises";
import { createWriteStream } from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { getDeviceIdentity } from "./device-identity.js";
import {
  clearPendingHqEnrollment,
  saveHqCredentials,
  savePendingHqEnrollment
} from "./hq-credential-store.js";
import { appPaths } from "../constants.js";
import { ensureDirectory } from "./fs-safe.js";

const DISCOVERY_REQUEST = "SENTRYLOOM_HQ_DISCOVER_V1";
export function normalizeFingerprint(value) {
  const normalized = String(value || "").replace(/[^a-f0-9]/gi, "").toUpperCase();
  if (normalized && !/^[A-F0-9]{64}$/.test(normalized)) {
    throw new Error("HQ certificate fingerprint must be a SHA-256 fingerprint");
  }
  return normalized;
}

export function normalizeHqUrl(value, options = {}) {
  const url = new URL(String(value || "").trim());
  if (url.protocol !== "https:" && !(options.allowHttp && url.protocol === "http:")) {
    throw new Error("SentryLoom HQ must use HTTPS");
  }
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

export function hqRequest(serverUrl, route, options = {}) {
  const url = new URL(route, `${serverUrl}/`);
  const expectedFingerprint = normalizeFingerprint(options.fingerprint256);
  const isHttps = url.protocol === "https:";
  if (!isHttps && !options.allowHttp) return Promise.reject(new Error("SentryLoom HQ must use HTTPS"));
  const transport = isHttps ? https : http;
  const serialized = options.body === undefined ? null : JSON.stringify(options.body);

  return new Promise((resolve, reject) => {
    let peerFingerprint = "";
    let pinVerified = !isHttps;
    let request;
    const verifyPeer = (socket) => {
      if (!isHttps) return true;
      const presented = normalizeFingerprint(socket?.getPeerCertificate?.()?.fingerprint256);
      if (!presented) throw new Error("HQ did not present a certificate fingerprint");
      if (expectedFingerprint && presented !== expectedFingerprint) {
        throw new Error(
          `HQ certificate fingerprint mismatch. Expected ${expectedFingerprint}; received ${presented}`
        );
      }
      peerFingerprint = presented;
      pinVerified = true;
      return true;
    };
    request = transport.request(url, {
      method: options.method || "GET",
      timeout: Math.max(1000, Number(options.timeoutMs) || 15000),
      rejectUnauthorized: isHttps ? false : undefined,
      headers: {
        Accept: "application/json",
        ...(serialized ? {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(serialized)
        } : {}),
        ...(options.credentials ? {
          Authorization: `Bearer ${options.credentials.token}`,
          "X-SentryLoom-Device": options.credentials.deviceId
        } : {}),
        ...(options.enrollmentSecret ? {
          Authorization: `Enrollment ${options.enrollmentSecret}`
        } : {})
      }
    }, (response) => {
      try {
        verifyPeer(response.socket);
      } catch (error) {
        response.resume();
        request.destroy(error);
        return;
      }
      const chunks = [];
      let bytes = 0;
      response.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) {
          request.destroy(new Error("HQ response is too large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (!pinVerified) {
          reject(new Error("HQ certificate verification did not complete"));
          return;
        }
        let body = {};
        try {
          body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
        } catch {
          reject(new Error("HQ returned an invalid JSON response"));
          return;
        }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(body.error || `HQ request failed (${response.statusCode})`));
          return;
        }
        resolve({ body, fingerprint256: peerFingerprint });
      });
    });
    request.on("socket", (socket) => {
      if (!isHttps) return;
      const certificate = socket.getPeerCertificate?.();
      if (certificate?.fingerprint256) {
        try { verifyPeer(socket); } catch (error) { request.destroy(error); }
        return;
      }
      socket.once("secureConnect", () => {
        try { verifyPeer(socket); } catch (error) { request.destroy(error); }
      });
    });
    request.on("timeout", () => request.destroy(new Error("HQ request timed out")));
    request.on("error", reject);
    if (serialized) request.write(serialized);
    request.end();
  });
}

export async function downloadHqPackage(credentials, route, destination, expected, options = {}) {
  const serverUrl = normalizeHqUrl(credentials.serverUrl, { allowHttp: options.allowHttp });
  const url = new URL(route, `${serverUrl}/`);
  const isHttps = url.protocol === "https:";
  if (!isHttps && !options.allowHttp) throw new Error("SentryLoom HQ must use HTTPS");
  const expectedFingerprint = normalizeFingerprint(credentials.fingerprint256);
  const maximumBytes = Math.min(1024 * 1024 * 1024, Math.max(1024, Number(options.maximumBytes) || expected.size));
  const transport = isHttps ? https : http;
  await ensureDirectory(path.dirname(destination));
  const temporary = `${destination}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`;

  try {
    const result = await new Promise((resolve, reject) => {
      let request;
      let pinVerified = !isHttps;
      const verifyPeer = (socket) => {
        if (!isHttps) return;
        const presented = normalizeFingerprint(socket?.getPeerCertificate?.()?.fingerprint256);
        if (!presented) throw new Error("HQ did not present a certificate fingerprint");
        if (presented !== expectedFingerprint) {
          throw new Error(`HQ certificate fingerprint mismatch. Expected ${expectedFingerprint}; received ${presented}`);
        }
        pinVerified = true;
      };
      request = transport.request(url, {
        method: "GET",
        timeout: Math.max(1000, Number(options.timeoutMs) || 10 * 60 * 1000),
        rejectUnauthorized: isHttps ? false : undefined,
        headers: {
          Accept: "application/octet-stream",
          Authorization: `Bearer ${credentials.token}`,
          "X-SentryLoom-Device": credentials.deviceId
        }
      }, async (response) => {
        try {
          verifyPeer(response.socket);
          if (!pinVerified) throw new Error("HQ certificate verification did not complete");
          if (response.statusCode !== 200) {
            const chunks = [];
            let total = 0;
            for await (const chunk of response) {
              total += chunk.length;
              if (total > 65536) break;
              chunks.push(chunk);
            }
            let message = `HQ update download failed (${response.statusCode})`;
            try { message = JSON.parse(Buffer.concat(chunks).toString("utf8")).error || message; } catch {}
            throw new Error(message);
          }
          const contentLength = Number(response.headers["content-length"]);
          if (!Number.isSafeInteger(contentLength) || contentLength !== expected.size || contentLength > maximumBytes) {
            throw new Error("HQ update package size does not match its manifest");
          }
          if (String(response.headers["x-sentryloom-sha256"] || "").toUpperCase() !== expected.sha256) {
            throw new Error("HQ update package header does not match its manifest");
          }
          const hash = crypto.createHash("sha256");
          let bytes = 0;
          const meter = new Transform({
            transform(chunk, encoding, callback) {
              bytes += chunk.length;
              if (bytes > maximumBytes) {
                callback(new Error("HQ update package exceeded the maximum size"));
                return;
              }
              hash.update(chunk);
              callback(null, chunk);
            }
          });
          await pipeline(response, meter, createWriteStream(temporary, { flags: "wx", mode: 0o600 }));
          const sha256 = hash.digest("hex").toUpperCase();
          if (bytes !== expected.size || sha256 !== expected.sha256) {
            throw new Error("HQ update package failed SHA-256 verification");
          }
          resolve({ bytes, sha256 });
        } catch (error) {
          reject(error);
        }
      });
      request.on("socket", (socket) => {
        if (!isHttps) return;
        if (socket.getPeerCertificate?.()?.fingerprint256) {
          try { verifyPeer(socket); } catch (error) { request.destroy(error); }
          return;
        }
        socket.once("secureConnect", () => {
          try { verifyPeer(socket); } catch (error) { request.destroy(error); }
        });
      });
      request.on("timeout", () => request.destroy(new Error("HQ update download timed out")));
      request.on("error", reject);
      request.end();
    });
    await fs.rm(destination, { force: true });
    await fs.rename(temporary, destination);
    return { ...result, path: destination };
  } catch (error) {
    await fs.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}

export async function discoverHqServers(options = {}) {
  const timeoutMs = Math.max(250, Number(options.timeoutMs) || 1600);
  const port = Number(options.port) || 32110;
  const socket = dgram.createSocket("udp4");
  const servers = new Map();
  return new Promise((resolve, reject) => {
    const finish = () => {
      try { socket.close(); } catch {}
      resolve([...servers.values()]);
    };
    socket.on("error", (error) => {
      try { socket.close(); } catch {}
      reject(error);
    });
    socket.on("message", (message, remote) => {
      try {
        const candidate = JSON.parse(message.toString("utf8"));
        if (candidate.protocol !== "sentryloom-hq/1") return;
        const url = normalizeHqUrl(candidate.url);
        const fingerprint256 = normalizeFingerprint(candidate.fingerprint256);
        if (!fingerprint256) return;
        const advertised = new URL(url);
        const addressHost = remote.address.includes(":") ? `[${remote.address}]` : remote.address;
        const connectionUrl = `${advertised.protocol}//${addressHost}${advertised.port ? `:${advertised.port}` : ""}`;
        servers.set(`${connectionUrl}|${fingerprint256}`, {
          name: String(candidate.name || "SentryLoom HQ").slice(0, 100),
          url: connectionUrl,
          advertisedUrl: url,
          fingerprint256,
          address: remote.address
        });
      } catch {}
    });
    socket.bind(0, "0.0.0.0", () => {
      socket.setBroadcast(true);
      const request = Buffer.from(DISCOVERY_REQUEST);
      socket.send(request, port, "255.255.255.255");
      socket.send(request, port, "127.0.0.1");
      setTimeout(finish, timeoutMs);
    });
  });
}

export async function enrollWithHq(options) {
  const serverUrl = normalizeHqUrl(options.serverUrl, { allowHttp: options.allowHttp });
  let fingerprint256 = normalizeFingerprint(options.fingerprint256);
  if (!fingerprint256 && !options.trustOnFirstUse && !options.allowHttp) {
    throw new Error("Discover HQ or enter its certificate SHA-256 fingerprint");
  }
  const identity = await probeHq(serverUrl, {
    fingerprint256,
    allowHttp: options.allowHttp
  });
  fingerprint256 ||= identity.fingerprint256;
  const enrollmentResponse = await hqRequest(serverUrl, "/api/v1/enroll", {
    method: "POST",
    fingerprint256,
    allowHttp: options.allowHttp,
    body: {
      code: String(options.code || "").trim(),
      device: await getDeviceIdentity()
    }
  });
  const credentials = {
    serverUrl,
    fingerprint256,
    hqName: enrollmentResponse.body.hqName,
    deviceId: enrollmentResponse.body.deviceId,
    token: enrollmentResponse.body.token,
    enrolledAt: enrollmentResponse.body.enrolledAt
  };
  await saveHqCredentials(credentials);
  return credentials;
}

export async function probeHq(serverUrl, options = {}) {
  const normalizedUrl = normalizeHqUrl(serverUrl, { allowHttp: options.allowHttp });
  const identityResponse = await hqRequest(normalizedUrl, "/api/v1/hq", {
    fingerprint256: options.fingerprint256,
    allowHttp: options.allowHttp,
    timeoutMs: options.timeoutMs
  });
  const advertised = normalizeFingerprint(identityResponse.body.fingerprint256);
  if (!options.allowHttp && advertised !== identityResponse.fingerprint256) {
    throw new Error(
      `HQ certificate identity conflict. Server advertised ${advertised || "no fingerprint"}; TLS presented ${identityResponse.fingerprint256}`
    );
  }
  return {
    serverUrl: normalizedUrl,
    hqName: String(identityResponse.body.name || "SentryLoom HQ"),
    fingerprint256: identityResponse.fingerprint256
  };
}

export async function requestHqEnrollment(options = {}) {
  const allowHttp = Boolean(options.allowHttp || process.env.SENTRYLOOM_ALLOW_INSECURE_HQ === "1");
  let discovered = null;
  if (!options.serverUrl) {
    const servers = await discoverHqServers(options);
    if (!servers.length) throw new Error("No SentryLoom HQ server was found on this network");
    if (servers.length > 1) throw new Error("Multiple HQ servers were found; choose one in SentryLoom Settings");
    discovered = servers[0];
  }
  const serverUrl = normalizeHqUrl(options.serverUrl || discovered.url, { allowHttp });
  const fingerprint256 = normalizeFingerprint(options.fingerprint256 || discovered?.fingerprint256);
  const identity = await probeHq(serverUrl, {
    fingerprint256: fingerprint256 || undefined,
    allowHttp
  });
  const response = await hqRequest(serverUrl, "/api/v1/enrollment-requests", {
    method: "POST",
    fingerprint256: identity.fingerprint256,
    allowHttp,
    body: { device: await getDeviceIdentity() }
  });
  const pending = {
    serverUrl,
    fingerprint256: identity.fingerprint256,
    hqName: response.body.hqName || identity.hqName,
    requestId: response.body.requestId,
    requestSecret: response.body.requestSecret,
    requestedAt: response.body.requestedAt,
    status: "pending"
  };
  await savePendingHqEnrollment(pending);
  return pending;
}

export async function pollHqEnrollment(pending) {
  const allowHttp = process.env.SENTRYLOOM_ALLOW_INSECURE_HQ === "1";
  const response = await hqRequest(
    pending.serverUrl,
    `/api/v1/enrollment-requests/${pending.requestId}`,
    {
      fingerprint256: pending.fingerprint256,
      enrollmentSecret: pending.requestSecret,
      allowHttp
    }
  );
  if (response.body.status === "approved") {
    const credentials = {
      serverUrl: pending.serverUrl,
      fingerprint256: pending.fingerprint256,
      hqName: response.body.hqName || pending.hqName,
      deviceId: response.body.deviceId,
      token: response.body.token,
      enrolledAt: response.body.enrolledAt
    };
    await saveHqCredentials(credentials);
    await clearPendingHqEnrollment();
    return { status: "approved", credentials };
  }
  if (response.body.status === "rejected") {
    await savePendingHqEnrollment({ ...pending, status: "rejected" });
  }
  return { status: response.body.status };
}

export class HqEnrollmentPoller {
  constructor(pending, options = {}) {
    this.pending = pending;
    this.onApproved = options.onApproved;
    this.intervalMs = Math.max(2000, Number(options.intervalMs) || 5000);
    this.running = false;
    this.timer = null;
    this.lastCheckedAt = null;
    this.lastError = null;
    this.state = pending.status || "pending";
  }

  start() {
    if (this.running || this.state === "rejected") return;
    this.running = true;
    this.schedule(0);
  }

  schedule(delay = this.intervalMs) {
    clearTimeout(this.timer);
    if (!this.running) return;
    this.timer = setTimeout(() => this.pulse().finally(() => this.schedule()), delay);
    this.timer.unref?.();
  }

  async pulse() {
    try {
      const result = await pollHqEnrollment(this.pending);
      this.lastCheckedAt = new Date().toISOString();
      this.lastError = null;
      this.state = result.status;
      if (result.status === "approved") {
        this.stop();
        await this.onApproved?.(result.credentials);
      } else if (result.status === "rejected") {
        this.stop();
      }
    } catch (error) {
      this.lastError = error.message;
    }
  }

  stop() {
    this.running = false;
    clearTimeout(this.timer);
    this.timer = null;
  }

  status() {
    return {
      enabled: true,
      running: this.running,
      pending: this.state === "pending",
      rejected: this.state === "rejected",
      approvalStatus: this.state,
      hqName: this.pending.hqName,
      serverUrl: this.pending.serverUrl,
      requestedAt: this.pending.requestedAt,
      lastCheckedAt: this.lastCheckedAt,
      lastError: this.lastError,
      deviceId: null,
      activeCommands: 0
    };
  }
}

function processIsAlive(pid) {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

export async function acquireHqConnectorLease() {
  const lockFile = appPaths().hqConnectorLock;
  await ensureDirectory(appPaths().data);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const nonce = crypto.randomBytes(16).toString("hex");
    try {
      const handle = await fs.open(lockFile, "wx", 0o600);
      await handle.writeFile(JSON.stringify({
        pid: process.pid,
        nonce,
        acquiredAt: new Date().toISOString()
      }));
      await handle.close();
      return async () => {
        try {
          const current = JSON.parse(await fs.readFile(lockFile, "utf8"));
          if (current.pid === process.pid && current.nonce === nonce) {
            await fs.rm(lockFile, { force: true });
          }
        } catch {}
      };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let owner = null;
      try { owner = JSON.parse(await fs.readFile(lockFile, "utf8")); } catch {}
      if (owner && processIsAlive(Number(owner.pid))) return null;
      await fs.rm(lockFile, { force: true }).catch(() => {});
    }
  }
  return null;
}

export class HqConnector {
  constructor(credentials, options = {}) {
    this.credentials = credentials;
    this.metricsProvider = options.metricsProvider;
    this.commandExecutor = options.commandExecutor;
    this.onEvent = options.onEvent;
    this.stateWriter = options.stateWriter;
    this.intervalMs = Math.max(1000, Number(options.intervalMs) || 1500);
    this.telemetryIntervalMs = Math.max(2000, Number(options.telemetryIntervalMs) || 2000);
    this.maximumRetryMs = Math.max(this.intervalMs, Number(options.maximumRetryMs) || 30000);
    this.failureThreshold = Math.max(1, Number(options.failureThreshold) || 2);
    this.resumeThresholdMs = Math.max(
      this.intervalMs * 4,
      Number(options.resumeThresholdMs) || 10000
    );
    this.allowHttp = Boolean(options.allowHttp);
    this.running = false;
    this.timer = null;
    this.lastTelemetryAt = 0;
    this.lastPulseAt = 0;
    this.lastAttemptAt = null;
    this.lastConnectedAt = null;
    this.lastErrorAt = null;
    this.lastResumeAt = null;
    this.lastError = null;
    this.connectionState = "connecting";
    this.consecutiveFailures = 0;
    this.nextRetryAt = null;
    this.offlineNotified = false;
    this.activeCommands = new Set();
  }

  start() {
    if (this.running) return;
    this.running = true;
    this.schedule(0);
  }

  schedule(delay = this.intervalMs) {
    clearTimeout(this.timer);
    if (!this.running) return;
    this.timer = setTimeout(async () => {
      const nextDelay = await this.pulse();
      this.schedule(nextDelay);
    }, Math.max(0, delay));
    this.timer.unref?.();
  }

  emit(event) {
    try {
      this.onEvent?.(event);
    } catch {}
  }

  async persistState() {
    try {
      await this.stateWriter?.({
        ...this.status(),
        updatedAt: new Date().toISOString(),
        ownerPid: process.pid
      });
    } catch {}
  }

  async request(route, options = {}) {
    const response = await hqRequest(this.credentials.serverUrl, route, {
      ...options,
      credentials: this.credentials,
      fingerprint256: this.credentials.fingerprint256,
      allowHttp: this.allowHttp
    });
    return response.body;
  }

  async pulse() {
    if (!this.running) return this.intervalMs;
    const now = Date.now();
    const suspendedForMs = this.lastPulseAt ? now - this.lastPulseAt : 0;
    if (suspendedForMs >= this.resumeThresholdMs) {
      this.lastResumeAt = new Date(now).toISOString();
      this.lastTelemetryAt = 0;
      this.consecutiveFailures = 0;
      this.nextRetryAt = null;
      this.connectionState = "connecting";
      this.emit({
        type: "system.resume-detected",
        suspendedForMs,
        message: "Windows resumed or the event loop was paused; reconnecting to HQ immediately"
      });
    }
    this.lastPulseAt = now;
    this.lastAttemptAt = new Date(now).toISOString();
    try {
      if (now - this.lastTelemetryAt >= this.telemetryIntervalMs) {
        await this.request("/api/v1/device/telemetry", {
          method: "POST",
          body: await this.metricsProvider()
        });
        this.lastTelemetryAt = Date.now();
      }
      const response = await this.request("/api/v1/device/commands");
      for (const command of response.commands || []) this.beginCommand(command);
      const recovered = this.offlineNotified;
      this.lastConnectedAt = new Date().toISOString();
      this.lastError = null;
      this.lastErrorAt = null;
      this.connectionState = "online";
      this.consecutiveFailures = 0;
      this.nextRetryAt = null;
      this.offlineNotified = false;
      if (recovered) {
        this.emit({
          type: "hq.connection-restored",
          hqName: this.credentials.hqName,
          serverUrl: this.credentials.serverUrl,
          message: "Connection to SentryLoom HQ was restored"
        });
      }
      await this.persistState();
      return this.intervalMs;
    } catch (error) {
      this.lastError = error.message;
      this.lastErrorAt = new Date().toISOString();
      this.consecutiveFailures += 1;
      this.connectionState = this.consecutiveFailures >= this.failureThreshold
        ? "offline"
        : "reconnecting";
      const retryDelay = Math.min(
        this.maximumRetryMs,
        this.intervalMs * (2 ** Math.min(10, this.consecutiveFailures - 1))
      );
      this.nextRetryAt = new Date(Date.now() + retryDelay).toISOString();
      if (this.consecutiveFailures >= this.failureThreshold && !this.offlineNotified) {
        this.offlineNotified = true;
        this.emit({
          type: "hq.connection-lost",
          hqName: this.credentials.hqName,
          serverUrl: this.credentials.serverUrl,
          error: error.message,
          failures: this.consecutiveFailures,
          retryInMs: retryDelay
        });
      }
      await this.persistState();
      return retryDelay;
    }
  }

  beginCommand(command) {
    if (!/^[a-f0-9-]{36}$/i.test(command.id) || this.activeCommands.has(command.id)) return;
    this.activeCommands.add(command.id);
    void (async () => {
      const startedAt = new Date().toISOString();
      try {
        await this.request(`/api/v1/device/commands/${command.id}/result`, {
          method: "POST",
          body: { status: "running", result: { acceptedAt: startedAt } }
        });
        this.emit({
          type: "hq.command-started",
          commandId: command.id,
          commandType: command.type,
          message: `Background command ${command.type} started`
        });
        const result = await this.commandExecutor(command);
        await this.request(`/api/v1/device/commands/${command.id}/result`, {
          method: "POST",
          body: { status: "completed", result }
        });
        this.emit({
          type: "hq.command-completed",
          commandId: command.id,
          commandType: command.type,
          durationMs: Date.now() - new Date(startedAt).getTime(),
          result,
          message: `Background command ${command.type} completed`
        });
      } catch (error) {
        await this.request(`/api/v1/device/commands/${command.id}/result`, {
          method: "POST",
          body: { status: "failed", result: { error: error.message } }
        }).catch(() => {});
        this.emit({
          type: "hq.command-failed",
          commandId: command.id,
          commandType: command.type,
          durationMs: Date.now() - new Date(startedAt).getTime(),
          error: error.message
        });
      } finally {
        this.activeCommands.delete(command.id);
      }
    })();
  }

  stop() {
    this.running = false;
    clearTimeout(this.timer);
    this.timer = null;
    this.nextRetryAt = null;
    void this.persistState();
  }

  status() {
    return {
      enabled: true,
      running: this.running,
      hqName: this.credentials.hqName,
      serverUrl: this.credentials.serverUrl,
      deviceId: this.credentials.deviceId,
      enrolledAt: this.credentials.enrolledAt,
      connectionState: this.connectionState,
      connected: this.running && this.connectionState === "online",
      consecutiveFailures: this.consecutiveFailures,
      lastAttemptAt: this.lastAttemptAt,
      lastConnectedAt: this.lastConnectedAt,
      lastErrorAt: this.lastErrorAt,
      lastResumeAt: this.lastResumeAt,
      lastError: this.lastError,
      nextRetryAt: this.nextRetryAt,
      activeCommands: this.activeCommands.size
    };
  }
}
