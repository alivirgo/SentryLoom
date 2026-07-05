import fs from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import dgram from "node:dgram";
import crypto from "node:crypto";
import { createReadStream } from "node:fs";
import { fileURLToPath } from "node:url";
import { HqStore, verifyAdminPassword } from "./store.js";
import { compareVersions, UpdateService } from "./update-service.js";
import { wakeDevice } from "./wake-on-lan.js";
import { HqSecretStore } from "./secret-store.js";
import { ThreatGateway } from "./threat-gateway.js";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.resolve(moduleDirectory, "..", "public");
const DISCOVERY_REQUEST = "SENTRYLOOM_HQ_DISCOVER_V1";
const HQ_VERSION = "0.4.4";
const DEFAULT_UPDATE_STAGING = "Z:\\Extreme Control\\SentryLoom Updates";
const HQ_CAPABILITIES = Object.freeze([
  "maintenance-authorization-v1",
  "maintenance-request-v1",
  "threat-intelligence-gateway-v1"
]);
const SETTING_OPTIONS = Object.freeze({
  retentionDays: [30, 90, 365],
  offlineAfterSeconds: [60, 300, 900],
  sessionHours: [1, 4, 8, 12, 24],
  maxLoginAttempts: [5, 10, 20],
  maintenanceMinutes: [5, 10, 30, 60],
  maintenanceUses: [1, 3, 10]
});
const COMMAND_TYPES = new Set([
  "scan.quick",
  "scan.full",
  "scan.startup",
  "scan.processes",
  "scan.external",
  "scan.cancel",
  "update.databases",
  "client.update",
  "protection.fix-all",
  "protection.restart"
]);
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml"
};

function sendJson(response, status, value, headers = {}) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers
  });
  response.end(body);
}

async function readJson(request, maximumBytes = 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > maximumBytes) throw new Error("Request body is too large");
    chunks.push(chunk);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}

function cookies(request) {
  return Object.fromEntries((request.headers.cookie || "").split(";").map((part) => {
    const [name, ...value] = part.trim().split("=");
    return [name, value.join("=")];
  }).filter(([name]) => name));
}

function clientAddress(request) {
  return String(request.socket.remoteAddress || "").replace(/^::ffff:/, "");
}

function selected(value, allowed, fallback) {
  const numeric = Number(value);
  return allowed.includes(numeric) ? numeric : fallback;
}

function stagingDirectory(value, fallback = DEFAULT_UPDATE_STAGING) {
  const candidate = String(value || fallback).trim();
  if (!candidate || candidate.length > 1024 ||
      (!path.isAbsolute(candidate) && !path.win32.isAbsolute(candidate))) {
    throw new Error("The update staging folder must be an absolute local or UNC path");
  }
  return candidate;
}

export function applyHqSettings(config, update = {}) {
  config.schemaVersion = Math.max(4, Number(config.schemaVersion) || 1);
  config.telemetryRetentionDays = selected(
    update.telemetryRetentionDays ?? config.telemetryRetentionDays,
    SETTING_OPTIONS.retentionDays,
    30
  );
  config.alerts = {
    ...(config.alerts || {}),
    offlineAfterSeconds: selected(
      update.offlineAfterSeconds ?? config.alerts?.offlineAfterSeconds,
      SETTING_OPTIONS.offlineAfterSeconds,
      60
    )
  };
  config.admin = {
    ...config.admin,
    sessionHours: selected(
      update.sessionHours ?? config.admin?.sessionHours,
      SETTING_OPTIONS.sessionHours,
      12
    ),
    maxLoginAttempts: selected(
      update.maxLoginAttempts ?? config.admin?.maxLoginAttempts,
      SETTING_OPTIONS.maxLoginAttempts,
      10
    )
  };
  config.maintenance = {
    ...(config.maintenance || {}),
    defaultMinutes: selected(
      update.maintenanceMinutes ?? config.maintenance?.defaultMinutes,
      SETTING_OPTIONS.maintenanceMinutes,
      10
    ),
    defaultUses: selected(
      update.maintenanceUses ?? config.maintenance?.defaultUses,
      SETTING_OPTIONS.maintenanceUses,
      1
    )
  };
  config.secrets = {
    ...(config.secrets || {}),
    path: String(config.secrets?.path || "hq-secrets.json")
  };
  config.updates = {
    ...config.updates,
    stagingDirectory: stagingDirectory(
      update.stagingDirectory ?? config.updates?.stagingDirectory
    ),
    autoDeploy: update.autoDeploy === undefined
      ? Boolean(config.updates?.autoDeploy)
      : Boolean(update.autoDeploy)
  };
  return config;
}

export function publicHqSettings(config) {
  return {
    schemaVersion: config.schemaVersion,
    telemetryRetentionDays: config.telemetryRetentionDays,
    offlineAfterSeconds: config.alerts.offlineAfterSeconds,
    sessionHours: config.admin.sessionHours,
    maxLoginAttempts: config.admin.maxLoginAttempts,
    maintenanceMinutes: config.maintenance.defaultMinutes,
    maintenanceUses: config.maintenance.defaultUses,
    stagingDirectory: config.updates.stagingDirectory,
    autoDeploy: Boolean(config.updates.autoDeploy),
    allowed: SETTING_OPTIONS
  };
}

function validateDevice(body) {
  const device = body?.device || {};
  if (!/^[a-f0-9-]{36}$/i.test(String(device.installationId || ""))) {
    throw new Error("A valid installation identifier is required");
  }
  for (const field of ["name", "hostname", "platform", "appVersion"]) {
    if (!String(device[field] || "").trim() || String(device[field]).length > 200) {
      throw new Error(`Device ${field} is invalid`);
    }
  }
  return {
    installationId: String(device.installationId),
    name: String(device.name).trim(),
    hostname: String(device.hostname).trim(),
    platform: String(device.platform).trim(),
    appVersion: String(device.appVersion).trim()
  };
}

function alertMessage(event) {
  if (event.type === "scan.completed" && Number(event.result?.detections) > 0) {
    const count = Number(event.result.detections);
    return `${count} threat${count === 1 ? "" : "s"} found by the ${event.result.type || "requested"} scan`;
  }
  return String(
    event.error ||
    event.reason ||
    event.message ||
    event.result?.findings?.[0]?.name ||
    event.observation?.domain ||
    event.observation?.endpoint ||
    event.type ||
    "Endpoint attention required"
  ).slice(0, 500);
}

export function buildAdminAlerts(store, options = {}) {
  const now = Number(options.now) || Date.now();
  const offlineAfterMs = Math.max(10000, Number(options.offlineAfterMs) || 60000);
  const alerts = [];
  for (const device of store.listDevices()) {
    if (device.revokedAt) continue;
    const lastSeenAt = new Date(device.lastSeen || device.enrolledAt || 0).getTime();
    if (!Number.isFinite(lastSeenAt) || now - lastSeenAt >= offlineAfterMs) {
      alerts.push({
        id: `device-offline:${device.id}`,
        kind: "availability",
        severity: "warning",
        deviceId: device.id,
        deviceName: device.name,
        at: device.lastSeen || device.enrolledAt,
        title: `${device.name} is offline`,
        message: device.lastSeen
          ? `No telemetry has arrived since ${device.lastSeen}. The client will reconnect automatically.`
          : "This endpoint has not sent its first telemetry report."
      });
    }

    for (const event of Array.isArray(device.status?.events) ? device.status.events : []) {
      const type = String(event.type || "");
      const detection = type === "detection" ||
        type.includes(".detection") ||
        type === "ransomware.canary-tampered" ||
        type === "ransomware.write-burst" ||
        (type === "scan.completed" && Number(event.result?.detections) > 0) ||
        (type === "windows.security-event" && Number(event.event?.eventId) === 1116);
      const failure = /(?:^|[.-])(?:error|failed|failure|unavailable)$/.test(type);
      if (!detection && !failure) continue;
      alerts.push({
        id: `event:${device.id}:${event.id || crypto.createHash("sha256").update(
          `${type}|${event.at || ""}|${alertMessage(event)}`
        ).digest("hex").slice(0, 20)}`,
        kind: detection ? "detection" : "failure",
        severity: detection ? "critical" : "warning",
        deviceId: device.id,
        deviceName: device.name,
        at: event.at || device.lastSeen,
        title: detection
          ? `${device.name}: threat detected`
          : `${device.name}: operation failed`,
        message: alertMessage(event),
        eventType: type
      });
    }

    for (const command of store.listCommands(device.id, 20)) {
      if (command.status !== "failed" && command.status !== "rejected") continue;
      alerts.push({
        id: `command:${command.id}:${command.status}`,
        kind: "command",
        severity: "warning",
        deviceId: device.id,
        deviceName: device.name,
        at: command.completedAt || command.createdAt,
        title: `${device.name}: remote action ${command.status}`,
        message: command.result?.error || `${command.type} did not complete successfully`,
        eventType: command.type
      });
    }
  }
  return alerts
    .sort((left, right) => new Date(right.at || 0) - new Date(left.at || 0))
    .slice(0, 100);
}

export async function createHqServer(config, options = {}) {
  applyHqSettings(config);
  const store = options.store || await new HqStore(config.databasePath).open();
  const updateService = options.updateService || new UpdateService(
    config.updates?.directory || path.join(path.dirname(config.databasePath), "updates")
  );
  const secretStore = options.secretStore || new HqSecretStore(
    config.secrets?.path || path.join(path.dirname(config.databasePath), "hq-secrets.json")
  );
  const threatGateway = options.threatGateway || new ThreatGateway(secretStore);
  const sessions = new Map();
  const loginAttempts = new Map();
  const adminAttempts = new Map();
  const enrollmentRequestAttempts = new Map();
  const maintenanceAttempts = new Map();
  let discoverySocket = null;

  function adminSession(request) {
    const id = cookies(request).sentryloom_hq_session;
    const session = sessions.get(id);
    if (!session || Date.now() - session.createdAt > config.admin.sessionHours * 60 * 60 * 1000) {
      if (id) sessions.delete(id);
      return null;
    }
    return session;
  }

  async function persistHqSettings() {
    if (!options.configPath) return;
    const current = JSON.parse(await fs.readFile(options.configPath, "utf8"));
    current.schemaVersion = config.schemaVersion;
    current.telemetryRetentionDays = config.telemetryRetentionDays;
    current.alerts = { ...(current.alerts || {}), ...config.alerts };
    current.admin = {
      ...current.admin,
      sessionHours: config.admin.sessionHours,
      maxLoginAttempts: config.admin.maxLoginAttempts
    };
    current.maintenance = { ...(current.maintenance || {}), ...config.maintenance };
    current.updates = {
      ...(current.updates || {}),
      stagingDirectory: config.updates.stagingDirectory,
      autoDeploy: Boolean(config.updates.autoDeploy)
    };
    const temporary = `${options.configPath}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    await fs.writeFile(temporary, `${JSON.stringify(current, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx"
    });
    try {
      await fs.rename(temporary, options.configPath);
    } catch (error) {
      await fs.rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  }

  function clientSession(request) {
    const authorization = request.headers.authorization || "";
    const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    return store.authenticateDevice(request.headers["x-sentryloom-device"], token);
  }

  function queueClientUpdate(update) {
    const commands = store.listDevices()
      .filter((device) =>
        !device.revokedAt &&
        compareVersions(
          update.version,
          device.status?.device?.appVersion || device.appVersion
        ) > 0
      )
      .map((device) => store.ensureCommand(
        device.id,
        "client.update",
        { version: update.version }
      ));
    return {
      version: update.version,
      queued: commands.filter((command) => !command.deduplicated).length,
      alreadyQueued: commands.filter((command) => command.deduplicated).length
    };
  }

  async function handler(request, response) {
    try {
      const url = new URL(request.url, "https://sentryloom-hq.local");
      if (request.method === "GET" && url.pathname === "/api/v1/hq") {
        sendJson(response, 200, {
          protocol: "sentryloom-hq/1",
          name: config.hqName,
          version: HQ_VERSION,
          capabilities: HQ_CAPABILITIES,
          fingerprint256: config.tls.fingerprint256
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/v1/enroll") {
        const address = clientAddress(request);
        const prior = loginAttempts.get(address) || { count: 0, since: Date.now() };
        if (Date.now() - prior.since < 60000 && prior.count >= config.admin.maxLoginAttempts) {
          sendJson(response, 429, { error: "Too many enrollment attempts" });
          return;
        }
        const body = await readJson(request);
        const device = validateDevice(body);
        if (!store.consumeEnrollmentCode(String(body.code || ""))) {
          loginAttempts.set(address, {
            count: Date.now() - prior.since > 60000 ? 1 : prior.count + 1,
            since: Date.now() - prior.since > 60000 ? Date.now() : prior.since
          });
          sendJson(response, 403, { error: "Enrollment code is invalid or expired" });
          return;
        }
        const enrollment = store.enrollDevice(device, address);
        sendJson(response, 201, {
          protocol: "sentryloom-hq/1",
          hqName: config.hqName,
          deviceId: enrollment.id,
          token: enrollment.token,
          enrolledAt: enrollment.enrolledAt
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/v1/enrollment-requests") {
        const address = clientAddress(request);
        const prior = enrollmentRequestAttempts.get(address) || { count: 0, since: Date.now() };
        if (Date.now() - prior.since < 60 * 60 * 1000 && prior.count >= 20) {
          sendJson(response, 429, { error: "Too many enrollment requests from this address" });
          return;
        }
        const body = await readJson(request);
        const pending = store.createEnrollmentRequest(validateDevice(body), address);
        enrollmentRequestAttempts.set(address, {
          count: Date.now() - prior.since > 60 * 60 * 1000 ? 1 : prior.count + 1,
          since: Date.now() - prior.since > 60 * 60 * 1000 ? Date.now() : prior.since
        });
        sendJson(response, 202, {
          protocol: "sentryloom-hq/1",
          hqName: config.hqName,
          requestId: pending.id,
          requestSecret: pending.secret,
          requestedAt: pending.requestedAt,
          status: "pending"
        });
        return;
      }

      const enrollmentRequestMatch = url.pathname.match(
        /^\/api\/v1\/enrollment-requests\/([a-f0-9-]{36})$/i
      );
      if (request.method === "GET" && enrollmentRequestMatch) {
        const authorization = request.headers.authorization || "";
        const secret = authorization.startsWith("Enrollment ") ? authorization.slice(11) : "";
        const pending = store.enrollmentRequest(enrollmentRequestMatch[1], secret);
        if (!pending) {
          sendJson(response, 401, { error: "Enrollment request authentication failed" });
          return;
        }
        const result = store.provisionEnrollmentRequest(pending);
        sendJson(response, 200, {
          protocol: "sentryloom-hq/1",
          hqName: config.hqName,
          ...result
        });
        return;
      }

      if (url.pathname.startsWith("/api/v1/device/")) {
        const device = clientSession(request);
        if (!device) {
          sendJson(response, 401, { error: "Device authentication failed" });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/v1/device/telemetry") {
          const payload = await readJson(request, 2 * 1024 * 1024);
          const receivedAt = store.recordTelemetry(device.id, payload, clientAddress(request));
          if (config.updates?.autoDeploy) {
            const update = await updateService.latest();
            if (update && compareVersions(update.version, payload.device?.appVersion) > 0) {
              store.ensureCommand(device.id, "client.update", { version: update.version });
            }
          }
          sendJson(response, 202, {
            receivedAt,
            hq: {
              version: HQ_VERSION,
              capabilities: HQ_CAPABILITIES,
              abuseChGatewayConfigured: (await threatGateway.status()).abuseChConfigured
            }
          });
          return;
        }
        const threatGatewayMatch = url.pathname.match(
          /^\/api\/v1\/device\/threat-intelligence\/(malwarebazaar|urlhaus|threatfox)$/i
        );
        if (request.method === "GET" && threatGatewayMatch) {
          sendJson(response, 200, await threatGateway.fetchSource(
            threatGatewayMatch[1].toLowerCase()
          ));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/v1/device/maintenance-requests") {
          const body = await readJson(request);
          let publicKey;
          try {
            publicKey = crypto.createPublicKey(String(body.publicKey || ""));
          } catch {
            sendJson(response, 400, { error: "A valid maintenance request public key is required" });
            return;
          }
          if (publicKey.asymmetricKeyType !== "rsa") {
            sendJson(response, 400, { error: "Maintenance requests require an RSA public key" });
            return;
          }
          const pending = store.createMaintenanceRequest(
            device.id,
            body.action,
            body.reason,
            publicKey.export({ type: "spki", format: "pem" }),
            20
          );
          sendJson(response, 202, {
            id: pending.id,
            status: pending.status,
            requestedAt: pending.requestedAt,
            expiresAt: pending.expiresAt,
            approvalWindowSeconds: 20
          });
          return;
        }
        const maintenanceRequestMatch = url.pathname.match(
          /^\/api\/v1\/device\/maintenance-requests\/([a-f0-9-]{36})$/i
        );
        if (request.method === "GET" && maintenanceRequestMatch) {
          const pending = store.getMaintenanceRequest(maintenanceRequestMatch[1]);
          if (!pending || pending.deviceId !== device.id) {
            sendJson(response, 404, { error: "Maintenance request was not found" });
            return;
          }
          sendJson(response, 200, {
            id: pending.id,
            status: pending.status,
            expiresAt: pending.expiresAt,
            passwordExpiresAt: pending.passwordExpiresAt,
            encryptedPassword: pending.status === "approved"
              ? pending.encryptedPassword
              : undefined
          });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/v1/device/maintenance/authorize") {
          const prior = maintenanceAttempts.get(device.id) || { count: 0, since: Date.now() };
          if (Date.now() - prior.since < 60000 && prior.count >= 10) {
            sendJson(response, 429, { error: "Too many maintenance password attempts" });
            return;
          }
          const body = await readJson(request);
          const authorized = store.consumeMaintenancePassword(String(body.password || ""), device.id);
          if (!authorized) {
            maintenanceAttempts.set(device.id, {
              count: Date.now() - prior.since > 60000 ? 1 : prior.count + 1,
              since: Date.now() - prior.since > 60000 ? Date.now() : prior.since
            });
            sendJson(response, 403, { error: "Maintenance password is invalid, expired, used, or revoked" });
            return;
          }
          maintenanceAttempts.delete(device.id);
          sendJson(response, 200, {
            authorized: true,
            authorizationId: authorized.id,
            action: String(body.action || "critical-settings").slice(0, 100)
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/v1/device/update") {
          sendJson(response, 200, { update: updateService.publicManifest(await updateService.latest()) });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/v1/device/update/package") {
          const update = await updateService.latest();
          if (!update) {
            sendJson(response, 404, { error: "No client update is published" });
            return;
          }
          response.writeHead(200, {
            "Content-Type": "application/octet-stream",
            "Content-Length": update.size,
            "Content-Disposition": `attachment; filename="${update.fileName}"`,
            "Cache-Control": "private, no-store",
            "X-SentryLoom-SHA256": update.sha256,
            "X-Content-Type-Options": "nosniff"
          });
          await new Promise((resolve, reject) => {
            const stream = createReadStream(update.packagePath);
            stream.on("error", reject);
            response.on("close", resolve);
            stream.on("end", resolve);
            stream.pipe(response);
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/v1/device/commands") {
          sendJson(response, 200, { commands: store.pendingCommands(device.id) });
          return;
        }
        const resultMatch = url.pathname.match(/^\/api\/v1\/device\/commands\/([a-f0-9-]{36})\/result$/i);
        if (request.method === "POST" && resultMatch) {
          const body = await readJson(request);
          if (!store.completeCommand(device.id, resultMatch[1], body.status, body.result)) {
            sendJson(response, 404, { error: "Command was not found" });
            return;
          }
          sendJson(response, 200, { updated: true });
          return;
        }
        sendJson(response, 404, { error: "Device API route not found" });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/admin/login") {
        const address = clientAddress(request);
        const prior = adminAttempts.get(address) || { count: 0, since: Date.now() };
        if (Date.now() - prior.since < 60000 && prior.count >= 10) {
          sendJson(response, 429, { error: "Too many administrator sign-in attempts" });
          return;
        }
        const body = await readJson(request);
        if (!verifyAdminPassword(String(body.password || ""), config.admin)) {
          adminAttempts.set(address, {
            count: Date.now() - prior.since > 60000 ? 1 : prior.count + 1,
            since: Date.now() - prior.since > 60000 ? Date.now() : prior.since
          });
          sendJson(response, 403, { error: "Invalid administrator password" });
          return;
        }
        adminAttempts.delete(address);
        const id = crypto.randomBytes(32).toString("base64url");
        const session = {
          createdAt: Date.now(),
          csrf: crypto.randomBytes(24).toString("base64url")
        };
        sessions.set(id, session);
        sendJson(response, 200, { csrf: session.csrf }, {
          "Set-Cookie": `sentryloom_hq_session=${id}; HttpOnly; Secure; SameSite=Strict; Path=/`
        });
        return;
      }

      if (url.pathname.startsWith("/api/admin/")) {
        const session = adminSession(request);
        if (!session) {
          sendJson(response, 401, { error: "Administrator session required" });
          return;
        }
        if (request.method !== "GET" && request.headers["x-sentryloom-csrf"] !== session.csrf) {
          sendJson(response, 403, { error: "Request verification failed" });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/bootstrap") {
          sendJson(response, 200, {
            hq: { name: config.hqName, version: HQ_VERSION },
            csrf: session.csrf,
            devices: store.listDevices(),
            enrollmentRequests: store.listEnrollmentRequests(),
            maintenance: {
              passwords: store.listMaintenancePasswords(),
              requests: store.listMaintenanceRequests()
            },
            settings: publicHqSettings(config)
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/devices") {
          sendJson(response, 200, store.listDevices());
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/alerts") {
          const offlineAfterMs = config.alerts.offlineAfterSeconds * 1000;
          sendJson(response, 200, {
            generatedAt: new Date().toISOString(),
            offlineAfterMs,
            alerts: buildAdminAlerts(store, { offlineAfterMs })
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/settings") {
          sendJson(response, 200, publicHqSettings(config));
          return;
        }
        if (request.method === "PATCH" && url.pathname === "/api/admin/settings") {
          const body = await readJson(request);
          applyHqSettings(config, body);
          await persistHqSettings();
          const pruning = store.pruneOperationalData(config.telemetryRetentionDays);
          sendJson(response, 200, {
            settings: publicHqSettings(config),
            pruning,
            appliedAt: new Date().toISOString()
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/update") {
          sendJson(response, 200, {
            update: updateService.publicManifest(await updateService.latest()),
            autoDeploy: Boolean(config.updates?.autoDeploy),
            staging: await updateService.stagingStatus(config.updates.stagingDirectory)
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/threat-credentials") {
          sendJson(response, 200, await secretStore.status());
          return;
        }
        if (request.method === "PUT" && url.pathname === "/api/admin/threat-credentials") {
          const body = await readJson(request);
          const status = await secretStore.setAbuseChAuthKey(body.abuseChAuthKey);
          threatGateway.clearCache();
          sendJson(response, 200, status);
          return;
        }
        if (request.method === "DELETE" && url.pathname === "/api/admin/threat-credentials") {
          const status = await secretStore.clearAbuseChAuthKey();
          threatGateway.clearCache();
          sendJson(response, 200, status);
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/maintenance") {
          sendJson(response, 200, {
            generatedAt: new Date().toISOString(),
            passwords: store.listMaintenancePasswords(),
            requests: store.listMaintenanceRequests()
          });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/admin/maintenance/passwords") {
          const body = await readJson(request);
          const password = `SL-${crypto.randomBytes(24).toString("base64url")}`;
          const policy = store.createMaintenancePassword(password, {
            minutes: body.minutes ?? config.maintenance.defaultMinutes,
            uses: body.uses ?? config.maintenance.defaultUses,
            source: "administrator"
          });
          sendJson(response, 201, {
            password,
            ...policy,
            notice: "This password is shown once. Store it securely or generate another."
          });
          return;
        }
        const maintenancePasswordRevokeMatch = url.pathname.match(
          /^\/api\/admin\/maintenance\/passwords\/([a-f0-9-]{36})\/revoke$/i
        );
        if (request.method === "POST" && maintenancePasswordRevokeMatch) {
          sendJson(response, 200, {
            revoked: store.revokeMaintenancePassword(maintenancePasswordRevokeMatch[1])
          });
          return;
        }
        const maintenanceReviewMatch = url.pathname.match(
          /^\/api\/admin\/maintenance\/requests\/([a-f0-9-]{36})\/(approve|reject)$/i
        );
        if (request.method === "POST" && maintenanceReviewMatch) {
          const pending = store.getMaintenanceRequest(maintenanceReviewMatch[1]);
          if (!pending) {
            sendJson(response, 404, { error: "Maintenance request was not found" });
            return;
          }
          if (pending.status !== "pending") {
            sendJson(response, 409, { error: "The maintenance request is no longer pending" });
            return;
          }
          if (maintenanceReviewMatch[2] === "reject") {
            const reviewed = store.reviewMaintenanceRequest(pending.id, false);
            sendJson(response, 200, {
              id: reviewed.id,
              status: reviewed.status,
              reviewedAt: reviewed.reviewedAt
            });
            return;
          }
          const password = `SL-${crypto.randomBytes(24).toString("base64url")}`;
          const policy = store.createMaintenancePassword(password, {
            minutes: 2,
            uses: 1,
            source: "client-request",
            deviceId: pending.deviceId
          });
          let encryptedPassword;
          try {
            encryptedPassword = crypto.publicEncrypt({
              key: pending.publicKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: "sha256"
            }, Buffer.from(password, "utf8")).toString("base64");
          } catch (error) {
            store.revokeMaintenancePassword(policy.id);
            throw new Error(`Could not encrypt the maintenance password for the endpoint: ${error.message}`);
          }
          let reviewed;
          try {
            reviewed = store.reviewMaintenanceRequest(pending.id, true, {
              encryptedPassword,
              maintenancePasswordId: policy.id
            });
          } catch (error) {
            store.revokeMaintenancePassword(policy.id);
            throw error;
          }
          sendJson(response, 200, {
            id: reviewed.id,
            status: reviewed.status,
            reviewedAt: reviewed.reviewedAt,
            expiresAt: policy.expiresAt
          });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/admin/update/deploy") {
          const update = await updateService.latest();
          if (!update) {
            sendJson(response, 409, { error: "No signed client update is published" });
            return;
          }
          sendJson(response, 202, queueClientUpdate(update));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/admin/update/publish-latest") {
          const published = await updateService.publishLatest(config.updates.stagingDirectory, {
            releaseNotes: "Published from the configured HQ staging folder"
          });
          sendJson(response, 202, {
            update: updateService.publicManifest(published),
            sourceFile: published.sourceFile,
            deployment: queueClientUpdate(published)
          });
          return;
        }
        const detailsMatch = url.pathname.match(/^\/api\/admin\/devices\/([a-f0-9-]{36})\/details$/i);
        if (request.method === "GET" && detailsMatch) {
          const device = store.getDevice(detailsMatch[1]);
          if (!device) {
            sendJson(response, 404, { error: "Managed device was not found" });
            return;
          }
          sendJson(response, 200, {
            device,
            telemetry: store.telemetryHistory(device.id, url.searchParams.get("limit")),
            commands: store.listCommands(device.id)
          });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/admin/enrollment-codes") {
          const body = await readJson(request);
          const code = crypto.randomBytes(9).toString("base64url").toUpperCase();
          const policy = store.createEnrollmentCode(code, {
            hours: body.hours,
            uses: body.uses
          });
          sendJson(response, 201, { code, ...policy });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/admin/enrollment-requests") {
          sendJson(response, 200, store.listEnrollmentRequests());
          return;
        }
        const reviewMatch = url.pathname.match(
          /^\/api\/admin\/enrollment-requests\/([a-f0-9-]{36})\/(approve|reject)$/i
        );
        if (request.method === "POST" && reviewMatch) {
          const reviewed = store.reviewEnrollmentRequest(reviewMatch[1], reviewMatch[2] === "approve");
          sendJson(response, 200, {
            id: reviewed.id,
            status: reviewed.status,
            reviewedAt: reviewed.reviewed_at
          });
          return;
        }
        const commandMatch = url.pathname.match(/^\/api\/admin\/devices\/([a-f0-9-]{36})\/commands$/i);
        if (commandMatch && request.method === "GET") {
          sendJson(response, 200, store.listCommands(commandMatch[1]));
          return;
        }
        if (commandMatch && request.method === "POST") {
          const body = await readJson(request);
          if (!COMMAND_TYPES.has(body.type)) {
            sendJson(response, 400, { error: "Command type is not allowed" });
            return;
          }
          sendJson(response, 201, store.createCommand(commandMatch[1], body.type, body.payload));
          return;
        }
        const wakeMatch = url.pathname.match(/^\/api\/admin\/devices\/([a-f0-9-]{36})\/wake$/i);
        if (wakeMatch && request.method === "POST") {
          const device = store.getDevice(wakeMatch[1]);
          if (!device || device.revokedAt) {
            sendJson(response, 404, { error: "Managed device was not found" });
            return;
          }
          sendJson(response, 202, await wakeDevice(device));
          return;
        }
        const revokeMatch = url.pathname.match(/^\/api\/admin\/devices\/([a-f0-9-]{36})\/revoke$/i);
        if (revokeMatch && request.method === "POST") {
          sendJson(response, 200, { revoked: store.revokeDevice(revokeMatch[1]) });
          return;
        }
        sendJson(response, 404, { error: "Administrator API route not found" });
        return;
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        sendJson(response, 405, { error: "Method not allowed" });
        return;
      }
      const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      const file = path.resolve(publicDirectory, relative);
      if (!file.startsWith(`${publicDirectory}${path.sep}`) && file !== path.join(publicDirectory, "index.html")) {
        response.writeHead(403).end();
        return;
      }
      const content = await fs.readFile(file);
      response.writeHead(200, {
        "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
        "Content-Length": content.length,
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer"
      });
      response.end(request.method === "HEAD" ? undefined : content);
    } catch (error) {
      if (error.code === "ENOENT") {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        response.end("Not found");
        return;
      }
      sendJson(response, 500, { error: error.message });
    }
  }

  let webServer;
  if (options.httpOnly) {
    webServer = http.createServer(handler);
  } else {
    webServer = https.createServer({
      pfx: await fs.readFile(config.tls.pfxPath),
      passphrase: config.tls.password,
      minVersion: "TLSv1.2"
    }, handler);
  }

  return {
    store,
    async listen(host = config.host, port = config.port) {
      await new Promise((resolve, reject) => {
        webServer.once("error", reject);
        webServer.listen(port, host, resolve);
      });
      const address = webServer.address();
      return { host: address.address, port: address.port };
    },
    startDiscovery() {
      if (options.httpOnly || config.discovery?.enabled === false || discoverySocket) return;
      discoverySocket = dgram.createSocket({ type: "udp4", reuseAddr: true });
      discoverySocket.on("error", (error) => {
        console.error(`SentryLoom HQ discovery error: ${error.message}`);
      });
      discoverySocket.on("message", (message, remote) => {
        if (message.toString("utf8").trim() !== DISCOVERY_REQUEST) return;
        const response = Buffer.from(JSON.stringify({
          protocol: "sentryloom-hq/1",
          name: config.hqName,
          url: `https://${config.publicHost}:${config.port}`,
          fingerprint256: config.tls.fingerprint256
        }));
        discoverySocket.send(response, remote.port, remote.address, (error) => {
          if (error) {
            console.error(`SentryLoom HQ discovery response failed for ${remote.address}: ${error.message}`);
          }
        });
      });
      discoverySocket.bind(config.discovery.port, "0.0.0.0", () => {
        discoverySocket.setBroadcast(true);
      });
    },
    async close() {
      if (discoverySocket) {
        await new Promise((resolve) => discoverySocket.close(resolve));
        discoverySocket = null;
      }
      if (webServer.listening) {
        await new Promise((resolve, reject) => webServer.close((error) => error ? reject(error) : resolve()));
      }
      if (!options.store) store.close();
    }
  };
}

export { COMMAND_TYPES, DISCOVERY_REQUEST };
