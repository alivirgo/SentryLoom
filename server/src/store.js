import crypto from "node:crypto";
import path from "node:path";
import fs from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";

function digest(value) {
  return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function parse(value, fallback = null) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function deviceFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    installationId: row.installation_id,
    name: row.name,
    hostname: row.hostname,
    platform: row.platform,
    appVersion: row.app_version,
    enrolledAt: row.enrolled_at,
    lastSeen: row.last_seen,
    remoteAddress: row.remote_address,
    revokedAt: row.revoked_at,
    status: parse(row.status_json, {})
  };
}

function telemetrySnapshot(row) {
  const payload = parse(row.payload_json, {});
  return {
    receivedAt: row.received_at,
    score: payload.security?.score ?? null,
    quarantineCount: payload.security?.quarantineCount ?? null,
    rssBytes: payload.runtime?.rssBytes ?? null,
    heapUsedBytes: payload.runtime?.heapUsedBytes ?? null,
    filesInspected: payload.protection?.file?.filesInspected ?? null,
    fileDetections: payload.protection?.file?.detections ?? null,
    networkDetections: payload.protection?.network?.detections ?? null,
    processDetections: payload.protection?.advanced?.processDetections ?? null,
    scanActive: Boolean(payload.scan?.active),
    scanCompleted: payload.scan?.progress?.completed ?? null,
    scanTotal: payload.scan?.progress?.total ?? null
  };
}

export class HqStore {
  constructor(databasePath) {
    this.databasePath = path.resolve(databasePath);
    this.database = null;
  }

  async open() {
    await fs.mkdir(path.dirname(this.databasePath), { recursive: true });
    this.database = new DatabaseSync(this.databasePath);
    this.database.exec(`
      PRAGMA journal_mode=WAL;
      PRAGMA synchronous=NORMAL;
      PRAGMA busy_timeout=10000;
      PRAGMA foreign_keys=ON;

      CREATE TABLE IF NOT EXISTS enrollment_codes (
        code_hash TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        uses_remaining INTEGER NOT NULL CHECK (uses_remaining > 0)
      );

      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL UNIQUE,
        token_hash TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        hostname TEXT NOT NULL,
        platform TEXT NOT NULL,
        app_version TEXT NOT NULL,
        enrolled_at TEXT NOT NULL,
        last_seen TEXT,
        remote_address TEXT,
        revoked_at TEXT,
        status_json TEXT
      );

      CREATE TABLE IF NOT EXISTS enrollment_requests (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL UNIQUE,
        request_secret_hash TEXT NOT NULL,
        device_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'provisioned')),
        requested_at TEXT NOT NULL,
        reviewed_at TEXT,
        remote_address TEXT,
        device_id TEXT REFERENCES devices(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_enrollment_requests_status
        ON enrollment_requests(status, requested_at);

      CREATE TABLE IF NOT EXISTS telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        received_at TEXT NOT NULL,
        payload_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_telemetry_device_received
        ON telemetry(device_id, received_at DESC);

      CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        delivered_at TEXT,
        completed_at TEXT,
        result_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_commands_device_status
        ON commands(device_id, status, created_at);

      CREATE TABLE IF NOT EXISTS maintenance_passwords (
        id TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        uses_remaining INTEGER NOT NULL CHECK (uses_remaining > 0),
        revoked_at TEXT,
        source TEXT NOT NULL,
        device_id TEXT REFERENCES devices(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_maintenance_passwords_active
        ON maintenance_passwords(expires_at, revoked_at);

      CREATE TABLE IF NOT EXISTS maintenance_requests (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        action TEXT NOT NULL,
        reason TEXT,
        public_key TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
        requested_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        reviewed_at TEXT,
        encrypted_password TEXT,
        maintenance_password_id TEXT REFERENCES maintenance_passwords(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_maintenance_requests_status
        ON maintenance_requests(status, expires_at);
    `);
    return this;
  }

  close() {
    this.database?.close();
    this.database = null;
  }

  createEnrollmentCode(code, options = {}) {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (Number(options.hours) || 24) * 60 * 60 * 1000);
    const uses = Math.max(1, Math.min(10000, Number(options.uses) || 1));
    this.database.prepare(`
      INSERT OR REPLACE INTO enrollment_codes
        (code_hash, created_at, expires_at, uses_remaining)
      VALUES (?, ?, ?, ?)
    `).run(digest(code), now.toISOString(), expiresAt.toISOString(), uses);
    return { expiresAt: expiresAt.toISOString(), uses };
  }

  consumeEnrollmentCode(code) {
    const codeHash = digest(code);
    const now = new Date().toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.prepare("DELETE FROM enrollment_codes WHERE expires_at <= ?").run(now);
      const record = this.database.prepare(`
        SELECT uses_remaining FROM enrollment_codes
        WHERE code_hash = ? AND expires_at > ?
      `).get(codeHash, now);
      if (!record) {
        this.database.exec("ROLLBACK");
        return false;
      }
      if (record.uses_remaining <= 1) {
        this.database.prepare("DELETE FROM enrollment_codes WHERE code_hash = ?").run(codeHash);
      } else {
        this.database.prepare(`
          UPDATE enrollment_codes SET uses_remaining = uses_remaining - 1
          WHERE code_hash = ?
        `).run(codeHash);
      }
      this.database.exec("COMMIT");
      return true;
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  enrollDevice(device, remoteAddress) {
    const now = new Date().toISOString();
    const token = crypto.randomBytes(32).toString("base64url");
    const existing = this.database.prepare(
      "SELECT id, enrolled_at FROM devices WHERE installation_id = ?"
    ).get(device.installationId);
    const id = existing?.id || crypto.randomUUID();
    this.database.prepare(`
      INSERT INTO devices (
        id, installation_id, token_hash, name, hostname, platform,
        app_version, enrolled_at, last_seen, remote_address, revoked_at, status_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
      ON CONFLICT(installation_id) DO UPDATE SET
        token_hash=excluded.token_hash,
        name=excluded.name,
        hostname=excluded.hostname,
        platform=excluded.platform,
        app_version=excluded.app_version,
        last_seen=excluded.last_seen,
        remote_address=excluded.remote_address,
        revoked_at=NULL
    `).run(
      id,
      device.installationId,
      digest(token),
      device.name,
      device.hostname,
      device.platform,
      device.appVersion,
      existing?.enrolled_at || now,
      now,
      remoteAddress || null
    );
    return { id, token, enrolledAt: existing?.enrolled_at || now };
  }

  createEnrollmentRequest(device, remoteAddress) {
    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString("base64url");
    const requestedAt = new Date().toISOString();
    this.database.prepare(`
      INSERT INTO enrollment_requests (
        id, installation_id, request_secret_hash, device_json, status,
        requested_at, reviewed_at, remote_address, device_id
      ) VALUES (?, ?, ?, ?, 'pending', ?, NULL, ?, NULL)
      ON CONFLICT(installation_id) DO UPDATE SET
        id=excluded.id,
        request_secret_hash=excluded.request_secret_hash,
        device_json=excluded.device_json,
        status='pending',
        requested_at=excluded.requested_at,
        reviewed_at=NULL,
        remote_address=excluded.remote_address,
        device_id=NULL
    `).run(
      id,
      device.installationId,
      digest(secret),
      JSON.stringify(device),
      requestedAt,
      remoteAddress || null
    );
    return { id, secret, requestedAt };
  }

  enrollmentRequest(id, secret) {
    if (!id || !secret) return null;
    const record = this.database.prepare(`
      SELECT * FROM enrollment_requests WHERE id = ?
    `).get(id);
    if (!record) return null;
    const supplied = Buffer.from(digest(secret), "hex");
    const expected = Buffer.from(record.request_secret_hash, "hex");
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
    return {
      id: record.id,
      installationId: record.installation_id,
      device: parse(record.device_json, {}),
      status: record.status,
      requestedAt: record.requested_at,
      reviewedAt: record.reviewed_at,
      remoteAddress: record.remote_address,
      deviceId: record.device_id
    };
  }

  listEnrollmentRequests() {
    return this.database.prepare(`
      SELECT id, installation_id, device_json, status, requested_at,
             reviewed_at, remote_address, device_id
      FROM enrollment_requests
      ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, requested_at DESC
      LIMIT 500
    `).all().map((record) => ({
      id: record.id,
      installationId: record.installation_id,
      device: parse(record.device_json, {}),
      status: record.status,
      requestedAt: record.requested_at,
      reviewedAt: record.reviewed_at,
      remoteAddress: record.remote_address,
      deviceId: record.device_id
    }));
  }

  reviewEnrollmentRequest(id, approved) {
    const status = approved ? "approved" : "rejected";
    const updated = this.database.prepare(`
      UPDATE enrollment_requests
      SET status = ?, reviewed_at = ?
      WHERE id = ? AND status = 'pending'
    `).run(status, new Date().toISOString(), id);
    if (!updated.changes) throw new Error("Pending enrollment request was not found");
    return this.database.prepare(`
      SELECT id, installation_id, device_json, status, requested_at,
             reviewed_at, remote_address, device_id
      FROM enrollment_requests WHERE id = ?
    `).get(id);
  }

  provisionEnrollmentRequest(request) {
    if (request.status !== "approved") return { status: request.status };
    const enrollment = this.enrollDevice(request.device, request.remoteAddress);
    this.database.prepare(`
      UPDATE enrollment_requests SET device_id = ? WHERE id = ?
    `).run(enrollment.id, request.id);
    return {
      status: "approved",
      deviceId: enrollment.id,
      token: enrollment.token,
      enrolledAt: enrollment.enrolledAt
    };
  }

  createMaintenancePassword(password, options = {}) {
    const now = new Date();
    const minutes = Math.max(1, Math.min(60, Number(options.minutes) || 10));
    const uses = Math.max(1, Math.min(100, Number(options.uses) || 1));
    const record = {
      id: crypto.randomUUID(),
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + minutes * 60000).toISOString(),
      usesRemaining: uses,
      source: String(options.source || "administrator").slice(0, 50),
      deviceId: options.deviceId || null
    };
    this.database.prepare(`
      INSERT INTO maintenance_passwords (
        id, password_hash, created_at, expires_at, uses_remaining,
        revoked_at, source, device_id
      ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)
    `).run(
      record.id,
      digest(password),
      record.createdAt,
      record.expiresAt,
      record.usesRemaining,
      record.source,
      record.deviceId
    );
    return record;
  }

  listMaintenancePasswords(limit = 100) {
    return this.database.prepare(`
      SELECT id, created_at, expires_at, uses_remaining, revoked_at, source, device_id
      FROM maintenance_passwords
      ORDER BY created_at DESC LIMIT ?
    `).all(Math.max(1, Math.min(500, Number(limit) || 100))).map((row) => ({
      id: row.id,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      usesRemaining: row.uses_remaining,
      revokedAt: row.revoked_at,
      source: row.source,
      deviceId: row.device_id,
      active: !row.revoked_at && new Date(row.expires_at).getTime() > Date.now() && row.uses_remaining > 0
    }));
  }

  revokeMaintenancePassword(id) {
    return this.database.prepare(`
      UPDATE maintenance_passwords SET revoked_at = ?
      WHERE id = ? AND revoked_at IS NULL
    `).run(new Date().toISOString(), id).changes > 0;
  }

  consumeMaintenancePassword(password, deviceId) {
    const supplied = Buffer.from(digest(password), "hex");
    const now = new Date().toISOString();
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const records = this.database.prepare(`
        SELECT id, password_hash, uses_remaining
        FROM maintenance_passwords
        WHERE revoked_at IS NULL AND expires_at > ?
          AND (device_id IS NULL OR device_id = ?)
      `).all(now, deviceId);
      const match = records.find((record) => {
        const expected = Buffer.from(record.password_hash, "hex");
        return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
      });
      if (!match) {
        this.database.exec("ROLLBACK");
        return null;
      }
      if (match.uses_remaining <= 1) {
        this.database.prepare(`
          UPDATE maintenance_passwords
          SET revoked_at = ?
          WHERE id = ?
        `).run(now, match.id);
      } else {
        this.database.prepare(`
          UPDATE maintenance_passwords
          SET uses_remaining = uses_remaining - 1
          WHERE id = ?
        `).run(match.id);
      }
      this.database.exec("COMMIT");
      return { id: match.id };
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  createMaintenanceRequest(deviceId, action, reason, publicKey, windowSeconds = 20) {
    const device = this.database.prepare(
      "SELECT id FROM devices WHERE id = ? AND revoked_at IS NULL"
    ).get(deviceId);
    if (!device) throw new Error("Managed device was not found");
    const now = new Date();
    const record = {
      id: crypto.randomUUID(),
      deviceId,
      action: String(action || "critical-settings").slice(0, 100),
      reason: String(reason || "").slice(0, 500),
      publicKey: String(publicKey),
      status: "pending",
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + Math.max(5, Math.min(60, windowSeconds)) * 1000).toISOString()
    };
    this.database.prepare(`
      UPDATE maintenance_requests SET status = 'expired'
      WHERE status = 'pending' AND expires_at <= ?
    `).run(record.requestedAt);
    this.database.prepare(`
      INSERT INTO maintenance_requests (
        id, device_id, action, reason, public_key, status,
        requested_at, expires_at, reviewed_at, encrypted_password,
        maintenance_password_id
      ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, NULL)
    `).run(
      record.id,
      record.deviceId,
      record.action,
      record.reason,
      record.publicKey,
      record.requestedAt,
      record.expiresAt
    );
    return record;
  }

  getMaintenanceRequest(id) {
    const row = this.database.prepare(`
      SELECT r.*, d.name AS device_name, p.expires_at AS password_expires_at
      FROM maintenance_requests r
      JOIN devices d ON d.id = r.device_id
      LEFT JOIN maintenance_passwords p ON p.id = r.maintenance_password_id
      WHERE r.id = ?
    `).get(id);
    if (!row) return null;
    if (row.status === "pending" && new Date(row.expires_at).getTime() <= Date.now()) {
      this.database.prepare(
        "UPDATE maintenance_requests SET status = 'expired' WHERE id = ? AND status = 'pending'"
      ).run(id);
      row.status = "expired";
    }
    return {
      id: row.id,
      deviceId: row.device_id,
      deviceName: row.device_name,
      action: row.action,
      reason: row.reason,
      publicKey: row.public_key,
      status: row.status,
      requestedAt: row.requested_at,
      expiresAt: row.expires_at,
      reviewedAt: row.reviewed_at,
      encryptedPassword: row.encrypted_password,
      maintenancePasswordId: row.maintenance_password_id,
      passwordExpiresAt: row.password_expires_at
    };
  }

  listMaintenanceRequests(limit = 100) {
    this.database.prepare(`
      UPDATE maintenance_requests SET status = 'expired'
      WHERE status = 'pending' AND expires_at <= ?
    `).run(new Date().toISOString());
    return this.database.prepare(`
      SELECT r.id
      FROM maintenance_requests r
      ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.requested_at DESC
      LIMIT ?
    `).all(Math.max(1, Math.min(500, Number(limit) || 100)))
      .map((row) => this.getMaintenanceRequest(row.id));
  }

  reviewMaintenanceRequest(id, approved, options = {}) {
    const request = this.getMaintenanceRequest(id);
    if (!request || request.status !== "pending") {
      throw new Error("Active maintenance request was not found");
    }
    if (new Date(request.expiresAt).getTime() <= Date.now()) {
      throw new Error("The 20-second maintenance approval window expired");
    }
    const status = approved ? "approved" : "rejected";
    this.database.prepare(`
      UPDATE maintenance_requests
      SET status = ?, reviewed_at = ?, encrypted_password = ?,
          maintenance_password_id = ?
      WHERE id = ? AND status = 'pending'
    `).run(
      status,
      new Date().toISOString(),
      approved ? options.encryptedPassword : null,
      approved ? options.maintenancePasswordId : null,
      id
    );
    return this.getMaintenanceRequest(id);
  }

  authenticateDevice(id, token) {
    if (!id || !token) return null;
    const device = this.database.prepare(`
      SELECT * FROM devices WHERE id = ? AND revoked_at IS NULL
    `).get(id);
    if (!device) return null;
    const supplied = Buffer.from(digest(token), "hex");
    const expected = Buffer.from(device.token_hash, "hex");
    return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected)
      ? device
      : null;
  }

  recordTelemetry(deviceId, payload, remoteAddress) {
    const receivedAt = new Date().toISOString();
    const serialized = JSON.stringify(payload);
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database.prepare(`
        UPDATE devices SET last_seen = ?, remote_address = ?, status_json = ? WHERE id = ?
      `).run(receivedAt, remoteAddress || null, serialized, deviceId);
      const lastHistorical = this.database.prepare(`
        SELECT received_at FROM telemetry WHERE device_id = ?
        ORDER BY received_at DESC LIMIT 1
      `).get(deviceId);
      if (!lastHistorical || Date.now() - new Date(lastHistorical.received_at).getTime() >= 10000) {
        this.database.prepare(`
          INSERT INTO telemetry (device_id, received_at, payload_json) VALUES (?, ?, ?)
        `).run(deviceId, receivedAt, serialized);
      }
      this.database.prepare(`
        UPDATE enrollment_requests
        SET status='provisioned'
        WHERE status='approved' AND installation_id = (
          SELECT installation_id FROM devices WHERE id = ?
        )
      `).run(deviceId);
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return receivedAt;
  }

  pruneTelemetry(days) {
    const cutoff = new Date(Date.now() - Math.max(1, Number(days) || 30) * 86400000).toISOString();
    return this.database.prepare("DELETE FROM telemetry WHERE received_at < ?").run(cutoff).changes;
  }

  pruneOperationalData(days) {
    const retentionDays = [30, 90, 365].includes(Number(days)) ? Number(days) : 30;
    const cutoff = new Date(Date.now() - retentionDays * 86400000).toISOString();
    const telemetry = this.database.prepare(
      "DELETE FROM telemetry WHERE received_at < ?"
    ).run(cutoff).changes;
    const commands = this.database.prepare(`
      DELETE FROM commands
      WHERE created_at < ? AND status IN ('completed', 'failed', 'rejected')
    `).run(cutoff).changes;
    const enrollmentRequests = this.database.prepare(`
      DELETE FROM enrollment_requests
      WHERE requested_at < ? AND status IN ('rejected', 'provisioned')
    `).run(cutoff).changes;
    const maintenanceRequests = this.database.prepare(`
      DELETE FROM maintenance_requests
      WHERE requested_at < ? AND status IN ('approved', 'rejected', 'expired')
    `).run(cutoff).changes;
    const maintenancePasswords = this.database.prepare(`
      DELETE FROM maintenance_passwords
      WHERE created_at < ? AND (revoked_at IS NOT NULL OR expires_at < ?)
    `).run(cutoff, new Date().toISOString()).changes;
    return {
      retentionDays,
      cutoff,
      deleted: {
        telemetry,
        commands,
        enrollmentRequests,
        maintenanceRequests,
        maintenancePasswords
      }
    };
  }

  listDevices() {
    return this.database.prepare(`
      SELECT id, installation_id, name, hostname, platform, app_version,
             enrolled_at, last_seen, remote_address, revoked_at, status_json
      FROM devices ORDER BY COALESCE(last_seen, enrolled_at) DESC
    `).all().map(deviceFromRow);
  }

  getDevice(deviceId) {
    const row = this.database.prepare(`
      SELECT id, installation_id, name, hostname, platform, app_version,
             enrolled_at, last_seen, remote_address, revoked_at, status_json
      FROM devices WHERE id = ?
    `).get(deviceId);
    return deviceFromRow(row);
  }

  telemetryHistory(deviceId, limit = 60) {
    const rows = this.database.prepare(`
      SELECT received_at, payload_json FROM telemetry
      WHERE device_id = ? ORDER BY received_at DESC LIMIT ?
    `).all(deviceId, Math.max(1, Math.min(360, Number(limit) || 60)));
    return rows.map(telemetrySnapshot).reverse();
  }

  createCommand(deviceId, type, payload = {}) {
    const device = this.database.prepare(
      "SELECT id FROM devices WHERE id = ? AND revoked_at IS NULL"
    ).get(deviceId);
    if (!device) throw new Error("Managed device was not found");
    const command = {
      id: crypto.randomUUID(),
      deviceId,
      type,
      payload,
      status: "queued",
      createdAt: new Date().toISOString()
    };
    this.database.prepare(`
      INSERT INTO commands (id, device_id, type, payload_json, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(command.id, deviceId, type, JSON.stringify(payload), command.status, command.createdAt);
    return command;
  }

  ensureCommand(deviceId, type, payload = {}) {
    const existing = this.database.prepare(`
      SELECT id, device_id, type, payload_json, status, created_at
      FROM commands
      WHERE device_id = ? AND type = ? AND status IN ('queued', 'delivered', 'running')
      ORDER BY created_at DESC LIMIT 1
    `).get(deviceId, type);
    if (existing) {
      return {
        id: existing.id,
        deviceId: existing.device_id,
        type: existing.type,
        payload: parse(existing.payload_json, {}),
        status: existing.status,
        createdAt: existing.created_at,
        deduplicated: true
      };
    }
    return this.createCommand(deviceId, type, payload);
  }

  pendingCommands(deviceId) {
    const rows = this.database.prepare(`
      SELECT id, type, payload_json, status, created_at
      FROM commands
      WHERE device_id = ? AND status IN ('queued', 'delivered')
      ORDER BY created_at ASC LIMIT 20
    `).all(deviceId);
    const deliveredAt = new Date().toISOString();
    const mark = this.database.prepare(`
      UPDATE commands SET status='delivered', delivered_at=COALESCE(delivered_at, ?)
      WHERE id = ? AND status='queued'
    `);
    for (const row of rows) mark.run(deliveredAt, row.id);
    return rows.map((row) => ({
      id: row.id,
      type: row.type,
      payload: parse(row.payload_json, {}),
      status: row.status,
      createdAt: row.created_at
    }));
  }

  completeCommand(deviceId, commandId, status, result) {
    const allowed = new Set(["running", "completed", "failed", "rejected"]);
    if (!allowed.has(status)) throw new Error("Invalid command result status");
    const completedAt = status === "running" ? null : new Date().toISOString();
    const updated = this.database.prepare(`
      UPDATE commands
      SET status = ?, completed_at = ?, result_json = ?
      WHERE id = ? AND device_id = ?
    `).run(status, completedAt, JSON.stringify(result || {}), commandId, deviceId);
    return updated.changes > 0;
  }

  listCommands(deviceId, limit = 50) {
    return this.database.prepare(`
      SELECT id, type, status, created_at, delivered_at, completed_at, result_json
      FROM commands WHERE device_id = ?
      ORDER BY created_at DESC LIMIT ?
    `).all(deviceId, Math.max(1, Math.min(200, Number(limit) || 50))).map((row) => ({
      id: row.id,
      type: row.type,
      status: row.status,
      createdAt: row.created_at,
      deliveredAt: row.delivered_at,
      completedAt: row.completed_at,
      result: parse(row.result_json, null)
    }));
  }

  revokeDevice(deviceId) {
    const now = new Date().toISOString();
    return this.database.prepare(`
      UPDATE devices SET revoked_at = ?, token_hash = ? WHERE id = ?
    `).run(now, digest(crypto.randomUUID()), deviceId).changes > 0;
  }
}

export function hashAdminPassword(password, salt, iterations = 310000) {
  return crypto.pbkdf2Sync(String(password), Buffer.from(salt, "base64"), iterations, 32, "sha256")
    .toString("base64");
}

export function verifyAdminPassword(password, admin) {
  const actual = Buffer.from(hashAdminPassword(password, admin.salt, admin.iterations), "base64");
  const expected = Buffer.from(admin.passwordHash, "base64");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}
