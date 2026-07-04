import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { HqStore, hashAdminPassword, verifyAdminPassword } from "../src/store.js";
import {
  applyHqSettings,
  buildAdminAlerts,
  createHqServer,
  publicHqSettings
} from "../src/server.js";
import {
  authorizeHqMaintenance,
  downloadHqPackage,
  requestHqMaintenancePassword
} from "../../src/lib/hq-client.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("HQ setup password updater hashes the chosen password without printing it", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sentryloom-hq-password-"));
  const configPath = path.join(root, "config.json");
  const password = "Chosen-Setup-Pässword-42!  ";
  await fs.writeFile(configPath, JSON.stringify({
    schemaVersion: 1,
    admin: {
      iterations: 1000,
      salt: Buffer.alloc(16).toString("base64"),
      passwordHash: Buffer.alloc(32).toString("base64"),
      sessionHours: 8,
      maxLoginAttempts: 5
    }
  }));
  try {
    const result = spawnSync(process.execPath, [
      "--disable-warning=ExperimentalWarning",
      path.join(projectRoot, "server", "src", "set-admin-password.js"),
      configPath
    ], {
      cwd: projectRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD: password
      }
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.includes(password), false);
    const config = JSON.parse(await fs.readFile(configPath, "utf8"));
    assert.equal(verifyAdminPassword(password, config.admin), true);
    assert.equal(verifyAdminPassword("wrong-password", config.admin), false);
    assert.equal(config.admin.sessionHours, 8);
    assert.equal(config.admin.maxLoginAttempts, 5);
    const verification = spawnSync(process.execPath, [
      "--disable-warning=ExperimentalWarning",
      path.join(projectRoot, "server", "src", "verify-admin-password.js"),
      configPath
    ], {
      cwd: projectRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        SENTRYLOOM_HQ_SETUP_ADMIN_PASSWORD: password
      }
    });
    assert.equal(verification.status, 0, verification.stderr);
    assert.equal(verification.stdout.includes(password), false);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("HQ alerts cover stale clients, detections, failures, and failed commands", () => {
  const now = Date.now();
  const deviceId = crypto.randomUUID();
  const alerts = buildAdminAlerts({
    listDevices: () => [{
      id: deviceId,
      name: "Finance-Laptop",
      enrolledAt: new Date(now - 120000).toISOString(),
      lastSeen: new Date(now - 90000).toISOString(),
      status: {
        events: [
          { id: "detect-1", at: new Date(now - 1000).toISOString(), type: "network.detection", message: "Known C2 endpoint" },
          { id: "error-1", at: new Date(now - 2000).toISOString(), type: "monitoring.error", error: "Collector stopped" }
        ]
      }
    }],
    listCommands: () => [{
      id: "command-1",
      type: "scan.quick",
      status: "failed",
      createdAt: new Date(now - 3000).toISOString(),
      completedAt: new Date(now - 2500).toISOString(),
      result: { error: "Scanner unavailable" }
    }]
  }, { now });
  assert.equal(alerts.some((alert) => alert.kind === "availability"), true);
  assert.equal(alerts.some((alert) => alert.kind === "detection"), true);
  assert.equal(alerts.some((alert) => alert.kind === "failure"), true);
  assert.equal(alerts.some((alert) => alert.kind === "command"), true);
});

test("HQ settings expose only discrete safe values and preserve secret admin fields", () => {
  const config = {
    schemaVersion: 1,
    telemetryRetentionDays: 30,
    admin: {
      salt: "secret-salt",
      passwordHash: "secret-hash"
    },
    updates: { autoDeploy: false }
  };
  applyHqSettings(config, {
    telemetryRetentionDays: 365,
    offlineAfterSeconds: 300,
    sessionHours: 8,
    maxLoginAttempts: 5,
    maintenanceMinutes: 30,
    maintenanceUses: 3,
    autoDeploy: true
  });
  assert.equal(config.admin.passwordHash, "secret-hash");
  assert.equal(config.admin.salt, "secret-salt");
  assert.deepEqual(publicHqSettings(config), {
    schemaVersion: 2,
    telemetryRetentionDays: 365,
    offlineAfterSeconds: 300,
    sessionHours: 8,
    maxLoginAttempts: 5,
    maintenanceMinutes: 30,
    maintenanceUses: 3,
    autoDeploy: true,
    allowed: {
      retentionDays: [30, 90, 365],
      offlineAfterSeconds: [60, 300, 900],
      sessionHours: [1, 4, 8, 12, 24],
      maxLoginAttempts: [5, 10, 20],
      maintenanceMinutes: [5, 10, 30, 60],
      maintenanceUses: [1, 3, 10]
    }
  });
});

test("HQ enrolls, authenticates telemetry, and delivers allowlisted commands", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "sentryloom-hq-"));
  const salt = crypto.randomBytes(16).toString("base64");
  const password = "Correct-Horse-HQ-Password";
  const config = {
    hqName: "Test HQ",
    host: "127.0.0.1",
    port: 0,
    databasePath: path.join(root, "hq.sqlite"),
    tls: { fingerprint256: "A".repeat(64) },
    admin: {
      salt,
      iterations: 1000,
      passwordHash: hashAdminPassword(password, salt, 1000)
    },
    discovery: { enabled: false, port: 32110 },
    telemetryRetentionDays: 30,
    updates: {
      directory: path.join(root, "updates"),
      autoDeploy: false
    }
  };
  await fs.mkdir(config.updates.directory, { recursive: true });
  const updatePackage = Buffer.alloc(4096, 7);
  const updateFileName = "SentryLoom-Setup-9.8.7.exe";
  await fs.writeFile(path.join(config.updates.directory, updateFileName), updatePackage);
  await fs.writeFile(path.join(config.updates.directory, "latest.json"), JSON.stringify({
    schemaVersion: 1,
    version: "9.8.7",
    fileName: updateFileName,
    size: updatePackage.length,
    sha256: crypto.createHash("sha256").update(updatePackage).digest("hex"),
    signerThumbprint: "B".repeat(40),
    signerSubject: "CN=NUC7 Studios",
    publishedAt: new Date().toISOString(),
    releaseNotes: "Test update"
  }));
  const store = await new HqStore(config.databasePath).open();
  const hqConfigPath = path.join(root, "config.json");
  await fs.writeFile(hqConfigPath, `${JSON.stringify(config, null, 2)}\n`);
  store.createEnrollmentCode("ENROLL-ONCE", { hours: 1, uses: 1 });
  const hq = await createHqServer(config, { store, httpOnly: true, configPath: hqConfigPath });
  const address = await hq.listen("127.0.0.1", 0);
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const dashboardScript = await fetch(`${origin}/app.js?v=test`);
    assert.equal(dashboardScript.status, 200);
    assert.equal(dashboardScript.headers.get("cache-control"), "no-store");

    const enrollmentResponse = await fetch(`${origin}/api/v1/enroll`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: "ENROLL-ONCE",
        device: {
          installationId: crypto.randomUUID(),
          name: "Finance-Laptop",
          hostname: "FIN-01",
          platform: "win32",
          appVersion: "0.13.0"
        }
      })
    });
    assert.equal(enrollmentResponse.status, 201);
    const enrollment = await enrollmentResponse.json();
    assert.match(enrollment.deviceId, /^[a-f0-9-]{36}$/i);
    assert.ok(enrollment.token.length >= 40);

    const deviceHeaders = {
      "Content-Type": "application/json",
      "X-SentryLoom-Device": enrollment.deviceId,
      Authorization: `Bearer ${enrollment.token}`
    };
    const telemetryResponse = await fetch(`${origin}/api/v1/device/telemetry`, {
      method: "POST",
      headers: deviceHeaders,
      body: JSON.stringify({
        security: { score: 91, quarantineCount: 0 },
        events: [{
          id: "detection-1",
          type: "network.detection",
          at: new Date().toISOString(),
          message: "Known command-and-control endpoint"
        }]
      })
    });
    assert.equal(telemetryResponse.status, 202);
    const telemetryAcknowledgement = await telemetryResponse.json();
    assert.equal(telemetryAcknowledgement.hq.version, "0.4.2");
    assert.equal(
      telemetryAcknowledgement.hq.capabilities.includes("maintenance-authorization-v1"),
      true
    );
    const updateMetadataResponse = await fetch(`${origin}/api/v1/device/update`, {
      headers: deviceHeaders
    });
    const updateMetadata = await updateMetadataResponse.json();
    assert.equal(updateMetadata.update.version, "9.8.7");
    const updatePackageResponse = await fetch(`${origin}/api/v1/device/update/package`, {
      headers: deviceHeaders
    });
    assert.equal(updatePackageResponse.status, 200);
    assert.equal(
      crypto.createHash("sha256").update(Buffer.from(await updatePackageResponse.arrayBuffer())).digest("hex"),
      updateMetadata.update.sha256.toLowerCase()
    );
    const downloadedUpdate = path.join(root, "downloaded-update.exe");
    const streamed = await downloadHqPackage({
      serverUrl: origin,
      fingerprint256: "",
      deviceId: enrollment.deviceId,
      token: enrollment.token
    }, "/api/v1/device/update/package", downloadedUpdate, {
      ...updateMetadata.update,
      sha256: updateMetadata.update.sha256.toUpperCase()
    }, { allowHttp: true });
    assert.equal(streamed.bytes, updatePackage.length);
    assert.deepEqual(await fs.readFile(downloadedUpdate), updatePackage);

    const loginResponse = await fetch(`${origin}/api/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password })
    });
    assert.equal(loginResponse.status, 200);
    const login = await loginResponse.json();
    const cookie = loginResponse.headers.get("set-cookie").split(";")[0];
    const adminHeaders = {
      Cookie: cookie,
      "Content-Type": "application/json",
      "X-SentryLoom-CSRF": login.csrf
    };

    const settingsResponse = await fetch(`${origin}/api/admin/settings`, {
      headers: adminHeaders
    });
    assert.equal(settingsResponse.status, 200);
    assert.equal((await settingsResponse.json()).telemetryRetentionDays, 30);
    const updatedSettingsResponse = await fetch(`${origin}/api/admin/settings`, {
      method: "PATCH",
      headers: adminHeaders,
      body: JSON.stringify({
        telemetryRetentionDays: 90,
        offlineAfterSeconds: 300,
        sessionHours: 8,
        maxLoginAttempts: 5,
        maintenanceMinutes: 30,
        maintenanceUses: 3,
        autoDeploy: true
      })
    });
    assert.equal(updatedSettingsResponse.status, 200);
    const updatedSettings = await updatedSettingsResponse.json();
    assert.equal(updatedSettings.settings.telemetryRetentionDays, 90);
    assert.equal(updatedSettings.settings.autoDeploy, true);
    const persistedSettings = JSON.parse(await fs.readFile(hqConfigPath, "utf8"));
    assert.equal(persistedSettings.telemetryRetentionDays, 90);
    assert.equal(persistedSettings.admin.passwordHash, config.admin.passwordHash);

    const generatedPasswordResponse = await fetch(`${origin}/api/admin/maintenance/passwords`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({ minutes: 5, uses: 1 })
    });
    assert.equal(generatedPasswordResponse.status, 201);
    const generatedPassword = await generatedPasswordResponse.json();
    assert.match(generatedPassword.password, /^SL-[A-Za-z0-9_-]{32}$/);
    const maintenanceCredentials = {
      serverUrl: origin,
      fingerprint256: "",
      deviceId: enrollment.deviceId,
      token: enrollment.token
    };
    assert.equal((await authorizeHqMaintenance(
      maintenanceCredentials,
      generatedPassword.password,
      "critical-settings",
      { allowHttp: true }
    )).authorized, true);
    await assert.rejects(
      authorizeHqMaintenance(
        maintenanceCredentials,
        generatedPassword.password,
        "critical-settings",
        { allowHttp: true }
      ),
      /invalid, expired, used, or revoked/
    );

    const requestedPasswordPromise = requestHqMaintenancePassword(
      maintenanceCredentials,
      {
        allowHttp: true,
        action: "uninstall",
        reason: "Test maintenance approval"
      }
    );
    let maintenanceRequest;
    for (let attempt = 0; attempt < 30 && !maintenanceRequest; attempt += 1) {
      maintenanceRequest = store.listMaintenanceRequests()
        .find((item) => item.status === "pending");
      if (!maintenanceRequest) await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.ok(maintenanceRequest);
    const approveMaintenanceResponse = await fetch(
      `${origin}/api/admin/maintenance/requests/${maintenanceRequest.id}/approve`,
      { method: "POST", headers: adminHeaders, body: "{}" }
    );
    assert.equal(approveMaintenanceResponse.status, 200);
    const requestedPassword = await requestedPasswordPromise;
    assert.match(requestedPassword.password, /^SL-[A-Za-z0-9_-]{32}$/);
    assert.equal((await authorizeHqMaintenance(
      maintenanceCredentials,
      requestedPassword.password,
      "uninstall",
      { allowHttp: true }
    )).authorized, true);

    const automaticRequestResponse = await fetch(`${origin}/api/v1/enrollment-requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device: {
          installationId: crypto.randomUUID(),
          name: "Operations-Desktop",
          hostname: "OPS-01",
          platform: "win32",
          appVersion: "0.14.0"
        }
      })
    });
    assert.equal(automaticRequestResponse.status, 202);
    const automaticRequest = await automaticRequestResponse.json();
    const pendingResponse = await fetch(
      `${origin}/api/v1/enrollment-requests/${automaticRequest.requestId}`,
      { headers: { Authorization: `Enrollment ${automaticRequest.requestSecret}` } }
    );
    assert.equal((await pendingResponse.json()).status, "pending");
    const approvalResponse = await fetch(
      `${origin}/api/admin/enrollment-requests/${automaticRequest.requestId}/approve`,
      { method: "POST", headers: adminHeaders, body: "{}" }
    );
    assert.equal(approvalResponse.status, 200);
    const approvedResponse = await fetch(
      `${origin}/api/v1/enrollment-requests/${automaticRequest.requestId}`,
      { headers: { Authorization: `Enrollment ${automaticRequest.requestSecret}` } }
    );
    const approved = await approvedResponse.json();
    assert.equal(approved.status, "approved");
    assert.ok(approved.token.length >= 40);

    const rejectedRequestResponse = await fetch(`${origin}/api/v1/enrollment-requests`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        device: {
          installationId: crypto.randomUUID(),
          name: "Unknown-Device",
          hostname: "UNKNOWN-01",
          platform: "win32",
          appVersion: "0.14.0"
        }
      })
    });
    const rejectedRequest = await rejectedRequestResponse.json();
    await fetch(
      `${origin}/api/admin/enrollment-requests/${rejectedRequest.requestId}/reject`,
      { method: "POST", headers: adminHeaders, body: "{}" }
    );
    const rejectedResponse = await fetch(
      `${origin}/api/v1/enrollment-requests/${rejectedRequest.requestId}`,
      { headers: { Authorization: `Enrollment ${rejectedRequest.requestSecret}` } }
    );
    assert.equal((await rejectedResponse.json()).status, "rejected");

    const devicesResponse = await fetch(`${origin}/api/admin/devices`, {
      headers: { Cookie: cookie }
    });
    const devices = await devicesResponse.json();
    assert.equal(
      devices.find((device) => device.id === enrollment.deviceId).status.security.score,
      91
    );
    const alertsResponse = await fetch(`${origin}/api/admin/alerts`, {
      headers: { Cookie: cookie }
    });
    const alerts = await alertsResponse.json();
    assert.equal(alertsResponse.status, 200);
    assert.equal(alerts.alerts.some((alert) =>
      alert.deviceId === enrollment.deviceId && alert.kind === "detection"
    ), true);
    const detailsResponse = await fetch(
      `${origin}/api/admin/devices/${enrollment.deviceId}/details`,
      { headers: { Cookie: cookie } }
    );
    assert.equal(detailsResponse.status, 200);
    const details = await detailsResponse.json();
    assert.equal(details.device.status.security.score, 91);
    assert.equal(details.telemetry.at(-1).score, 91);
    assert.deepEqual(details.commands, []);

    const commandResponse = await fetch(
      `${origin}/api/admin/devices/${enrollment.deviceId}/commands`,
      {
        method: "POST",
        headers: adminHeaders,
        body: JSON.stringify({ type: "scan.quick", payload: {} })
      }
    );
    assert.equal(commandResponse.status, 201);
    const command = await commandResponse.json();

    const pendingCommandsResponse = await fetch(`${origin}/api/v1/device/commands`, {
      headers: deviceHeaders
    });
    const pendingCommands = await pendingCommandsResponse.json();
    assert.equal(pendingCommands.commands[0].type, "scan.quick");

    const resultResponse = await fetch(
      `${origin}/api/v1/device/commands/${command.id}/result`,
      {
        method: "POST",
        headers: deviceHeaders,
        body: JSON.stringify({ status: "completed", result: { detections: 0 } })
      }
    );
    assert.equal(resultResponse.status, 200);

    const historyResponse = await fetch(
      `${origin}/api/admin/devices/${enrollment.deviceId}/commands`,
      { headers: { Cookie: cookie } }
    );
    const history = await historyResponse.json();
    assert.equal(history[0].status, "completed");

    const updateStatusResponse = await fetch(`${origin}/api/admin/update`, {
      headers: { Cookie: cookie }
    });
    assert.equal((await updateStatusResponse.json()).update.version, "9.8.7");
    const deployResponse = await fetch(`${origin}/api/admin/update/deploy`, {
      method: "POST",
      headers: adminHeaders,
      body: "{}"
    });
    const deployment = await deployResponse.json();
    assert.equal(deployResponse.status, 202);
    assert.equal(deployment.queued, 2);
    const updateCommandsResponse = await fetch(`${origin}/api/v1/device/commands`, {
      headers: deviceHeaders
    });
    const updateCommands = await updateCommandsResponse.json();
    assert.equal(updateCommands.commands.some((item) => item.type === "client.update"), true);
  } finally {
    await hq.close();
    store.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});
