let csrf = "";
let devices = [];
let enrollmentRequests = [];
let updateState = { update: null, autoDeploy: false, staging: null };
let threatCredentialState = { abuseChConfigured: false, revision: null, updatedAt: null };
let maintenanceState = { passwords: [], requests: [] };
let serverSettings = null;
let serverSettingsDirty = false;
let serverSettingsRendered = false;
let activeAlerts = [];
let knownAlertIds = null;
let knownMaintenanceRequestIds = null;
let selectedDeviceId = null;
let pollTimer = null;
let detailRequestActive = false;
let serverReachable = true;
const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function toast(message) {
  $("#toast").textContent = message;
  $("#toast").classList.add("show");
  setTimeout(() => $("#toast").classList.remove("show"), 3000);
}

function setServerAvailability(available, error = "") {
  const state = document.querySelector(".server-state");
  state.classList.toggle("offline", !available);
  state.innerHTML = `<i></i> ${available ? "Server online" : "Server connection lost"}`;
  if (available && !serverReachable) toast("HQ dashboard connection restored");
  if (!available && serverReachable) toast(error || "HQ dashboard connection failed");
  serverReachable = available;
}

function desktopAlert(alert) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  try {
    new Notification(alert.title, {
      body: `${alert.deviceName || "Endpoint"} · ${alert.message}`,
      tag: alert.id
    });
  } catch {}
}

async function api(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-SentryLoom-CSRF"] = csrf;
  const response = await fetch(url, { ...options, headers });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function relative(value) {
  if (!value) return "never";
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function timeUntil(value) {
  const seconds = Math.max(0, Math.ceil((new Date(value).getTime() - Date.now()) / 1000));
  if (seconds < 60) return `${seconds}s`;
  return `${Math.ceil(seconds / 60)}m`;
}

function dateTime(value) {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function formatBytes(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "Not reported";
  if (number < 1024) return `${number} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = number;
  let unit = -1;
  do { size /= 1024; unit += 1; } while (size >= 1024 && unit < units.length - 1);
  return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function humanLabel(value) {
  return String(value || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[._-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatScalar(value, key = "") {
  if (value === null || value === undefined || value === "") return "Not reported";
  if (typeof value === "boolean") return value ? "Enabled / yes" : "Disabled / no";
  if (/bytes$/i.test(key) && Number.isFinite(Number(value))) return formatBytes(value);
  if (/(?:at|time|date)$/i.test(key) && typeof value === "string" && !Number.isNaN(new Date(value).getTime())) {
    return dateTime(value);
  }
  if (typeof value === "number") return value.toLocaleString();
  return String(value);
}

function flattenScalars(value, prefix = "", output = [], depth = 0) {
  if (output.length >= 120 || depth > 5) return output;
  if (value === null || value === undefined || typeof value !== "object") {
    output.push([prefix || "value", value]);
    return output;
  }
  if (Array.isArray(value)) {
    if (!value.length) output.push([prefix || "items", "None"]);
    else if (value.every((item) => item === null || typeof item !== "object")) {
      output.push([prefix || "items", value.join(", ")]);
    } else {
      output.push([`${prefix || "items"} count`, value.length]);
    }
    return output;
  }
  for (const [key, item] of Object.entries(value)) {
    const next = prefix ? `${prefix}.${key}` : key;
    flattenScalars(item, next, output, depth + 1);
  }
  return output;
}

function propertyGrid(value, emptyText = "No telemetry reported for this component.") {
  const entries = flattenScalars(value);
  if (!entries.length) return `<div class="detail-empty">${escapeHtml(emptyText)}</div>`;
  return `<dl class="property-grid">${entries.map(([key, item]) => {
    const stateClass = typeof item === "boolean" ? (item ? "positive" : "muted") : "";
    return `<div><dt>${escapeHtml(humanLabel(key))}</dt><dd class="${stateClass}">${escapeHtml(formatScalar(item, key))}</dd></div>`;
  }).join("")}</dl>`;
}

function detailSection(kicker, title, content, options = {}) {
  return `<section class="detail-section ${options.wide ? "wide" : ""}">
    <div class="section-heading"><div><p>${escapeHtml(kicker)}</p><h3>${escapeHtml(title)}</h3></div>${options.note ? `<span>${escapeHtml(options.note)}</span>` : ""}</div>
    ${content}
  </section>`;
}

function metric(label, value, note = "", tone = "") {
  return `<article class="detail-metric ${tone}"><small>${escapeHtml(label)}</small><strong>${escapeHtml(value)}</strong>${note ? `<span>${escapeHtml(note)}</span>` : ""}</article>`;
}

function sparkline(values, color = "#167568") {
  const clean = values.map(Number).filter(Number.isFinite);
  if (clean.length < 2) return `<div class="chart-empty">Trend begins after two samples</div>`;
  const minimum = Math.min(...clean);
  const maximum = Math.max(...clean);
  const spread = maximum - minimum || 1;
  const points = clean.map((value, index) => {
    const x = (index / (clean.length - 1)) * 100;
    const y = 34 - ((value - minimum) / spread) * 28;
    return `${x.toFixed(2)},${y.toFixed(2)}`;
  }).join(" ");
  return `<svg class="sparkline" viewBox="0 0 100 38" preserveAspectRatio="none" role="img" aria-label="Recent telemetry trend">
    <polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.8" vector-effect="non-scaling-stroke"></polyline>
  </svg>`;
}

function renderIssues(issues = []) {
  if (!issues.length) return `<div class="good-state"><i>✓</i><div><strong>No posture issues reported</strong><span>All evaluated controls meet the current policy.</span></div></div>`;
  return `<div class="issue-list">${issues.map((issue) => `<article class="issue severity-${escapeHtml(issue.severity || "info")}">
    <span>${escapeHtml((issue.severity || "info").toUpperCase())}</span>
    <div><strong>${escapeHtml(issue.title || issue.id)}</strong><small>${escapeHtml(issue.detail || issue.action || "Administrator attention recommended")}</small></div>
  </article>`).join("")}</div>`;
}

function renderScanHistory(scans = []) {
  if (!scans.length) return `<div class="detail-empty">No completed scans have been reported.</div>`;
  return `<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Scan</th><th>Completed</th><th>Files</th><th>Detections</th><th>Errors</th></tr></thead><tbody>
    ${scans.slice(0, 20).map((scan) => `<tr><td><strong>${escapeHtml(humanLabel(scan.type || "scan"))}</strong><small>${escapeHtml(scan.target || "Multiple targets")}</small></td><td>${escapeHtml(relative(scan.endedAt))}</td><td>${escapeHtml(formatScalar(scan.scanned ?? 0))}</td><td class="${scan.detections ? "danger-text" : ""}">${escapeHtml(formatScalar(scan.detections ?? 0))}</td><td>${escapeHtml(formatScalar(scan.errorCount ?? 0))}</td></tr>`).join("")}
  </tbody></table></div>`;
}

function renderQuarantine(items = []) {
  if (!items.length) return `<div class="detail-empty">No quarantine records reported by this endpoint.</div>`;
  return `<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Original file</th><th>Finding</th><th>Size</th><th>Quarantined</th><th>State</th></tr></thead><tbody>
    ${items.map((item) => `<tr><td><strong class="path-value">${escapeHtml(item.originalPath || "Unknown path")}</strong><small>${escapeHtml(item.sha256 || "Hash unavailable")}</small></td><td>${escapeHtml((item.findings || []).map((finding) => finding.name || finding.id).filter(Boolean).join(", ") || "Unclassified")}</td><td>${escapeHtml(formatBytes(item.originalSize))}</td><td>${escapeHtml(relative(item.quarantinedAt))}</td><td><span class="table-state">${escapeHtml(humanLabel(item.state || "unknown"))}</span></td></tr>`).join("")}
  </tbody></table></div>`;
}

function renderTimeline(events = [], audit = []) {
  const combined = [
    ...events.map((event) => ({ at: event.at, type: event.type, detail: event.message || event.error || event.path || event.address })),
    ...audit.map((entry) => ({ at: entry.at || entry.timestamp, type: entry.event || entry.type, detail: entry.details?.message }))
  ].filter((item) => item.at || item.type).sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0)).slice(0, 60);
  if (!combined.length) return `<div class="detail-empty">No recent security events reported.</div>`;
  return `<div class="event-timeline">${combined.map((event) => `<article><i></i><div><strong>${escapeHtml(humanLabel(event.type || "security event"))}</strong>${event.detail ? `<small>${escapeHtml(event.detail)}</small>` : ""}</div><time title="${escapeHtml(dateTime(event.at))}">${escapeHtml(relative(event.at))}</time></article>`).join("")}</div>`;
}

function renderCommands(commands = []) {
  $("#command-history").innerHTML = commands.length ? commands.map((command) => `
    <div class="command">
      <div><span>${escapeHtml(humanLabel(command.type))}</span><small>${escapeHtml(dateTime(command.createdAt))}${command.result ? ` · ${escapeHtml(JSON.stringify(command.result))}` : ""}</small></div>
      <b class="command-${escapeHtml(command.status)}">${escapeHtml(humanLabel(command.status))}</b>
    </div>
  `).join("") : `<div class="command"><span>No remote actions have been sent to this endpoint.</span></div>`;
}

function renderAlerts(payload) {
  activeAlerts = payload.alerts || [];
  const currentIds = new Set(activeAlerts.map((alert) => alert.id));
  if (knownAlertIds) {
    const fresh = activeAlerts.filter((alert) => !knownAlertIds.has(alert.id));
    if (fresh.length) {
      const alert = fresh[0];
      toast(`${alert.title}: ${alert.message}`);
      desktopAlert(alert);
    }
  }
  knownAlertIds = currentIds;
  $("#alert-count").textContent = activeAlerts.length;
  $("#alert-empty").classList.toggle("hidden", Boolean(activeAlerts.length));
  $("#alert-updated").textContent = activeAlerts.length
    ? `${activeAlerts.length} active · checked ${relative(payload.generatedAt)}`
    : `No active alerts · checked ${relative(payload.generatedAt)}`;
  $("#alerts").innerHTML = activeAlerts.map((alert) => `
    <article class="alert ${escapeHtml(alert.severity)}">
      <i></i>
      <div><strong>${escapeHtml(alert.title)}</strong><small>${escapeHtml(humanLabel(alert.kind))}</small></div>
      <span>${escapeHtml(alert.message)}</span>
      <time title="${escapeHtml(dateTime(alert.at))}">${escapeHtml(relative(alert.at))}</time>
    </article>
  `).join("");
}

function renderDeviceDetails(result) {
  const { device, telemetry = [], commands = [] } = result;
  const status = device.status || {};
  const security = status.security || {};
  const protection = status.protection || {};
  const scan = status.scan || {};
  const current = Date.now() - new Date(device.lastSeen || 0) < 60000;
  const progressPercent = scan.progress?.total
    ? Math.min(100, Math.round((scan.progress.completed / scan.progress.total) * 100))
    : 0;

  $("#device-name").textContent = device.name;
  $("#device-meta").textContent = `${device.hostname} · ${device.platform} · Client ${device.appVersion} · ${device.remoteAddress || "Address unavailable"}`;
  $("#device-live").classList.toggle("offline", !current);
  $("#device-live").innerHTML = `<i></i><span>${current ? `Live · ${relative(device.lastSeen)}` : `Offline · ${relative(device.lastSeen)}`}</span>`;

  const metrics = `<div class="detail-metrics">
    ${metric("SECURITY SCORE", security.score ?? "—", security.grade ? `Grade ${security.grade}` : "Not evaluated", Number(security.score) < 70 ? "warning" : "secure")}
    ${metric("PROTECTION", humanLabel(security.state || (protection.running ? "active" : "unknown")), protection.elevated ? "Elevated service" : "Standard user context")}
    ${metric("QUARANTINED", security.quarantineCount ?? 0, `${(security.issues || []).length} posture issue(s)`, security.quarantineCount ? "warning" : "")}
    ${metric("LAST TELEMETRY", relative(device.lastSeen), dateTime(device.lastSeen))}
  </div>`;

  const trend = `<div class="trend-grid">
    <article><div><strong>Security score</strong><span>${telemetry.at(-1)?.score ?? "—"} / 100</span></div>${sparkline(telemetry.map((item) => item.score))}</article>
    <article><div><strong>Memory footprint</strong><span>${formatBytes(telemetry.at(-1)?.rssBytes)}</span></div>${sparkline(telemetry.map((item) => item.rssBytes), "#4d6f91")}</article>
    <article><div><strong>Files inspected</strong><span>${formatScalar(telemetry.at(-1)?.filesInspected ?? "—")}</span></div>${sparkline(telemetry.map((item) => item.filesInspected), "#8b6d3f")}</article>
  </div>`;

  const activeScan = scan.active
    ? `<div class="active-scan"><div><strong>${escapeHtml(humanLabel(scan.active.type || "scan"))} in progress</strong><span>${escapeHtml(formatScalar(scan.progress?.completed ?? 0))} of ${escapeHtml(formatScalar(scan.progress?.total ?? "unknown"))} files · ${escapeHtml(humanLabel(scan.progress?.phase || scan.active.status || "running"))}</span></div><b>${progressPercent}%</b><div class="progress-track"><i style="width:${progressPercent}%"></i></div></div>`
    : `<div class="good-state compact"><i>✓</i><div><strong>No scan currently running</strong><span>Last completed ${escapeHtml(relative(scan.last?.endedAt))}</span></div></div>`;

  const protectionSections = [
    detailSection("REAL-TIME", "File and Downloads protection", propertyGrid(protection.file)),
    detailSection("NETWORK", "Web, DNS and connection monitoring", propertyGrid(protection.network)),
    detailSection("BEHAVIOR", "Process, ransomware and system monitors", propertyGrid(protection.advanced)),
    detailSection("ENFORCEMENT", "Firewall protection", propertyGrid(protection.firewallEnforcement)),
    detailSection("CONTROLS", "DNS, firewall and USB policy", propertyGrid(status.controls)),
    detailSection("INTELLIGENCE", "Signatures and update health", propertyGrid(status.signatures)),
    detailSection("CLIENT", "Application update state", propertyGrid(status.clientUpdate))
  ].join("");

  $("#device-details").innerHTML = `
    ${metrics}
    ${trend}
    <div class="details-layout">
      ${detailSection("POSTURE", "Recommended attention", renderIssues(security.issues), { wide: true })}
      ${protectionSections}
      ${detailSection("SCANNING", "Current scan activity", activeScan)}
      ${detailSection("RUNTIME", "Client process health", propertyGrid(status.runtime))}
      ${detailSection("HISTORY", "Completed scans", renderScanHistory(scan.history), { wide: true, note: `${(scan.history || []).length} recent records` })}
      ${detailSection("CONTAINMENT", "Quarantine inventory", renderQuarantine(status.quarantine), { wide: true, note: "Metadata only—file contents never leave the endpoint" })}
      ${detailSection("ACTIVITY", "Security and audit timeline", renderTimeline(status.events, status.audit), { wide: true })}
      ${detailSection("POLICY", "Effective endpoint configuration", propertyGrid(status.policy), { wide: true })}
      ${detailSection("DIAGNOSTICS", "Complete sanitized telemetry", `<details class="raw-telemetry"><summary>View every field received from this endpoint</summary><pre>${escapeHtml(JSON.stringify(status, null, 2))}</pre></details>`, { wide: true, note: `Schema ${status.schemaVersion || 1}` })}
    </div>`;
  renderCommands(commands);
}

function renderUpdateRelease() {
  const update = updateState.update;
  $("#update-policy").textContent = updateState.autoDeploy
    ? "Automatic deployment enabled"
    : "Administrator-triggered deployment";
  if (!update) {
    $("#update-release").innerHTML = `
      <div class="update-copy"><strong>No signed client update published</strong><span>Run Publish-SentryLoomUpdate.ps1 on the HQ server to publish a signed Setup package.</span></div>
      <button class="primary" id="deploy-update" disabled>Deploy update</button>`;
    return;
  }
  $("#update-release").innerHTML = `
    <div class="update-version"><small>AVAILABLE VERSION</small><strong>${escapeHtml(update.version)}</strong></div>
    <div class="update-copy"><strong>${escapeHtml(update.signerSubject || "Verified publisher")}</strong><span>Published ${escapeHtml(relative(update.publishedAt))} · ${escapeHtml(formatBytes(update.size))} · SHA-256 ${escapeHtml(update.sha256.slice(0, 12))}…</span></div>
    <button class="primary" id="deploy-update">Deploy to eligible devices</button>`;
}

function renderFleet() {
  const online = devices.filter((device) => Date.now() - new Date(device.lastSeen || 0) < 60000);
  const pending = enrollmentRequests.filter((request) => request.status === "pending");
  $("#device-count").textContent = devices.length;
  $("#online-count").textContent = online.length;
  $("#pending-count").textContent = pending.length;
  $("#approval-empty").classList.toggle("hidden", Boolean(pending.length));
  $("#approvals").innerHTML = pending.map((request) => `
    <article class="approval">
      <div><strong>${escapeHtml(request.device.name)}</strong><small>${escapeHtml(request.device.hostname)} · ${escapeHtml(request.device.appVersion)}</small></div>
      <span>${escapeHtml(request.remoteAddress || "Unknown address")}</span>
      <span><small>${relative(request.requestedAt)}</small></span>
      <div class="approval-actions">
        <button class="approve" data-approve="${request.id}">Approve</button>
        <button class="reject" data-reject="${request.id}">Reject</button>
      </div>
    </article>
  `).join("");
  $("#empty").classList.toggle("hidden", Boolean(devices.length));
  $("#devices").innerHTML = devices.map((device) => {
    const current = Date.now() - new Date(device.lastSeen || 0) < 60000;
    const score = device.status?.security?.score;
    const threats = device.status?.security?.quarantineCount ?? 0;
    const scanActive = Boolean(device.status?.scan?.active);
    return `<article class="device">
      <div><strong>${escapeHtml(device.name)}</strong><small>${escapeHtml(device.hostname)} · ${escapeHtml(device.appVersion)}${scanActive ? " · Scan running" : ""}</small></div>
      <span class="state ${current ? "" : "offline"}">${current ? "ONLINE" : "OFFLINE"}</span>
      <span class="score">${score ?? "—"} / 100</span>
      <span><b>${threats}</b><small>quarantined</small></span>
      <button data-device="${device.id}">Open endpoint</button>
    </article>`;
  }).join("");
  $("#updated").textContent = `Live telemetry · ${new Date().toLocaleTimeString()}`;
  renderUpdateRelease();
}

function renderMaintenance() {
  const activePasswords = (maintenanceState.passwords || []).filter((item) => item.active);
  const pendingRequests = (maintenanceState.requests || []).filter((item) => item.status === "pending");
  const currentRequestIds = new Set(pendingRequests.map((item) => item.id));
  if (knownMaintenanceRequestIds) {
    const fresh = pendingRequests.find((item) => !knownMaintenanceRequestIds.has(item.id));
    if (fresh) {
      toast(`${fresh.deviceName} is requesting immediate maintenance approval`);
      desktopAlert({
        id: `maintenance:${fresh.id}`,
        title: "Maintenance approval requested",
        deviceName: fresh.deviceName,
        message: "Approve or reject within 20 seconds"
      });
    }
  }
  knownMaintenanceRequestIds = currentRequestIds;
  $("#maintenance-password-empty").classList.toggle("hidden", Boolean(activePasswords.length));
  $("#maintenance-passwords").innerHTML = activePasswords.map((item) => `
    <article class="maintenance-row">
      <div><strong>${escapeHtml(item.source === "client-request" ? "Endpoint-requested password" : "Administrator password")}</strong><small>${escapeHtml(item.usesRemaining)} use(s) remaining · expires in ${escapeHtml(timeUntil(item.expiresAt))}${item.deviceId ? " · device scoped" : " · all managed devices"}</small></div>
      <button class="danger" data-revoke-maintenance="${item.id}">Revoke</button>
    </article>
  `).join("");
  $("#maintenance-request-empty").classList.toggle("hidden", Boolean(pendingRequests.length));
  $("#maintenance-requests").innerHTML = pendingRequests.map((item) => {
    const seconds = Math.max(0, Math.ceil((new Date(item.expiresAt).getTime() - Date.now()) / 1000));
    return `<article class="maintenance-row">
      <div><strong>${escapeHtml(item.deviceName)}</strong><small>${escapeHtml(humanLabel(item.action))} · ${seconds}s remaining${item.reason ? ` · ${escapeHtml(item.reason)}` : ""}</small></div>
      <div class="maintenance-actions"><button data-approve-maintenance="${item.id}">Approve</button><button class="danger" data-reject-maintenance="${item.id}">Reject</button></div>
    </article>`;
  }).join("");
}

function renderServerSettings(settings) {
  serverSettings = settings;
  if (serverSettingsDirty) return;
  $("#setting-retention-days").value = String(settings.telemetryRetentionDays);
  $("#setting-offline-seconds").value = String(settings.offlineAfterSeconds);
  $("#setting-session-hours").value = String(settings.sessionHours);
  $("#setting-login-attempts").value = String(settings.maxLoginAttempts);
  $("#setting-maintenance-minutes").value = String(settings.maintenanceMinutes);
  $("#setting-maintenance-uses").value = String(settings.maintenanceUses);
  $("#setting-staging-directory").value = settings.stagingDirectory || "";
  $("#setting-auto-deploy").checked = Boolean(settings.autoDeploy);
  const staging = updateState.staging;
  const stagingState = $("#update-staging-state");
  stagingState.className = staging?.accessible ? "ready" : staging ? "error" : "";
  stagingState.textContent = staging?.accessible
    ? staging.latest
      ? `Accessible to HQ · newest file: ${staging.latest.fileName}`
      : "Accessible to HQ · no SentryLoom Setup file found"
    : staging?.error ||
      "HQ checks this folder using its SYSTEM service identity. Use a UNC path for network shares.";
  if (!serverSettingsRendered) {
    $("#maintenance-minutes").value = String(settings.maintenanceMinutes);
    $("#maintenance-uses").value = String(settings.maintenanceUses);
  }
  serverSettingsRendered = true;
}

function renderThreatCredentialState() {
  const configured = Boolean(threatCredentialState.abuseChConfigured);
  $("#server-abuse-key-state").textContent = configured
    ? `Configured securely with Windows DPAPI · updated ${relative(threatCredentialState.updatedAt)} · clients authenticate through HQ`
    : "Not configured. Managed clients cannot update authenticated abuse.ch feeds.";
  $("#remove-server-abuse-key").disabled = !configured;
}

async function refreshDeviceDetails(force = false) {
  if (!selectedDeviceId || detailRequestActive) return;
  if (!force && !$("#device-dialog").open) return;
  detailRequestActive = true;
  try {
    renderDeviceDetails(await api(`/api/admin/devices/${selectedDeviceId}/details?limit=60`));
  } finally {
    detailRequestActive = false;
  }
}

async function refresh() {
  let alertState;
  [devices, enrollmentRequests, updateState, alertState, maintenanceState, serverSettings, threatCredentialState] = await Promise.all([
    api("/api/admin/devices"),
    api("/api/admin/enrollment-requests"),
    api("/api/admin/update"),
    api("/api/admin/alerts"),
    api("/api/admin/maintenance"),
    api("/api/admin/settings"),
    api("/api/admin/threat-credentials")
  ]);
  renderFleet();
  renderAlerts(alertState);
  renderMaintenance();
  renderServerSettings(serverSettings);
  renderThreatCredentialState();
  await refreshDeviceDetails();
  setServerAvailability(true);
}

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ password: $("#password").value })
    });
    csrf = result.csrf;
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission().catch(() => {});
    }
    $("#login").classList.add("hidden");
    $("#shell").classList.remove("hidden");
    await refresh();
    pollTimer = setInterval(() => refresh().catch((error) => {
      setServerAvailability(false, error.message);
    }), 2000);
  } catch (error) {
    $("#login-error").textContent = error.message;
  }
});

$("#save-server-abuse-key").addEventListener("click", async () => {
  const button = $("#save-server-abuse-key");
  const input = $("#server-abuse-auth-key");
  const key = input.value.trim();
  if (!key) {
    toast("Enter the abuse.ch Auth-Key");
    return;
  }
  try {
    button.disabled = true;
    threatCredentialState = await api("/api/admin/threat-credentials", {
      method: "PUT",
      body: JSON.stringify({ abuseChAuthKey: key })
    });
    input.value = "";
    renderThreatCredentialState();
    toast("Server abuse.ch Auth-Key protected with Windows DPAPI");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#remove-server-abuse-key").addEventListener("click", async () => {
  if (!window.confirm(
    "Remove the server abuse.ch Auth-Key? Managed clients will immediately lose authenticated feed access."
  )) return;
  const button = $("#remove-server-abuse-key");
  try {
    button.disabled = true;
    threatCredentialState = await api("/api/admin/threat-credentials", {
      method: "DELETE",
      body: "{}"
    });
    renderThreatCredentialState();
    toast("Server abuse.ch Auth-Key removed");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#refresh-fleet").addEventListener("click", () => refresh().catch((error) => toast(error.message)));

$("#update-release").addEventListener("click", async (event) => {
  const button = event.target.closest("#deploy-update");
  if (!button || button.disabled || !updateState.update) return;
  if (!window.confirm(`Deploy SentryLoom ${updateState.update.version} to every eligible managed endpoint? Clients will verify the signed package and update silently.`)) return;
  try {
    button.disabled = true;
    const result = await api("/api/admin/update/deploy", { method: "POST", body: "{}" });
    toast(`Update ${result.version}: ${result.queued} queued, ${result.alreadyQueued} already pending`);
    await refresh();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#server-settings-form").addEventListener("change", (event) => {
  if (event.target.closest(".server-secret-row")) return;
  serverSettingsDirty = true;
  $("#server-settings-state").textContent = "Unsaved changes";
});

$("#save-server-settings").addEventListener("click", async () => {
  const button = $("#save-server-settings");
  try {
    button.disabled = true;
    const result = await api("/api/admin/settings", {
      method: "PATCH",
      body: JSON.stringify({
        telemetryRetentionDays: Number($("#setting-retention-days").value),
        offlineAfterSeconds: Number($("#setting-offline-seconds").value),
        sessionHours: Number($("#setting-session-hours").value),
        maxLoginAttempts: Number($("#setting-login-attempts").value),
        maintenanceMinutes: Number($("#setting-maintenance-minutes").value),
        maintenanceUses: Number($("#setting-maintenance-uses").value),
        stagingDirectory: $("#setting-staging-directory").value.trim(),
        autoDeploy: $("#setting-auto-deploy").checked
      })
    });
    serverSettingsDirty = false;
    serverSettingsRendered = false;
    renderServerSettings(result.settings);
    updateState.autoDeploy = result.settings.autoDeploy;
    const deleted = Object.values(result.pruning?.deleted || {})
      .reduce((sum, value) => sum + Number(value || 0), 0);
    $("#server-settings-state").textContent =
      `Saved · ${result.settings.telemetryRetentionDays}-day retention · ${deleted} expired record(s) removed`;
    toast("HQ server settings saved");
    renderUpdateRelease();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#publish-staged-update").addEventListener("click", async () => {
  const button = $("#publish-staged-update");
  if (serverSettingsDirty) {
    toast("Save the staging-folder setting before publishing");
    return;
  }
  if (!window.confirm(
    "Validate the newest staged SentryLoom Setup, publish it, and queue it for every eligible managed endpoint?"
  )) return;
  try {
    button.disabled = true;
    const result = await api("/api/admin/update/publish-latest", {
      method: "POST",
      body: "{}"
    });
    toast(
      `Published ${result.update.version}: ${result.deployment.queued} queued, ` +
      `${result.deployment.alreadyQueued} already pending`
    );
    await refresh();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#generate-maintenance").addEventListener("click", async () => {
  const button = $("#generate-maintenance");
  try {
    button.disabled = true;
    const result = await api("/api/admin/maintenance/passwords", {
      method: "POST",
      body: JSON.stringify({
        minutes: Number($("#maintenance-minutes").value),
        uses: Number($("#maintenance-uses").value)
      })
    });
    $("#generated-maintenance-password").value = result.password;
    $("#maintenance-secret").classList.remove("hidden");
    toast("A new rotating maintenance password was generated");
    await refresh();
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

$("#copy-maintenance-password").addEventListener("click", async () => {
  const input = $("#generated-maintenance-password");
  try {
    await navigator.clipboard.writeText(input.value);
    toast("Maintenance password copied");
  } catch {
    input.select();
    document.execCommand("copy");
    toast("Maintenance password copied");
  }
});

$(".maintenance-panel").addEventListener("click", async (event) => {
  const revoke = event.target.closest("[data-revoke-maintenance]");
  const approve = event.target.closest("[data-approve-maintenance]");
  const reject = event.target.closest("[data-reject-maintenance]");
  const id = revoke?.dataset.revokeMaintenance ||
    approve?.dataset.approveMaintenance ||
    reject?.dataset.rejectMaintenance;
  if (!id) return;
  const route = revoke
    ? `/api/admin/maintenance/passwords/${id}/revoke`
    : `/api/admin/maintenance/requests/${id}/${approve ? "approve" : "reject"}`;
  try {
    event.target.disabled = true;
    await api(route, { method: "POST", body: "{}" });
    toast(revoke ? "Maintenance password revoked" : `Maintenance request ${approve ? "approved" : "rejected"}`);
    await refresh();
  } catch (error) {
    event.target.disabled = false;
    toast(error.message);
  }
});

$("#approvals").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-approve], [data-reject]");
  const id = button?.dataset.approve || button?.dataset.reject;
  if (!id) return;
  const action = button.dataset.approve ? "approve" : "reject";
  try {
    button.disabled = true;
    await api(`/api/admin/enrollment-requests/${id}/${action}`, { method: "POST", body: "{}" });
    toast(`Enrollment request ${action === "approve" ? "approved" : "rejected"}`);
    await refresh();
  } catch (error) {
    button.disabled = false;
    toast(error.message);
  }
});

$("#devices").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-device]");
  if (!button) return;
  selectedDeviceId = button.dataset.device;
  const device = devices.find((item) => item.id === selectedDeviceId);
  $("#device-name").textContent = device?.name || "Managed device";
  $("#device-meta").textContent = "Loading complete endpoint telemetry…";
  $("#device-details").innerHTML = `<div class="detail-loading">Loading complete endpoint state…</div>`;
  $("#command-history").innerHTML = "";
  $("#device-dialog").showModal();
  try {
    await refreshDeviceDetails(true);
  } catch (error) {
    $("#device-details").innerHTML = `<div class="detail-error">${escapeHtml(error.message)}</div>`;
    toast(error.message);
  }
});

$("#device-dialog").addEventListener("click", async (event) => {
  const wakeButton = event.target.closest("[data-wake]");
  if (wakeButton && selectedDeviceId) {
    const device = devices.find((item) => item.id === selectedDeviceId);
    if (!window.confirm(
      `Send a Wake-on-LAN magic packet to ${device?.name || "this endpoint"}?`
    )) return;
    try {
      wakeButton.disabled = true;
      const result = await api(`/api/admin/devices/${selectedDeviceId}/wake`, {
        method: "POST",
        body: "{}"
      });
      toast(`Sent ${result.packetsSent} Wake-on-LAN packet(s) to ${device?.name || "endpoint"}`);
    } catch (error) {
      toast(error.message);
    } finally {
      wakeButton.disabled = false;
    }
    return;
  }
  const button = event.target.closest("[data-command]");
  const type = button?.dataset.command;
  if (!type || !selectedDeviceId) return;
  const device = devices.find((item) => item.id === selectedDeviceId);
  if (type === "client.update" &&
      !window.confirm(`Silently update ${device?.name || "this endpoint"} to the latest signed HQ release?`)) return;
  try {
    button.disabled = true;
    await api(`/api/admin/devices/${selectedDeviceId}/commands`, {
      method: "POST",
      body: JSON.stringify({ type, payload: {} })
    });
    toast(`${humanLabel(type)} queued for ${device?.name || "endpoint"}`);
    await refreshDeviceDetails(true);
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog").close());
});
$("#device-dialog").addEventListener("close", () => { selectedDeviceId = null; });
window.addEventListener("beforeunload", () => clearInterval(pollTimer));
