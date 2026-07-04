let csrf = "";
let dashboard = null;
let pollTimer = null;
let knownQuarantineCount = null;
let knownEventIds = null;
let quarantineRequest = null;
let discoveredHqServers = [];
let dashboardReachable = true;

const savedTheme = localStorage.getItem("sentryloom-theme");
document.documentElement.dataset.theme = savedTheme === "light" ? "light" : "dark";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function syncThemeButton() {
  const light = document.documentElement.dataset.theme === "light";
  const label = light ? "Use dark theme" : "Use light theme";
  $("#theme-toggle").title = label;
  $("#theme-toggle").setAttribute("aria-label", label);
}

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.className = error ? "show error" : "show";
  setTimeout(() => { element.className = ""; }, 3500);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (options.method && options.method !== "GET") headers["X-SentryLoom-CSRF"] = csrf;
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function page(name) {
  $$(".page").forEach((element) => element.classList.toggle("active", element.id === `page-${name}`));
  $$(".nav").forEach((element) => element.classList.toggle("active", element.dataset.page === name));
  $("#page-title").textContent = name[0].toUpperCase() + name.slice(1);
  if (name === "quarantine" && csrf) refreshQuarantine().catch((error) => toast(error.message, true));
}

function relativeTime(value) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(value)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function duration(ms) {
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} sec`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function renderPosture(posture, runtime) {
  if (!posture) return;
  $("#security-score").textContent = posture.score;
  $("#security-grade").textContent = posture.grade;
  $("#security-score-card").dataset.state = posture.state;
  $("#action-count").textContent = posture.issues.length
    ? `${posture.issues.length} ACTION${posture.issues.length === 1 ? "" : "S"}`
    : "NO ACTIONS";
  $("#action-count").classList.toggle("warning", Boolean(posture.issues.length));
  $("#action-list").classList.toggle("empty", !posture.issues.length);
  $("#action-list").innerHTML = posture.issues.length
    ? posture.issues.slice(0, 5).map((item) => `
      <div class="action-item ${escapeHtml(item.severity)}">
        <i></i>
        <span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></span>
        <b>${escapeHtml(item.action)}</b>
      </div>
    `).join("")
    : `<div class="action-clear"><strong>No action required</strong><span>Recommended protection controls are active.</span></div>`;
  $("#fix-all").classList.toggle("hidden", !posture.fixableCount);
  $("#fix-all").textContent = `Fix all (${posture.fixableCount})`;
  $("#runtime-stat").textContent = runtime
    ? `Engine memory ${formatBytes(runtime.rssBytes)} · Uptime ${duration(runtime.uptimeSeconds * 1000)}`
    : "Engine performance is unavailable.";
}

function renderStatus(status) {
  if (status.navigation?.page) page(status.navigation.page);
  renderHq(status.management);
  const fileReady = !status.protection.enabled || status.protection.file.running;
  const networkReady = !status.protection.network.enabled || status.protection.network.running;
  const advancedReady = status.protection.advanced.running;
  const protectedNow = status.healthy && fileReady && networkReady && advancedReady;
  $("#health-title").textContent = protectedNow ? "SentryLoom protection is active" : "Protection needs attention";
  $("#health-detail").textContent = protectedNow
    ? `${status.protection.file.targets.length} fixed-drive watcher(s) and TCP/DNS IOC monitoring are active${status.protection.elevated ? " with administrator access." : " with current-user access."}`
    : status.audit.valid ? "One or more configured realtime monitors are not currently active." : "Audit log integrity validation failed.";
  $("#health-hero").classList.toggle("attention", !protectedNow);
  $("#realtime-stat").textContent = status.protection.file.running
    ? `${status.protection.monitorAllFixedDrives ? "All fixed drives" : "User profile"} · ${status.protection.file.filesInspected} checked${status.protection.file.downloadsDeepScan?.running ? ` · Downloads deep ${status.protection.file.downloadsDeepScan.filesInspected}` : ""}`
    : status.protection.enabled ? "Not running" : "Disabled";
  $("#network-stat").textContent = status.protection.network.running
    ? `TCP ${status.protection.network.connectionsObserved} · DNS ${status.protection.network.dnsEntriesObserved}`
    : status.protection.network.enabled ? "Not running" : "Disabled";
  const advanced = status.protection.advanced;
  $("#behavior-stat").textContent = advanced.running
    ? `${advanced.processesObserved} processes · ${advanced.canaries} canaries`
    : "Not running";
  if (dashboard) {
    $("#monitoring-summary").textContent = advanced.running
      ? `Processes ${advanced.processStarts} starts / ${advanced.processDetections} detections · Persistence ${advanced.persistenceChanges} changes · Security events ${advanced.securityEvents} · Removable ${advanced.removableArrivals} · Firewall ${advanced.firewallChanges} changes · Errors ${advanced.errors}`
      : "Advanced collectors are not running.";
  }
  const signatureTotal = status.signatures.hashCount + status.signatures.patternCount + status.signatures.threatCount;
  $("#signature-stat").textContent = status.clamavEngine.databasesReady
    ? `${status.clamavEngine.signatureCount.toLocaleString()} ClamAV + ${signatureTotal.toLocaleString()} hashes + ${status.signatures.networkIocCount.toLocaleString()} network IOCs`
    : `${signatureTotal.toLocaleString()} hashes + ${status.signatures.networkIocCount.toLocaleString()} network IOCs`;
  const quarantineChanged = knownQuarantineCount !== null && knownQuarantineCount !== status.quarantineCount;
  knownQuarantineCount = status.quarantineCount;
  $("#quarantine-stat").textContent = `${status.quarantineCount} item${status.quarantineCount === 1 ? "" : "s"}`;
  $("#nav-quarantine").textContent = status.quarantineCount;
  if (quarantineChanged) refreshQuarantine().catch((error) => toast(error.message, true));
  $("#audit-stat").textContent = status.audit.valid
    ? status.audit.recovered
      ? `${status.audit.records} verified records · prior evidence preserved`
      : `${status.audit.records} verified records`
    : `Failed at record ${status.audit.failedAt}`;
  const last = status.lastScan;
  if (last) {
    $("#last-scan-title").textContent = `${last.target} · ${relativeTime(last.endedAt)}`;
    $("#last-files").textContent = last.scanned.toLocaleString();
    $("#last-threats").textContent = last.detections;
    $("#last-duration").textContent = duration(last.durationMs);
    $("#last-scan-pill").textContent = last.detections ? "REVIEW" : "CLEAN";
  }
  const events = status.events.slice(0, 4);
  const eventIds = new Set(status.events.map((event) => event.id));
  if (knownEventIds) {
    const important = status.events.find((event) =>
      !knownEventIds.has(event.id) &&
      (event.type.includes("detection") ||
       /(?:^|[.-])(?:error|failed|failure|unavailable)$/.test(event.type) ||
       event.type === "hq.connection-lost" ||
       event.type === "hq.connection-restored")
    );
    if (important) {
      toast(
        important.error || important.message || important.type.replaceAll(".", " "),
        /(?:error|failed|failure|unavailable|connection-lost)$/.test(important.type)
      );
    }
  }
  knownEventIds = eventIds;
  $("#recent-events").classList.toggle("empty", !events.length);
  $("#recent-events").innerHTML = events.length ? events.map((event) => `
    <div class="timeline-item"><i></i><span>${escapeHtml(event.error ? `${event.type.replaceAll(".", " ")}: ${event.error}` : event.type.replaceAll(".", " "))}</span><time>${relativeTime(event.at)}</time></div>
  `).join("") : "No recent security events.";
  renderPosture(status.posture, status.runtime);
  renderProgress(status);
  renderThreatIntel(status);
}

function renderHq(status) {
  if (!status) return;
  const enrolled = Boolean(status.deviceId || status.enrolled);
  const pending = Boolean(status.pending);
  const rejected = Boolean(status.rejected);
  const connected = status.connected === undefined
    ? Boolean(status.running && status.lastConnectedAt && !status.lastError)
    : Boolean(status.connected);
  const reconnecting = status.connectionState === "reconnecting" || status.connectionState === "connecting";
  const state = pending ? "PENDING APPROVAL" : rejected ? "REJECTED" : enrolled
    ? connected ? (status.delegated ? "CONNECTED · BACKGROUND" : "CONNECTED")
      : reconnecting ? "RECONNECTING" : "OFFLINE"
    : "STANDALONE";
  $("#hq-state").textContent = state;
  $("#hq-state").classList.toggle("warning", pending || rejected || (enrolled && !connected && !status.delegated));
  $("#hq-summary").textContent = pending
    ? `${status.hqName || "SentryLoom HQ"} · Waiting for an administrator to approve this endpoint${status.lastCheckedAt ? ` · Checked ${relativeTime(status.lastCheckedAt)}` : ""}${status.lastError ? ` · ${status.lastError}` : ""}`
    : rejected
      ? `${status.hqName || "SentryLoom HQ"} rejected this enrollment request. Return to standalone mode before requesting again.`
      : enrolled
    ? `${status.hqName || "SentryLoom HQ"} · ${status.serverUrl || "server unavailable"}${status.delegated ? " · Managed by the background protection agent" : ""}${status.lastConnectedAt ? ` · Last contact ${relativeTime(status.lastConnectedAt)}` : ""}${status.lastResumeAt ? ` · Resumed ${relativeTime(status.lastResumeAt)}` : ""}${status.lastError ? ` · ${status.lastError}` : ""}${status.nextRetryAt ? ` · Retry ${relativeTime(status.nextRetryAt)}` : ""}`
    : "This endpoint is locally managed and does not send telemetry to a server.";
  $("#disconnect-hq").classList.toggle("hidden", !enrolled && !pending && !rejected);
  $("#enroll-hq").classList.toggle("hidden", enrolled || pending || rejected);
  if (status.serverUrl && !$("#hq-url").value) $("#hq-url").value = status.serverUrl;
}

function renderProgress(status) {
  const active = status.activeScan;
  $("#cancel-scan").classList.toggle("hidden", !active);
  if (!active) {
    $("#progress-title").textContent = "Scanner ready";
    $("#progress-file").textContent = "Choose a scan to begin.";
    $("#progress-bar").style.width = "0%";
    return;
  }
  const progress = status.progress || { completed: 0, total: 0 };
  const finalizing = progress.phase === "clamav";
  const percent = finalizing ? 98 : progress.total ? Math.min(97, progress.completed / progress.total * 97) : 2;
  $("#progress-title").textContent = finalizing
    ? "Final verification · ClamAV"
    : `${active.type[0].toUpperCase() + active.type.slice(1)} scan · ${progress.completed}/${progress.total || "…"}`;
  $("#progress-file").textContent = progress.current || "Discovering files…";
  $("#progress-bar").style.width = `${percent}%`;
}

function escapeHtml(value) {
  const span = document.createElement("span");
  span.textContent = String(value ?? "");
  return span.innerHTML;
}

function renderQuarantine(items) {
  const active = items.filter((item) => item.state === "quarantined");
  $("#quarantine-table").innerHTML = active.length ? active.map((item) => `
    <tr>
      <td><strong>${escapeHtml(item.findings[0]?.name || "Detection")}</strong></td>
      <td class="path" title="${escapeHtml(item.originalPath)}">${escapeHtml(item.originalPath)}</td>
      <td>${relativeTime(item.quarantinedAt)}</td>
      <td><span class="status-pill">ISOLATED</span></td>
      <td><button class="table-action" data-restore="${item.id}">Restore</button><button class="table-action delete" data-delete="${item.id}">Delete</button></td>
    </tr>
  `).join("") : `<tr><td colspan="5" class="muted">The quarantine vault is empty.</td></tr>`;
}

async function refreshQuarantine() {
  if (quarantineRequest) return quarantineRequest;
  quarantineRequest = api("/api/quarantine");
  try {
    const items = await quarantineRequest;
    if (dashboard) dashboard.quarantine = items;
    renderQuarantine(items);
    knownQuarantineCount = items.filter((item) => item.state === "quarantined").length;
    return items;
  } finally {
    quarantineRequest = null;
  }
}

function renderAudit(records) {
  $("#audit-list").innerHTML = records.length ? records.map((record) => `
    <div class="activity-item">
      <time>${new Date(record.at).toLocaleString()}</time>
      <strong>${escapeHtml(record.event)}</strong>
      <pre>${escapeHtml(JSON.stringify(record.details))}</pre>
    </div>
  `).join("") : `<p class="muted">No audit records yet.</p>`;
}

function renderHistory(records) {
  $("#scan-history").innerHTML = records.length ? records.map((record) => {
    const type = record.type || "scan";
    const clean = !record.detections && !record.errorCount;
    return `
      <tr>
        <td><strong>${escapeHtml(type[0].toUpperCase() + type.slice(1))}</strong></td>
        <td class="path" title="${escapeHtml(record.target)}">${escapeHtml(record.target)}</td>
        <td>${record.endedAt ? relativeTime(record.endedAt) : "Incomplete"}</td>
        <td>${Number(record.scanned || 0).toLocaleString()}</td>
        <td>${Number(record.detections || 0).toLocaleString()}</td>
        <td><span class="status-pill${clean ? "" : " warning"}">${clean ? "CLEAN" : record.detections ? "REVIEW" : "ERRORS"}</span></td>
      </tr>
    `;
  }).join("") : `<tr><td colspan="6" class="muted">No completed scans yet.</td></tr>`;
}

function renderReputation(result) {
  const container = $("#reputation-result");
  container.className = `reputation-result ${result.verdict}`;
  container.innerHTML = `
    <div class="reputation-verdict">
      <span><small>VERDICT</small><strong>${escapeHtml(result.verdict.toUpperCase())}</strong></span>
      <code>${escapeHtml(result.query)}</code>
    </div>
    ${result.matches.length ? result.matches.map((match) => `
      <div class="reputation-match">
        <span><strong>${escapeHtml(match.name)}</strong><small>${escapeHtml(match.source)}</small></span>
        <b>${escapeHtml(match.severity || (match.confidence ? `${match.confidence}% confidence` : "listed"))}</b>
      </div>
    `).join("") : `<p>No local intelligence match was found. An unknown verdict does not prove the indicator is safe.</p>`}
  `;
}

function renderSettings(config) {
  $("#setting-realtime").checked = config.protection.realtimeEnabled;
  $("#setting-all-drives").checked = config.protection.monitorAllFixedDrives;
  $("#setting-downloads-deep").checked = config.protection.downloadsDeepScanEnabled;
  $("#setting-network").checked = config.protection.networkMonitoringEnabled;
  $("#setting-dns").checked = config.protection.dnsMonitoringEnabled;
  $("#setting-confirmed").checked = config.protection.autoQuarantineConfirmed;
  $("#setting-heuristic").checked = config.protection.autoQuarantineHeuristics;
  $("#setting-exclusions").value = config.scanner.exclusions.join("\n");
  $("#setting-process-monitor").checked = config.monitoring.processEnabled;
  $("#setting-persistence-monitor").checked = config.monitoring.persistenceEnabled;
  $("#setting-ransomware-monitor").checked = config.monitoring.ransomwareEnabled;
  $("#setting-event-monitor").checked = config.monitoring.windowsEventsEnabled;
  $("#setting-removable-monitor").checked = config.monitoring.removableMediaEnabled;
  $("#setting-firewall-monitor").checked = config.monitoring.firewallIntegrityEnabled;
  $("#setting-firewall-block").checked = config.monitoring.firewallBlockHighConfidence;
  $("#clear-firewall-rules").textContent = `Clear SentryLoom firewall blocks (${dashboard.firewallPolicy?.blockedAddresses || 0})`;
}

function renderDnsFiltering(status) {
  dashboard.dnsFiltering = status;
  $("#dns-profile-grid").innerHTML = status.profiles.map((profile) => `
    <label class="dns-profile${status.detectedProfile === profile.id ? " applied" : ""}">
      <input type="radio" name="dns-profile" value="${escapeHtml(profile.id)}"
        ${status.selectedProfile === profile.id ? "checked" : ""}>
      <span>
        <strong>${escapeHtml(profile.name)}${profile.recommended ? " · Recommended" : ""}</strong>
        <small>${escapeHtml(profile.description)}</small>
        <code>${escapeHtml(profile.ipv4.join(" · "))}</code>
      </span>
    </label>
  `).join("");
  $("#dns-adapter-list").innerHTML = status.adapters.length
    ? status.adapters.map((adapter) => `
      <div><strong>${escapeHtml(adapter.alias)}</strong><span>${escapeHtml(adapter.dnsServers.join(", ") || "Automatic DNS")}</span></div>
    `).join("")
    : `<div class="muted">No active routed network adapter was found.</div>`;
  const state = $("#dns-filter-state");
  state.textContent = status.detectedProfile
    ? status.inSync ? "ACTIVE" : "EXTERNALLY CHANGED"
    : status.configuredProfile ? "OUT OF SYNC" : "WINDOWS DEFAULT";
  state.classList.toggle("warning", !status.inSync);
  $("#apply-dns-profile").disabled = !status.supported || !status.adapters.length;
  $("#restore-dns-profile").disabled = !status.backupAvailable;
}

function renderDeviceControl(status) {
  dashboard.deviceControl = status;
  const usb = status.usbStorage;
  const control = $("#setting-usb-storage-block");
  control.checked = Boolean(usb.blocked);
  control.disabled = !usb.supported || (usb.blocked && !usb.backupAvailable);
  const state = $("#usb-storage-state");
  state.textContent = !usb.supported
    ? "UNAVAILABLE"
    : usb.blocked
      ? usb.backupAvailable ? "STORAGE BLOCKED" : "POLICY BLOCKED"
      : "STORAGE ALLOWED";
  state.classList.toggle("warning", Boolean(usb.blocked));
}

function renderThreatIntel(status) {
  const configured = status.threatUpdates.credentials.abuseChConfigured;
  for (const feed of status.signatures.threatIntel.feeds) {
    const state = $(`#feed-state-${feed.source}`);
    const count = $(`#feed-count-${feed.source}`);
    if (!state || !count) continue;
    const needsKey = ["malwarebazaar", "urlhaus", "threatfox"].includes(feed.source) && !configured;
    state.textContent = needsKey
      ? "Auth-Key required"
      : feed.state === "ready"
        ? `Updated ${relativeTime(feed.lastSuccess)}`
        : feed.state === "error"
          ? feed.error || "Update failed"
          : feed.state === "updating"
            ? "Updating…"
            : "Never updated";
    state.classList.toggle("error", feed.state === "error");
    count.textContent = `${feed.entryCount.toLocaleString()} indicator${feed.entryCount === 1 ? "" : "s"}`;
  }
  const running = status.threatUpdates.running;
  $$(".feed-update, #update-all-feeds").forEach((button) => { button.disabled = running; });
  $("#update-progress").classList.toggle("hidden", !running);
  if (running) {
    const progress = status.threatUpdates.progress || {};
    const received = progress.received || 0;
    const total = progress.total || 0;
    $("#update-progress-bar").style.width = total ? `${Math.min(100, received / total * 100)}%` : "12%";
    $("#update-progress-text").textContent = progress.message ||
      `${progress.source || "Database"} · ${progress.phase || "working"}${progress.imported ? ` · ${progress.imported.toLocaleString()} indexed` : ""}`;
  }
}

async function refresh(full = false) {
  try {
    if (full) {
      const bootstrap = await api("/api/bootstrap");
      csrf = bootstrap.csrf;
      dashboard = bootstrap.data;
      $("#engine-version").textContent = `Engine ${bootstrap.app.version}`;
      renderStatus(dashboard.status);
      renderQuarantine(dashboard.quarantine);
      renderAudit(dashboard.audit);
      renderHistory(dashboard.history || []);
      renderSettings(dashboard.config);
      renderDnsFiltering(dashboard.dnsFiltering);
      renderDeviceControl(dashboard.deviceControl);
    } else {
      renderStatus(await api("/api/status"));
    }
    if (!dashboardReachable) toast("Local SentryLoom service connection restored");
    dashboardReachable = true;
  } catch (error) {
    if (dashboardReachable) toast(error.message, true);
    dashboardReachable = false;
  }
}

async function startScan(type, customPath) {
  try {
    await api("/api/scans", { method: "POST", body: JSON.stringify({ type, path: customPath }) });
    page("scan");
    toast(`${type} scan started`);
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
}

$$(".nav").forEach((button) => button.addEventListener("click", () => page(button.dataset.page)));
$$("[data-page-link]").forEach((button) => button.addEventListener("click", () => page(button.dataset.pageLink)));
$$("[data-scan]").forEach((button) => button.addEventListener("click", () => startScan(button.dataset.scan)));
$("#custom-scan").addEventListener("click", () => {
  const value = $("#custom-path").value.trim();
  if (!value) return toast("Enter an absolute path to scan", true);
  startScan("path", value);
});
async function browseScanTarget(kind) {
  const buttons = [$("#browse-file"), $("#browse-folder")];
  buttons.forEach((button) => { button.disabled = true; });
  try {
    const result = await api("/api/dialogs/scan-target", {
      method: "POST",
      body: JSON.stringify({ kind })
    });
    if (result.path) $("#custom-path").value = result.path;
  } catch (error) {
    toast(error.message, true);
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}
$("#browse-file").addEventListener("click", () => browseScanTarget("file"));
$("#browse-folder").addEventListener("click", () => browseScanTarget("folder"));
$("#cancel-scan").addEventListener("click", async () => {
  try { await api("/api/scans/cancel", { method: "POST" }); toast("Scan cancellation requested"); } catch (error) { toast(error.message, true); }
});
$("#fix-all").addEventListener("click", async () => {
  if (!confirm("Enable recommended protection controls and restart SentryLoom monitoring components? Aggressive heuristic quarantine and automatic firewall blocking will remain disabled.")) return;
  const button = $("#fix-all");
  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Applying protection…";
  try {
    const status = await api("/api/action-center/fix-all", { method: "POST", body: "{}" });
    renderStatus(status);
    toast("Recommended protection controls are active");
    await refresh(true);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    if (!button.classList.contains("hidden")) button.textContent = originalText;
  }
});
$("#refresh").addEventListener("click", () => refresh(true));
$("#theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("sentryloom-theme", next);
  syncThemeButton();
});
$("#lookup-reputation").addEventListener("click", async () => {
  const value = $("#reputation-value").value.trim();
  if (!value) return toast("Enter a hash, domain, URL, or IP address", true);
  const button = $("#lookup-reputation");
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    renderReputation(await api(`/api/reputation?value=${encodeURIComponent(value)}`));
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Check reputation";
  }
});
$("#reputation-value").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("#lookup-reputation").click();
});
$("#load-background-output").addEventListener("click", async () => {
  const button = $("#load-background-output");
  const output = $("#background-output");
  button.disabled = true;
  button.textContent = "Loading…";
  try {
    const result = await api("/api/background-output");
    const sections = [];
    if (result.previous?.text) sections.push(`--- PREVIOUS LOG ---\n${result.previous.text}`);
    if (result.current?.text) sections.push(`--- CURRENT LOG ---\n${result.current.text}`);
    output.textContent = sections.join("\n") || "No background output has been recorded yet.";
    output.classList.remove("hidden");
    output.scrollTop = output.scrollHeight;
    const bytes = Number(result.current?.bytes || 0) + Number(result.previous?.bytes || 0);
    $("#background-output-status").textContent = result.running
      ? `Resident protection is running (worker ${result.workerPid}). ${formatBytes(bytes)} of bounded output loaded.`
      : `Resident protection is not currently reporting. ${formatBytes(bytes)} of saved output loaded.`;
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Reload output";
  }
});
$("#exit-app").addEventListener("click", async () => {
  if (!confirm("Close the SentryLoom console? Resident scheduled protection will continue in the background.")) return;
  const button = $("#exit-app");
  button.disabled = true;
  document.body.classList.add("closing");
  try {
    await api("/api/application/exit", { method: "POST", body: "{}" });
    setTimeout(() => window.close(), 120);
  } catch (error) {
    document.body.classList.remove("closing");
    button.disabled = false;
    toast(error.message, true);
  }
});
$("#save-settings").addEventListener("click", async () => {
  const body = {
    protection: {
      realtimeEnabled: $("#setting-realtime").checked,
      monitorAllFixedDrives: $("#setting-all-drives").checked,
      downloadsDeepScanEnabled: $("#setting-downloads-deep").checked,
      networkMonitoringEnabled: $("#setting-network").checked,
      dnsMonitoringEnabled: $("#setting-dns").checked,
      autoQuarantineConfirmed: $("#setting-confirmed").checked,
      autoQuarantineHeuristics: $("#setting-heuristic").checked
    },
    scanner: {
      exclusions: $("#setting-exclusions").value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
    },
    monitoring: {
      processEnabled: $("#setting-process-monitor").checked,
      persistenceEnabled: $("#setting-persistence-monitor").checked,
      ransomwareEnabled: $("#setting-ransomware-monitor").checked,
      windowsEventsEnabled: $("#setting-event-monitor").checked,
      removableMediaEnabled: $("#setting-removable-monitor").checked,
      firewallIntegrityEnabled: $("#setting-firewall-monitor").checked,
      firewallBlockHighConfidence: $("#setting-firewall-block").checked
    }
  };
  try {
    dashboard.config = await api("/api/config", { method: "PATCH", body: JSON.stringify(body) });
    toast("Protection policy saved. Restart SentryLoom to apply realtime monitoring changes.");
  } catch (error) { toast(error.message, true); }
});
$("#discover-hq").addEventListener("click", async () => {
  const button = $("#discover-hq");
  button.disabled = true;
  button.textContent = "Searching network…";
  try {
    const result = await api("/api/hq/discover", { method: "POST", body: "{}" });
    discoveredHqServers = result.servers || [];
    const select = $("#hq-discovered");
    select.innerHTML = discoveredHqServers.map((server, index) =>
      `<option value="${index}">${escapeHtml(server.name)} · ${escapeHtml(server.url)}</option>`
    ).join("");
    select.classList.toggle("hidden", !discoveredHqServers.length);
    if (!discoveredHqServers.length) {
      toast("No SentryLoom HQ server answered on this network", true);
      return;
    }
    select.value = "0";
    select.dispatchEvent(new Event("change"));
    toast(`${discoveredHqServers.length} HQ server${discoveredHqServers.length === 1 ? "" : "s"} found`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Find HQ on this network";
  }
});
$("#hq-discovered").addEventListener("change", () => {
  const server = discoveredHqServers[Number($("#hq-discovered").value)];
  if (!server) return;
  $("#hq-url").value = server.url;
  $("#hq-fingerprint").value = server.fingerprint256;
});
$("#enroll-hq").addEventListener("click", async () => {
  const serverUrl = $("#hq-url").value.trim();
  const fingerprint256 = $("#hq-fingerprint").value.trim();
  const button = $("#enroll-hq");
  button.disabled = true;
  button.textContent = "Requesting approval…";
  try {
    const status = await api("/api/hq/request", {
      method: "POST",
      body: JSON.stringify({
        serverUrl: serverUrl || undefined,
        fingerprint256: fingerprint256 || undefined
      })
    });
    renderHq(status);
    toast(`Approval requested from ${status.hqName}`);
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Request administrator approval";
  }
});
$("#disconnect-hq").addEventListener("click", async () => {
  if (!confirm("Return this endpoint to standalone mode? HQ will stop receiving telemetry and issuing actions, but local protection will continue.")) return;
  try {
    const status = await api("/api/hq/disconnect", { method: "POST", body: "{}" });
    renderHq(status);
    $("#hq-url").value = "";
    $("#hq-fingerprint").value = "";
    toast("Standalone mode enabled");
  } catch (error) { toast(error.message, true); }
});
$("#clear-firewall-rules").addEventListener("click", async () => {
  if (!confirm("Remove every outbound threat-IP rule created by SentryLoom?")) return;
  try {
    const status = await api("/api/firewall-policy/clear", { method: "POST", body: "{}" });
    dashboard.firewallPolicy = status;
    $("#clear-firewall-rules").textContent = `Clear SentryLoom firewall blocks (${status.blockedAddresses || 0})`;
    toast("SentryLoom firewall rules cleared");
  } catch (error) { toast(error.message, true); }
});
$("#setting-usb-storage-block").addEventListener("change", async () => {
  const control = $("#setting-usb-storage-block");
  const requested = control.checked;
  const message = requested
    ? "Block access to USB and other removable storage classes on this PC? USB keyboards and mice will remain available."
    : "Restore the removable-storage policy that existed before SentryLoom enabled blocking?";
  if (!confirm(message)) {
    control.checked = !requested;
    return;
  }
  control.disabled = true;
  try {
    const status = await api("/api/device-control/usb-storage", {
      method: "POST",
      body: JSON.stringify({ blocked: requested })
    });
    renderDeviceControl(status);
    toast(requested ? "USB removable storage is blocked" : "USB removable storage access is restored");
  } catch (error) {
    control.checked = !requested;
    control.disabled = false;
    toast(error.message, true);
  }
});
$("#apply-dns-profile").addEventListener("click", async () => {
  const selected = document.querySelector('input[name="dns-profile"]:checked')?.value;
  if (!selected) return toast("Choose a DNS filtering profile", true);
  if (!confirm("Apply this encrypted DNS profile to every active Windows network adapter?")) return;
  const button = $("#apply-dns-profile");
  button.disabled = true;
  button.textContent = "Waiting for Windows approval…";
  try {
    const status = await api("/api/dns-filtering/apply", {
      method: "POST",
      body: JSON.stringify({ profileId: selected })
    });
    renderDnsFiltering(status);
    dashboard.config.dnsFiltering.selectedProfile = selected;
    toast("Encrypted ad-blocking DNS is active");
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.textContent = "Apply selected DNS";
    button.disabled = false;
  }
});
$("#restore-dns-profile").addEventListener("click", async () => {
  if (!confirm("Restore the DNS settings saved before SentryLoom made its first change?")) return;
  const button = $("#restore-dns-profile");
  button.disabled = true;
  try {
    const status = await api("/api/dns-filtering/restore", { method: "POST", body: "{}" });
    renderDnsFiltering(status);
    toast("Previous Windows DNS settings restored");
  } catch (error) {
    toast(error.message, true);
  }
});
$("#save-auth-key").addEventListener("click", async () => {
  const key = $("#abuse-auth-key").value.trim();
  if (!key) return toast("Enter your abuse.ch Auth-Key", true);
  try {
    await api("/api/threat-intel/credentials", {
      method: "POST",
      body: JSON.stringify({ abuseChAuthKey: key })
    });
    $("#abuse-auth-key").value = "";
    toast("Auth-Key encrypted and saved locally");
    await refresh(true);
  } catch (error) { toast(error.message, true); }
});

async function updateFeeds(sources) {
  try {
    await api("/api/threat-intel/update", {
      method: "POST",
      body: JSON.stringify({ sources })
    });
    toast("Database update started");
    await refresh();
  } catch (error) { toast(error.message, true); }
}

$$("[data-update-feed]").forEach((button) => {
  button.addEventListener("click", () => updateFeeds([button.dataset.updateFeed]));
});
$("#update-all-feeds").addEventListener("click", () => updateFeeds([
  "clamav", "malwarebazaar", "urlhaus", "feodotracker", "threatfox"
]));
$("#quarantine-table").addEventListener("click", async (event) => {
  const restore = event.target.dataset.restore;
  const remove = event.target.dataset.delete;
  try {
    if (restore) {
      if (!confirm("Restoring a detected file can put this PC at risk. Restore it to its original location?")) return;
      await api(`/api/quarantine/${restore}/restore`, { method: "POST", body: "{}" });
      toast("File restored");
    }
    if (remove) {
      if (!confirm("Permanently delete this quarantined file?")) return;
      await api(`/api/quarantine/${remove}/delete`, { method: "POST", body: "{}" });
      toast("Quarantined file deleted");
    }
    await refresh(true);
  } catch (error) { toast(error.message, true); }
});

syncThemeButton();
await refresh(true);
const initialPage = new URLSearchParams(window.location.search).get("page");
if (["overview", "scan", "quarantine", "activity", "settings"].includes(initialPage)) {
  page(initialPage);
  history.replaceState(null, "", window.location.pathname);
}
pollTimer = setInterval(() => refresh(false), 1500);
window.addEventListener("offline", () => {
  toast("Windows reports that the network is offline. HQ reconnection will be automatic.", true);
});
window.addEventListener("online", () => {
  toast("Network restored. Checking SentryLoom HQ now.");
  refresh(false);
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") refresh(false);
});
window.addEventListener("beforeunload", () => clearInterval(pollTimer));
