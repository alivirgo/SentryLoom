import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { APP_NAME, APP_VERSION, appPaths } from "./constants.js";
import { validDashboardPage } from "./lib/ui-command.js";

const directory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.join(directory, "ui");
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml"
};

function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(body);
}

async function bodyJson(request) {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 64 * 1024) throw new Error("Request body is too large");
    chunks.push(chunk);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}

async function readTextTail(file, maximumBytes = 256 * 1024) {
  let handle;
  try {
    handle = await fs.open(file, "r");
    const stat = await handle.stat();
    const length = Math.min(stat.size, maximumBytes);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, Math.max(0, stat.size - length));
    return {
      text: buffer.toString("utf8"),
      bytes: stat.size,
      truncated: stat.size > length,
      modifiedAt: stat.mtime.toISOString()
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      return { text: "", bytes: 0, truncated: false, modifiedAt: null };
    }
    throw error;
  } finally {
    await handle?.close();
  }
}

function cookieValue(request, key) {
  const values = (request.headers.cookie || "").split(";").map((item) => item.trim().split("="));
  return values.find(([name]) => name === key)?.[1];
}

export function createDashboardServer(engine, options = {}) {
  const launchToken = crypto.randomBytes(32).toString("base64url");
  const sessions = new Map();

  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://127.0.0.1");
      if (url.pathname === "/session") {
        const supplied = url.searchParams.get("token");
        if (!supplied || supplied.length !== launchToken.length ||
            !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(launchToken))) {
          response.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
          response.end("Invalid SentryLoom launch token. Start the console from the SentryLoom shortcut.");
          return;
        }
        const sessionId = crypto.randomBytes(24).toString("base64url");
        sessions.set(sessionId, { csrf: crypto.randomBytes(24).toString("base64url"), createdAt: Date.now() });
        const requestedPage = validDashboardPage(url.searchParams.get("page"));
        response.writeHead(302, {
          Location: requestedPage ? `/?page=${encodeURIComponent(requestedPage)}` : "/",
          "Set-Cookie": `sentryloom_session=${sessionId}; HttpOnly; SameSite=Strict; Path=/`,
          "Cache-Control": "no-store"
        });
        response.end();
        return;
      }

      const sessionId = cookieValue(request, "sentryloom_session");
      const session = sessions.get(sessionId);
      if (!session) {
        response.writeHead(401, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
        response.end("SentryLoom session required. Launch the console from the installed shortcut.");
        return;
      }
      if (url.pathname.startsWith("/api/")) {
        if (request.method !== "GET" && request.headers["x-sentryloom-csrf"] !== session.csrf) {
          json(response, 403, { error: "Request verification failed" });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/bootstrap") {
          json(response, 200, {
            app: { name: APP_NAME, version: APP_VERSION },
            csrf: session.csrf,
            data: await engine.getDashboardData()
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/status") {
          json(response, 200, await engine.getStatus());
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/quarantine") {
          json(response, 200, await engine.listQuarantine());
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/hq/status") {
          json(response, 200, await engine.getHqStatus());
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/hq/discover") {
          json(response, 200, { servers: await engine.discoverHq() });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/hq/enroll") {
          const body = await bodyJson(request);
          if (typeof body.serverUrl !== "string" || typeof body.code !== "string" ||
              typeof body.fingerprint256 !== "string") {
            json(response, 400, { error: "HQ URL, certificate fingerprint, and enrollment code are required" });
            return;
          }
          json(response, 200, await engine.enrollHq({
            serverUrl: body.serverUrl,
            code: body.code,
            fingerprint256: body.fingerprint256
          }));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/hq/request") {
          const body = await bodyJson(request);
          if (body.serverUrl !== undefined && typeof body.serverUrl !== "string") {
            json(response, 400, { error: "HQ URL is invalid" });
            return;
          }
          if (body.fingerprint256 !== undefined && typeof body.fingerprint256 !== "string") {
            json(response, 400, { error: "HQ certificate fingerprint is invalid" });
            return;
          }
          json(response, 202, await engine.requestHqEnrollment({
            serverUrl: body.serverUrl?.trim() || undefined,
            fingerprint256: body.fingerprint256?.trim() || undefined
          }));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/hq/disconnect") {
          json(response, 200, await engine.disconnectHq());
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/background-output") {
          const paths = appPaths();
          const [current, previous, runtimeText] = await Promise.all([
            readTextTail(paths.backgroundOutput),
            readTextTail(paths.backgroundOutputPrevious),
            fs.readFile(paths.backgroundRuntime, "utf8").catch((error) => {
              if (error.code === "ENOENT") return "";
              throw error;
            })
          ]);
          let runtime = null;
          try { runtime = runtimeText ? JSON.parse(runtimeText) : null; } catch {}
          const runtimeFresh = runtime?.updatedAt &&
            Date.now() - new Date(runtime.updatedAt).getTime() < 15000;
          json(response, 200, {
            running: Boolean(runtimeFresh),
            launcherPid: runtimeFresh ? runtime.launcherPid : null,
            workerPid: runtimeFresh ? runtime.workerPid : null,
            updatedAt: runtimeFresh ? runtime.updatedAt : null,
            current,
            previous
          });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/application/exit") {
          json(response, 200, { closing: true });
          setTimeout(() => options.onExit?.(), 75);
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/scans") {
          const body = await bodyJson(request);
          if (engine.activeScan) {
            json(response, 409, { error: "A scan is already running" });
            return;
          }
          engine.runScan(body.type, body.path).catch((error) => engine.emit({ type: "scan.error", error: error.message }));
          json(response, 202, { accepted: true });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/scans/cancel") {
          json(response, engine.cancelScan() ? 200 : 409, { cancelled: true });
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/dialogs/scan-target") {
          const body = await bodyJson(request);
          if (body.kind !== "file" && body.kind !== "folder") {
            json(response, 400, { error: "Picker type must be file or folder" });
            return;
          }
          json(response, 200, await engine.chooseScanTarget(body.kind));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/action-center/fix-all") {
          json(response, 200, await engine.applyRecommendedProtection());
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/threat-intel/credentials") {
          const body = await bodyJson(request);
          json(response, 200, await engine.saveThreatCredentials({ abuseChAuthKey: body.abuseChAuthKey }));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/threat-intel/update") {
          const body = await bodyJson(request);
          if (engine.threatUpdates.running) {
            json(response, 409, { error: "A threat-intelligence update is already running" });
            return;
          }
          const sources = Array.isArray(body.sources)
            ? body.sources.filter((item) => typeof item === "string").slice(0, 5)
            : undefined;
          engine.updateThreatIntel(sources, { force: Boolean(body.force) })
            .catch((error) => engine.emit({ type: "threat-intel.error", error: error.message }));
          json(response, 202, {
            accepted: true,
            sources: sources || ["clamav", "malwarebazaar", "urlhaus", "feodotracker", "threatfox"]
          });
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/dns-filtering") {
          json(response, 200, await engine.getDnsFilteringStatus());
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/dns-filtering/apply") {
          const body = await bodyJson(request);
          if (typeof body.profileId !== "string" || body.profileId.length > 64) {
            json(response, 400, { error: "Choose a supported DNS filtering profile" });
            return;
          }
          json(response, 200, await engine.applyDnsFiltering(body.profileId));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/dns-filtering/restore") {
          json(response, 200, await engine.restoreDnsFiltering());
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/firewall-policy") {
          json(response, 200, await engine.getFirewallPolicyStatus());
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/device-control") {
          json(response, 200, await engine.getDeviceControlStatus());
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/device-control/usb-storage") {
          const body = await bodyJson(request);
          json(response, 200, await engine.setUsbStorageBlocked(Boolean(body.blocked)));
          return;
        }
        if (request.method === "GET" && url.pathname === "/api/reputation") {
          const value = url.searchParams.get("value") || "";
          if (!value || value.length > 2048) {
            json(response, 400, { error: "Enter a valid reputation lookup value" });
            return;
          }
          json(response, 200, await engine.lookupReputation(value));
          return;
        }
        if (request.method === "POST" && url.pathname === "/api/firewall-policy/clear") {
          json(response, 200, await engine.clearFirewallPolicy());
          return;
        }
        if (request.method === "PATCH" && url.pathname === "/api/config") {
          const body = await bodyJson(request);
          const allowed = {
            protection: {
              realtimeEnabled: body.protection?.realtimeEnabled === undefined
                ? engine.config.protection.realtimeEnabled : Boolean(body.protection.realtimeEnabled),
              monitorAllFixedDrives: body.protection?.monitorAllFixedDrives === undefined
                ? engine.config.protection.monitorAllFixedDrives : Boolean(body.protection.monitorAllFixedDrives),
              downloadsDeepScanEnabled: body.protection?.downloadsDeepScanEnabled === undefined
                ? engine.config.protection.downloadsDeepScanEnabled : Boolean(body.protection.downloadsDeepScanEnabled),
              networkMonitoringEnabled: body.protection?.networkMonitoringEnabled === undefined
                ? engine.config.protection.networkMonitoringEnabled : Boolean(body.protection.networkMonitoringEnabled),
              dnsMonitoringEnabled: body.protection?.dnsMonitoringEnabled === undefined
                ? engine.config.protection.dnsMonitoringEnabled : Boolean(body.protection.dnsMonitoringEnabled),
              autoQuarantineConfirmed: body.protection?.autoQuarantineConfirmed === undefined
                ? engine.config.protection.autoQuarantineConfirmed : Boolean(body.protection.autoQuarantineConfirmed),
              autoQuarantineHeuristics: body.protection?.autoQuarantineHeuristics === undefined
                ? engine.config.protection.autoQuarantineHeuristics : Boolean(body.protection.autoQuarantineHeuristics)
            },
            scanner: {
              exclusions: Array.isArray(body.scanner?.exclusions)
                ? body.scanner.exclusions.filter((item) => typeof item === "string").slice(0, 100)
                : engine.config.scanner.exclusions
            },
            monitoring: {
              processEnabled: body.monitoring?.processEnabled === undefined
                ? engine.config.monitoring.processEnabled : Boolean(body.monitoring.processEnabled),
              persistenceEnabled: body.monitoring?.persistenceEnabled === undefined
                ? engine.config.monitoring.persistenceEnabled : Boolean(body.monitoring.persistenceEnabled),
              ransomwareEnabled: body.monitoring?.ransomwareEnabled === undefined
                ? engine.config.monitoring.ransomwareEnabled : Boolean(body.monitoring.ransomwareEnabled),
              windowsEventsEnabled: body.monitoring?.windowsEventsEnabled === undefined
                ? engine.config.monitoring.windowsEventsEnabled : Boolean(body.monitoring.windowsEventsEnabled),
              removableMediaEnabled: body.monitoring?.removableMediaEnabled === undefined
                ? engine.config.monitoring.removableMediaEnabled : Boolean(body.monitoring.removableMediaEnabled),
              firewallIntegrityEnabled: body.monitoring?.firewallIntegrityEnabled === undefined
                ? engine.config.monitoring.firewallIntegrityEnabled : Boolean(body.monitoring.firewallIntegrityEnabled),
              firewallBlockHighConfidence: body.monitoring?.firewallBlockHighConfidence === undefined
                ? engine.config.monitoring.firewallBlockHighConfidence : Boolean(body.monitoring.firewallBlockHighConfidence)
            }
          };
          json(response, 200, await engine.updateConfig(allowed));
          return;
        }
        const quarantineMatch = url.pathname.match(/^\/api\/quarantine\/([a-f0-9-]{36})\/(restore|delete)$/i);
        if (request.method === "POST" && quarantineMatch) {
          const [, id, action] = quarantineMatch;
          const body = await bodyJson(request);
          if (action === "restore") json(response, 200, { destination: await engine.restore(id, body.destination) });
          else {
            await engine.deleteQuarantine(id);
            json(response, 200, { deleted: true });
          }
          return;
        }
        json(response, 404, { error: "Not found" });
        return;
      }

      const pathname = url.pathname === "/" ? "/index.html" : url.pathname;
      const normalized = path.normalize(pathname).replace(/^([/\\])+/, "");
      const file = path.join(publicDirectory, normalized);
      if (!file.startsWith(publicDirectory)) {
        response.writeHead(403);
        response.end();
        return;
      }
      const content = await fs.readFile(file);
      response.writeHead(200, {
        "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store"
      });
      response.end(content);
    } catch (error) {
      if (error.code === "ENOENT") {
        response.writeHead(404);
        response.end("Not found");
      } else {
        json(response, 500, { error: error.message });
      }
    }
  });

  return {
    server,
    launchToken,
    async listen(host, port) {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, resolve);
      });
      return server.address();
    },
    close() {
      return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  };
}
