import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
import { spawn } from "node:child_process";
import { isIP } from "node:net";
import { appPaths, APP_VERSION } from "../constants.js";
import { ensureDirectory } from "./fs-safe.js";

export const FEED_SOURCES = Object.freeze({
  clamav: {
    id: "clamav",
    name: "ClamAV Official",
    requiresAuth: false,
    homepage: "https://www.clamav.net/",
    description: "Cisco Talos maintained official ClamAV signatures"
  },
  malwarebazaar: {
    id: "malwarebazaar",
    name: "MalwareBazaar",
    requiresAuth: true,
    homepage: "https://bazaar.abuse.ch/",
    description: "Recent family-labelled malware hashes from abuse.ch"
  },
  urlhaus: {
    id: "urlhaus",
    name: "URLhaus",
    requiresAuth: true,
    homepage: "https://urlhaus.abuse.ch/",
    description: "Recent payload hashes observed at malware distribution URLs"
  },
  feodotracker: {
    id: "feodotracker",
    name: "Feodo Tracker",
    requiresAuth: false,
    homepage: "https://feodotracker.abuse.ch/",
    description: "Recommended active botnet C2 IP blocklist"
  },
  threatfox: {
    id: "threatfox",
    name: "ThreatFox",
    requiresAuth: true,
    homepage: "https://threatfox.abuse.ch/",
    description: "Vetted malware hashes and network IOCs"
  }
});

const SOURCE_HOSTS = Object.freeze({
  clamav: ["database.clamav.net", "download.clamav.net"],
  malwarebazaar: ["mb-api.abuse.ch"],
  urlhaus: ["urlhaus-api.abuse.ch"],
  feodotracker: ["feodotracker.abuse.ch"],
  threatfox: ["threatfox-api.abuse.ch"]
});

function validateFeedUrl(value, allowedHosts) {
  const url = new URL(value);
  if (url.protocol !== "https:" || !allowedHosts.includes(url.hostname.toLowerCase())) {
    throw new Error(`Refusing untrusted feed URL: ${url.origin}`);
  }
  return url;
}

async function fetchPolicy(url, options, allowedHosts, fetchImpl = fetch) {
  let current = validateFeedUrl(url, allowedHosts);
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    const response = await fetchImpl(current, { ...options, redirect: "manual" });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get("location");
    if (!location) throw new Error(`Feed redirect ${response.status} had no location`);
    current = validateFeedUrl(new URL(location, current), allowedHosts);
  }
  throw new Error("Feed redirected too many times");
}

export async function fetchJsonFeed(url, options, policy) {
  const response = await fetchPolicy(url, options, policy.allowedHosts, policy.fetchImpl);
  if (!response.ok) throw new Error(`Feed returned HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > policy.maxBytes) throw new Error("Feed response exceeds the configured size limit");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > policy.maxBytes) throw new Error("Feed response exceeds the configured size limit");
  return JSON.parse(bytes.toString("utf8"));
}

export async function downloadFeedFile(url, destination, policy) {
  await ensureDirectory(path.dirname(destination));
  const temporary = `${destination}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policy.timeoutMs);
  try {
    const response = await fetchPolicy(url, {
      method: "GET",
      headers: { "User-Agent": `SentryLoom/${APP_VERSION}` },
      signal: controller.signal
    }, policy.allowedHosts, policy.fetchImpl);
    if (!response.ok || !response.body) throw new Error(`Feed returned HTTP ${response.status}`);
    const declared = Number(response.headers.get("content-length") || 0);
    if (declared > policy.maxBytes) throw new Error("Feed file exceeds the configured size limit");
    let received = 0;
    const limiter = new Transform({
      transform(chunk, _encoding, callback) {
        received += chunk.length;
        if (received > policy.maxBytes) callback(new Error("Feed file exceeds the configured size limit"));
        else {
          policy.onProgress?.({ phase: "download", received, total: declared || null });
          callback(null, chunk);
        }
      }
    });
    await pipeline(
      Readable.fromWeb(response.body),
      limiter,
      fs.createWriteStream(temporary, { flags: "wx", mode: 0o600 })
    );
    await fsp.rm(destination, { force: true });
    await fsp.rename(temporary, destination);
    return { bytes: received, etag: response.headers.get("etag"), modified: response.headers.get("last-modified") };
  } catch (error) {
    await fsp.rm(temporary, { force: true });
    if (error.name === "AbortError") throw new Error("Feed download timed out");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function parseClamHashLine(line) {
  const value = line.trim();
  if (!value || value.startsWith("#")) return null;
  const [hash, sizeText, name] = value.split(":");
  if (!name || !/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(hash)) return null;
  const algorithm = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : "sha256";
  const size = sizeText === "*" ? -1 : Number(sizeText);
  if (!Number.isSafeInteger(size) || size < -1) return null;
  return {
    algorithm,
    hash: hash.toLowerCase(),
    size,
    name,
    source: "clamav",
    severity: "critical",
    confirmed: true,
    details: null
  };
}

async function verifyCvdIntegrity(file) {
  const handle = await fsp.open(file, "r");
  const headerBuffer = Buffer.alloc(512);
  try {
    const { bytesRead } = await handle.read(headerBuffer, 0, 512, 0);
    if (bytesRead !== 512) throw new Error("ClamAV CVD is truncated");
  } finally {
    await handle.close();
  }
  const header = headerBuffer.toString("ascii").replace(/\0.*$/s, "").trim();
  const fields = header.split(":");
  if (fields[0] !== "ClamAV-VDB" || !/^[a-f0-9]{32}$/i.test(fields[5] || "")) {
    throw new Error("ClamAV CVD header is invalid");
  }
  const digest = crypto.createHash("md5");
  await pipeline(fs.createReadStream(file, { start: 512 }), new Transform({
    transform(chunk, _encoding, callback) {
      digest.update(chunk);
      callback();
    }
  }));
  const actual = digest.digest("hex");
  if (actual !== fields[5].toLowerCase()) throw new Error("ClamAV CVD integrity checksum failed");
  return { version: fields[2], declaredSignatures: Number(fields[3]), builder: fields[7], header };
}

export async function parseClamCvd(file, onSignature, onProgress = () => {}) {
  const info = await verifyCvdIntegrity(file);
  const input = fs.createReadStream(file, { start: 512 }).pipe(createGunzip());
  let buffer = Buffer.alloc(0);
  let state = { mode: "header" };
  let imported = 0;
  let processedBytes = 0;

  function consumeText(chunk, final = false) {
    const text = `${state.textRemainder || ""}${chunk.toString("utf8")}`;
    const lines = text.split(/\r?\n/);
    state.textRemainder = final ? "" : lines.pop();
    for (const line of lines) {
      const entry = parseClamHashLine(line);
      if (entry) {
        onSignature(entry);
        imported += 1;
        if (imported % 10000 === 0) onProgress({ phase: "index", imported, file: path.basename(file) });
      }
    }
    if (final && state.textRemainder) {
      const entry = parseClamHashLine(state.textRemainder);
      if (entry) {
        onSignature(entry);
        imported += 1;
      }
    }
  }

  for await (const chunk of input) {
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
    while (buffer.length) {
      if (state.mode === "header") {
        if (buffer.length < 512) break;
        const header = buffer.subarray(0, 512);
        buffer = buffer.subarray(512);
        if (header.every((byte) => byte === 0)) {
          buffer = Buffer.alloc(0);
          break;
        }
        const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/s, "");
        const sizeText = header.subarray(124, 136).toString("ascii").replace(/\0.*$/s, "").trim();
        const size = Number.parseInt(sizeText || "0", 8);
        if (!Number.isSafeInteger(size) || size < 0) throw new Error("Invalid TAR entry in ClamAV CVD");
        state = {
          mode: "file",
          name,
          remaining: size,
          padding: (512 - (size % 512)) % 512,
          target: /\.(?:hdb|hsb|hdu|hsu)$/i.test(name),
          textRemainder: ""
        };
        if (size === 0) state.mode = state.padding ? "padding" : "header";
      } else if (state.mode === "file") {
        const take = Math.min(state.remaining, buffer.length);
        const portion = buffer.subarray(0, take);
        buffer = buffer.subarray(take);
        state.remaining -= take;
        processedBytes += take;
        if (state.target) consumeText(portion);
        if (state.remaining === 0) {
          if (state.target) consumeText(Buffer.alloc(0), true);
          state.mode = state.padding ? "padding" : "header";
        }
      } else {
        const take = Math.min(state.padding, buffer.length);
        buffer = buffer.subarray(take);
        state.padding -= take;
        if (state.padding === 0) state = { mode: "header" };
      }
    }
  }
  if (state.mode === "file" && state.remaining) throw new Error("ClamAV CVD archive is truncated");
  return { ...info, imported, processedBytes };
}

export function malwareBazaarEntries(payload) {
  if (payload.query_status !== "ok" || !Array.isArray(payload.data)) {
    throw new Error(`MalwareBazaar response was not usable: ${payload.query_status || "unknown"}`);
  }
  const entries = [];
  for (const item of payload.data) {
    const name = `MalwareBazaar.${item.signature || "KnownMalware"}`;
    for (const [algorithm, field] of [["sha256", "sha256_hash"], ["sha1", "sha1_hash"], ["md5", "md5_hash"]]) {
      const hash = item[field];
      const length = algorithm === "sha256" ? 64 : algorithm === "sha1" ? 40 : 32;
      if (typeof hash === "string" && new RegExp(`^[a-f0-9]{${length}}$`, "i").test(hash)) {
        entries.push({
          algorithm,
          hash: hash.toLowerCase(),
          size: Number.isSafeInteger(Number(item.file_size)) ? Number(item.file_size) : -1,
          name,
          source: "malwarebazaar",
          severity: "critical",
          confirmed: true,
          details: { firstSeen: item.first_seen || null, fileType: item.file_type || null }
        });
      }
    }
  }
  return entries;
}

export function urlhausEntries(payload) {
  if (payload.query_status !== "ok" || !Array.isArray(payload.payloads)) {
    throw new Error(`URLhaus response was not usable: ${payload.query_status || "unknown"}`);
  }
  const entries = [];
  for (const item of payload.payloads) {
    for (const [algorithm, field] of [["sha256", "sha256_hash"], ["md5", "md5_hash"]]) {
      const hash = item[field];
      const length = algorithm === "sha256" ? 64 : 32;
      if (typeof hash === "string" && new RegExp(`^[a-f0-9]{${length}}$`, "i").test(hash)) {
        entries.push({
          algorithm,
          hash: hash.toLowerCase(),
          size: Number.isSafeInteger(Number(item.response_size ?? item.file_size))
            ? Number(item.response_size ?? item.file_size) : -1,
          name: `URLhaus.${item.signature || "ObservedPayload"}`,
          source: "urlhaus",
          severity: "high",
          confirmed: false,
          details: { firstSeen: item.firstseen || null, fileType: item.file_type || null }
        });
      }
    }
  }
  return entries;
}

export function feodoTrackerEntries(payload) {
  if (!Array.isArray(payload)) throw new Error("Feodo Tracker response was not a JSON array");
  const iocs = [];
  for (const item of payload) {
    if (typeof item.ip_address !== "string" || !isIP(item.ip_address)) continue;
    iocs.push({
      type: isIP(item.ip_address) === 6 ? "ipv6" : "ipv4",
      value: item.ip_address.toLowerCase(),
      source: "feodotracker",
      name: `FeodoTracker.${item.malware || "BotnetC2"}`,
      confidence: item.status === "online" ? 100 : 80,
      firstSeen: item.first_seen || null,
      lastSeen: item.last_online || null,
      details: {
        port: Number.isInteger(Number(item.port)) ? Number(item.port) : null,
        status: item.status || null,
        hostname: item.hostname || null,
        country: item.country || null,
        asNumber: item.as_number || null,
        asName: item.as_name || null
      }
    });
  }
  return { hashes: [], iocs };
}

function threatFoxHash(ioc) {
  if (/^[a-f0-9]{32}$/i.test(ioc)) return "md5";
  if (/^[a-f0-9]{40}$/i.test(ioc)) return "sha1";
  if (/^[a-f0-9]{64}$/i.test(ioc)) return "sha256";
  return null;
}

export function threatFoxEntries(payload) {
  if (payload.query_status !== "ok" || !Array.isArray(payload.data)) {
    throw new Error(`ThreatFox response was not usable: ${payload.query_status || "unknown"}`);
  }
  const hashes = [];
  const iocs = [];
  for (const item of payload.data) {
    if (typeof item.ioc !== "string") continue;
    const value = item.ioc.trim();
    const name = `ThreatFox.${item.malware_printable || item.malware || "KnownIOC"}`;
    const details = {
      threatType: item.threat_type || null,
      iocType: item.ioc_type || null,
      confidence: Number(item.confidence_level) || 0,
      firstSeen: item.first_seen || null,
      lastSeen: item.last_seen || null,
      tags: Array.isArray(item.tags) ? item.tags.slice(0, 50) : []
    };
    const algorithm = threatFoxHash(value);
    if (algorithm) {
      hashes.push({
        algorithm,
        hash: value.toLowerCase(),
        size: -1,
        name,
        source: "threatfox",
        severity: "critical",
        confirmed: true,
        details
      });
      continue;
    }
    let type = item.ioc_type || "unknown";
    let normalized = value;
    if (type === "domain") normalized = value.toLowerCase();
    else if (type === "ip:port") {
      const index = value.lastIndexOf(":");
      const host = index > 0 ? value.slice(0, index).replace(/^\[|\]$/g, "") : "";
      if (!isIP(host)) continue;
    } else if (type.includes("ip") && !isIP(value)) continue;
    else if (type === "url") {
      try {
        const url = new URL(value);
        if (!["http:", "https:"].includes(url.protocol)) continue;
        normalized = url.toString();
      } catch {
        continue;
      }
    }
    iocs.push({
      type,
      value: normalized,
      source: "threatfox",
      name,
      confidence: Number(item.confidence_level) || null,
      firstSeen: item.first_seen || null,
      lastSeen: item.last_seen || null,
      details
    });
  }
  return { hashes, iocs };
}

export async function downloadClamDatabases(config, onProgress, fetchImpl) {
  const directory = appPaths().threatArtifacts;
  await ensureDirectory(directory);
  const executable = await findClamExecutable("freshclam");
  if (!executable) {
    throw new Error("ClamAV freshclam is required. Install the official Cisco.ClamAV package, then retry");
  }
  const configFile = path.join(path.dirname(directory), "freshclam.conf");
  const logFile = path.join(path.dirname(directory), "freshclam.log");
  await fsp.writeFile(configFile, [
    "DatabaseMirror database.clamav.net",
    "ScriptedUpdates no",
    "Checks 1",
    `UpdateLogFile ${logFile.replaceAll("\\", "/")}`,
    "LogTime yes",
    ""
  ].join("\n"), { encoding: "utf8", mode: 0o600 });
  const commandEnvironment = { ...process.env };
  if (process.platform === "win32") {
    const caBundle = path.join(path.dirname(directory), "windows-trusted-roots.pem");
    onProgress({
      source: "clamav",
      phase: "download",
      message: "Exporting Windows trusted roots for FreshClam HTTPS verification"
    });
    const rootCount = await exportWindowsTrustedRoots(caBundle);
    commandEnvironment.CURL_CA_BUNDLE = caBundle;
    onProgress({
      source: "clamav",
      phase: "download",
      message: `FreshClam will verify HTTPS with ${rootCount} Windows trusted root certificates`
    });
  }
  onProgress({ source: "clamav", phase: "download", message: "Running the official freshclam updater" });
  const output = await runClamCommand(executable, [
    `--config-file=${configFile}`,
    `--datadir=${directory}`,
    "--stdout",
    "--show-progress",
    "--update-db=main",
    "--update-db=daily"
  ], Math.max(config.requestTimeoutMs, 10 * 60 * 1000), (line) => {
    onProgress({ source: "clamav", phase: "download", message: line.slice(0, 220) });
  }, { env: commandEnvironment });
  const artifacts = [];
  for (const database of ["main", "daily"]) {
    const destination = path.join(directory, `${database}.cvd`);
    let stat;
    try {
      stat = await fsp.stat(destination);
    } catch {
      throw new Error(`freshclam completed but did not create ${database}.cvd`);
    }
    artifacts.push({
      database,
      file: destination,
      download: { bytes: stat.size, etag: null, modified: stat.mtime.toISOString(), updater: "freshclam", output: output.slice(-2000) }
    });
  }
  return artifacts;
}

export async function exportWindowsTrustedRoots(destination) {
  if (process.platform !== "win32") return 0;
  await ensureDirectory(path.dirname(destination));
  const powershell = path.join(
    process.env.WINDIR || "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
  );
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$unique = @{}",
    "foreach ($location in @('LocalMachine', 'CurrentUser')) {",
    "  $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', $location)",
    "  try {",
    "    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)",
    "    foreach ($cert in $store.Certificates) { $unique[$cert.Thumbprint] = $cert }",
    "  } finally { $store.Close() }",
    "}",
    "$certs = @($unique.Values)",
    "$builder = New-Object Text.StringBuilder",
    "foreach ($cert in $certs) {",
    "  [void]$builder.AppendLine('-----BEGIN CERTIFICATE-----')",
    "  [void]$builder.AppendLine([Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks))",
    "  [void]$builder.AppendLine('-----END CERTIFICATE-----')",
    "}",
    "[IO.File]::WriteAllText($env:SENTRYLOOM_CA_BUNDLE_PATH, $builder.ToString(), (New-Object Text.UTF8Encoding($false)))",
    "[Console]::Out.Write($certs.Count)"
  ].join("; ");
  const result = await runProcess(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-WindowStyle",
    "Hidden",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script
  ], 30000, {
    ...process.env,
    SENTRYLOOM_CA_BUNDLE_PATH: destination
  });
  const count = Number(result.trim());
  if (!Number.isInteger(count) || count < 1) {
    throw new Error("Windows did not provide any trusted root certificates for FreshClam");
  }
  await fsp.chmod(destination, 0o600).catch(() => {});
  return count;
}

export async function findClamExecutable(tool) {
  const executable = process.platform === "win32" ? `${tool}.exe` : tool;
  const candidates = process.platform === "win32"
    ? [
        path.join(process.env.ProgramFiles || "C:\\Program Files", "ClamAV", executable),
        path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "ClamAV", executable)
      ]
    : [executable, `/usr/bin/${executable}`, `/usr/local/bin/${executable}`];
  for (const candidate of candidates) {
    try {
      await fsp.access(candidate, fs.constants.X_OK);
      return candidate;
    } catch {}
  }
  return null;
}

function runProcess(executable, args, timeoutMs, environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: environment
    });
    let output = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`Process timed out: ${path.basename(executable)}`));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => { output = `${output}${chunk}`.slice(-1024 * 1024); });
    child.stderr.on("data", (chunk) => { output = `${output}${chunk}`.slice(-1024 * 1024); });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (code === 0) resolve(output);
      else reject(new Error(`${path.basename(executable)} failed with exit code ${code}: ${output.slice(-2000)}`));
    });
  });
}

async function runClamCommand(executable, args, timeoutMs, onLine, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: options.env || process.env
    });
    let output = "";
    let pending = "";
    let lastLine = "";
    let lastProgressAt = 0;
    const emitLine = (line) => {
      const clean = line.trim();
      if (!clean || clean === lastLine) return;
      const isProgress = clean.startsWith("Time:");
      if (isProgress && Date.now() - lastProgressAt < 500) return;
      if (isProgress) lastProgressAt = Date.now();
      lastLine = clean;
      onLine(clean);
    };
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("freshclam update timed out"));
    }, timeoutMs);
    const consume = (chunk) => {
      output = `${output}${chunk}`.slice(-1024 * 1024);
      pending += chunk;
      const lines = pending.split(/[\r\n]+/);
      pending = lines.pop() || "";
      for (const line of lines) emitLine(line);
    };
    child.stdout.on("data", (chunk) => consume(chunk.toString("utf8")));
    child.stderr.on("data", (chunk) => consume(chunk.toString("utf8")));
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (pending) emitLine(pending);
      if (code === 0) resolve(output);
      else if (/(?:error 60|download failed \\(60\\)|ssl peer certificate)/i.test(output)) {
        reject(new Error(
          "FreshClam could not validate the ClamAV HTTPS certificate. " +
          "SentryLoom exported the Windows trusted roots, so verify the Windows date/time, " +
          "corporate TLS inspection certificate, and trusted-root policy before retrying."
        ));
      } else {
        reject(new Error(`freshclam failed with exit code ${code}: ${output.slice(-1000)}`));
      }
    });
  });
}

export async function fetchMalwareBazaar(config, authKey, fetchImpl) {
  const body = new URLSearchParams({ query: "recent_detections", hours: "168" });
  return fetchJsonFeed("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: {
      "Auth-Key": authKey,
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": `SentryLoom/${APP_VERSION}`
    },
    body,
    signal: AbortSignal.timeout(config.requestTimeoutMs)
  }, { allowedHosts: SOURCE_HOSTS.malwarebazaar, maxBytes: 50 * 1024 * 1024, fetchImpl });
}

export async function fetchUrlhaus(config, authKey, fetchImpl) {
  return fetchJsonFeed("https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/", {
    method: "GET",
    headers: { "Auth-Key": authKey, "User-Agent": `SentryLoom/${APP_VERSION}` },
    signal: AbortSignal.timeout(config.requestTimeoutMs)
  }, { allowedHosts: SOURCE_HOSTS.urlhaus, maxBytes: 50 * 1024 * 1024, fetchImpl });
}

export async function fetchFeodoTracker(config, fetchImpl) {
  return fetchJsonFeed("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", {
    method: "GET",
    headers: { "User-Agent": `SentryLoom/${APP_VERSION}` },
    signal: AbortSignal.timeout(config.requestTimeoutMs)
  }, { allowedHosts: SOURCE_HOSTS.feodotracker, maxBytes: 10 * 1024 * 1024, fetchImpl });
}

export async function fetchThreatFox(config, authKey, fetchImpl) {
  return fetchJsonFeed("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: {
      "Auth-Key": authKey,
      "Content-Type": "application/json",
      "User-Agent": `SentryLoom/${APP_VERSION}`
    },
    body: JSON.stringify({ query: "get_iocs", days: 7 }),
    signal: AbortSignal.timeout(config.requestTimeoutMs)
  }, { allowedHosts: SOURCE_HOSTS.threatfox, maxBytes: 100 * 1024 * 1024, fetchImpl });
}
