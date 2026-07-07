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
  },
  "spamhaus-drop": {
    id: "spamhaus-drop",
    name: "Spamhaus DROP",
    requiresAuth: false,
    homepage: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
    description: "IPv4 and IPv6 netblocks controlled by criminal operations"
  },
  "misp-circl": {
    id: "misp-circl",
    name: "CIRCL MISP OSINT",
    requiresAuth: false,
    homepage: "https://www.misp-project.org/communities/",
    description: "Recent public MISP events from CIRCL"
  },
  "misp-botvrij": {
    id: "misp-botvrij",
    name: "Botvrij MISP OSINT",
    requiresAuth: false,
    homepage: "https://www.botvrij.eu/",
    description: "Recent public MISP events derived from public reporting"
  },
  lmd: {
    id: "lmd",
    name: "Linux Malware Detect",
    requiresAuth: false,
    homepage: "https://rfxn.com/projects/linux-malware-detect",
    description: "GPLv2 Linux-focused SHA-256 malware signatures"
  }
});

const SOURCE_HOSTS = Object.freeze({
  clamav: ["database.clamav.net", "download.clamav.net"],
  malwarebazaar: ["mb-api.abuse.ch"],
  urlhaus: ["urlhaus-api.abuse.ch"],
  feodotracker: ["feodotracker.abuse.ch"],
  threatfox: ["threatfox-api.abuse.ch"],
  "spamhaus-drop": ["www.spamhaus.org"],
  "misp-circl": ["www.circl.lu"],
  "misp-botvrij": ["www.botvrij.eu"],
  lmd: ["cdn.rfxn.com"]
});

const MISP_FEEDS = Object.freeze({
  "misp-circl": "https://www.circl.lu/doc/misp/feed-osint/",
  "misp-botvrij": "https://www.botvrij.eu/data/feed-osint/"
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
  const text = await fetchTextFeed(url, options, policy);
  return JSON.parse(text);
}

export async function fetchTextFeed(url, options, policy) {
  const response = await fetchPolicy(url, options, policy.allowedHosts, policy.fetchImpl);
  if (!response.ok) throw new Error(`Feed returned HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > policy.maxBytes) throw new Error("Feed response exceeds the configured size limit");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > policy.maxBytes) throw new Error("Feed response exceeds the configured size limit");
  return bytes.toString("utf8");
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

export function spamhausDropEntries(text) {
  const byRange = new Map();
  const metadata = { records: 0, size: 0, timestamp: 0, terms: null, copyright: null };
  for (const line of String(text || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    let item;
    try { item = JSON.parse(line); } catch { continue; }
    if (item.type === "metadata") {
      metadata.records += Number(item.records) || 0;
      metadata.size += Number(item.size) || 0;
      metadata.timestamp = Math.max(metadata.timestamp, Number(item.timestamp) || 0);
      metadata.terms ||= item.terms || null;
      metadata.copyright ||= item.copyright || null;
      continue;
    }
    if (typeof item.cidr !== "string") continue;
    const [address, prefixText] = item.cidr.split("/");
    const family = isIP(address);
    const prefix = Number(prefixText);
    if (!family || !Number.isInteger(prefix) ||
        prefix < 0 || prefix > (family === 4 ? 32 : 128)) continue;
    const type = family === 4 ? "ipv4-cidr" : "ipv6-cidr";
    const value = `${address.toLowerCase()}/${prefix}`;
    const existing = byRange.get(`${type}|${value}`);
    if (existing) {
      if (item.sblid && !existing.details.sblIds.includes(item.sblid)) {
        existing.details.sblIds.push(item.sblid);
      }
      continue;
    }
    byRange.set(`${type}|${value}`, {
      type,
      value,
      source: "spamhaus-drop",
      name: `Spamhaus.DROP.${item.sblid || "ListedNetblock"}`,
      confidence: 100,
      firstSeen: null,
      lastSeen: null,
      details: {
        sblId: item.sblid || null,
        sblIds: item.sblid ? [item.sblid] : [],
        rir: item.rir || null,
        advisory: "drop-all-traffic"
      }
    });
  }
  return { hashes: [], iocs: [...byRange.values()], metadata };
}

function mispAttributes(event) {
  const root = event?.Event || event || {};
  const attributes = Array.isArray(root.Attribute) ? [...root.Attribute] : [];
  for (const object of Array.isArray(root.Object) ? root.Object : []) {
    if (Array.isArray(object.Attribute)) attributes.push(...object.Attribute);
  }
  return { root, attributes };
}

function mispHashEntry(algorithm, hash, name, source, details) {
  const lengths = { md5: 32, sha1: 40, sha256: 64 };
  if (!new RegExp(`^[a-f0-9]{${lengths[algorithm]}}$`, "i").test(hash)) return null;
  return {
    algorithm,
    hash: hash.toLowerCase(),
    size: -1,
    name,
    source,
    severity: "critical",
    confirmed: true,
    details
  };
}

function mispNetworkEntries(type, value, source, name, confidence, details) {
  const entries = [];
  const addIp = (address) => {
    const family = isIP(address);
    if (!family) return;
    entries.push({
      type: family === 6 ? "ipv6" : "ipv4",
      value: address.toLowerCase(),
      source, name, confidence,
      firstSeen: null, lastSeen: null, details
    });
  };
  if (["ip-src", "ip-dst"].includes(type)) {
    if (value.includes("/")) {
      const [address, prefixText] = value.split("/");
      const family = isIP(address);
      const prefix = Number(prefixText);
      if (family && Number.isInteger(prefix) &&
          prefix >= 0 && prefix <= (family === 4 ? 32 : 128)) {
        entries.push({
          type: family === 6 ? "ipv6-cidr" : "ipv4-cidr",
          value: `${address.toLowerCase()}/${prefix}`,
          source, name, confidence,
          firstSeen: null, lastSeen: null, details
        });
      }
    } else {
      addIp(value);
    }
  }
  else if (["domain", "hostname"].includes(type) && /^[a-z0-9._-]+$/i.test(value)) {
    entries.push({
      type: "domain",
      value: value.toLowerCase().replace(/\.$/, ""),
      source, name, confidence,
      firstSeen: null, lastSeen: null, details
    });
  } else if (["url", "uri"].includes(type)) {
    try {
      const url = new URL(value);
      if (["http:", "https:"].includes(url.protocol)) {
        entries.push({
          type: "url", value: url.toString(), source, name, confidence,
          firstSeen: null, lastSeen: null, details
        });
      }
    } catch {}
  } else if (type === "domain|ip") {
    const [domain, address] = value.split("|");
    entries.push(...mispNetworkEntries("domain", domain, source, name, confidence, details));
    addIp(address);
  } else if (["ip-src|port", "ip-dst|port"].includes(type)) {
    const [address, portText] = value.split("|");
    const family = isIP(address);
    const port = Number(portText);
    if (family && Number.isInteger(port) && port > 0 && port <= 65535) {
      entries.push({
        type: "ip:port",
        value: family === 6 ? `[${address.toLowerCase()}]:${port}` : `${address}:${port}`,
        source, name, confidence,
        firstSeen: null, lastSeen: null, details
      });
    }
  }
  return entries;
}

export function mispEntries(events, source) {
  if (!MISP_FEEDS[source]) throw new Error(`Unknown MISP feed source: ${source}`);
  const hashes = [];
  const iocs = [];
  for (const event of Array.isArray(events) ? events : []) {
    const { root, attributes } = mispAttributes(event);
    const threatLevel = Number(root.threat_level_id);
    const confidence = threatLevel === 1 ? 95 : threatLevel === 2 ? 80 : threatLevel === 3 ? 65 : 55;
    for (const attribute of attributes) {
      if (attribute?.to_ids !== true || attribute.deleted === true) continue;
      const type = String(attribute.type || "").toLowerCase();
      const value = String(attribute.value || "").trim();
      if (!value || value.length > 8192) continue;
      const details = {
        eventUuid: root.uuid || null,
        eventInfo: String(root.info || "").slice(0, 500) || null,
        eventDate: root.date || null,
        category: attribute.category || null,
        comment: String(attribute.comment || "").slice(0, 500) || null,
        attributeUuid: attribute.uuid || null,
        tags: [
          ...(Array.isArray(root.Tag) ? root.Tag : []),
          ...(Array.isArray(attribute.Tag) ? attribute.Tag : [])
        ].map((tag) => String(tag?.name || tag).slice(0, 120)).filter(Boolean).slice(0, 30)
      };
      const name = `MISP.${String(root.info || type || "IOC").replace(/[^\w.-]+/g, "_").slice(0, 120)}`;
      if (["md5", "sha1", "sha256"].includes(type)) {
        const entry = mispHashEntry(type, value, name, source, details);
        if (entry) hashes.push(entry);
        continue;
      }
      const compound = type.match(/^(?:filename|malware-sample)\|(md5|sha1|sha256)$/);
      if (compound) {
        const hash = value.slice(value.lastIndexOf("|") + 1);
        const entry = mispHashEntry(compound[1], hash, name, source, details);
        if (entry) hashes.push(entry);
        continue;
      }
      iocs.push(...mispNetworkEntries(type, value, source, name, confidence, details));
    }
  }
  return { hashes, iocs };
}

export function linuxMalwareDetectEntries(text) {
  const entries = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const match = line.trim().match(/^([a-f0-9]{64}):(\d+):\{SHA256\}(.+)$/i);
    if (!match) continue;
    const size = Number(match[2]);
    if (!Number.isSafeInteger(size) || size < 0) continue;
    entries.push({
      algorithm: "sha256",
      hash: match[1].toLowerCase(),
      size,
      name: `LMD.${match[3].slice(0, 240)}`,
      source: "lmd",
      severity: "critical",
      confirmed: true,
      details: { platformFocus: "linux", signatureFormat: "LMD SHA256 v2" }
    });
  }
  return entries;
}

function tarHeaderChecksum(header) {
  const expected = Number.parseInt(
    header.subarray(148, 156).toString("ascii").replace(/\0.*$/s, "").trim() || "0",
    8
  );
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (!Number.isSafeInteger(expected) || expected !== actual) {
    throw new Error("TAR entry checksum is invalid");
  }
}

export async function extractTarTextFiles(file, requestedNames, maximumBytes = 32 * 1024 * 1024) {
  const requested = new Set(requestedNames);
  const found = new Map();
  const input = fs.createReadStream(file).pipe(createGunzip());
  let buffer = Buffer.alloc(0);
  let state = { mode: "header" };

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
        tarHeaderChecksum(header);
        const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/s, "");
        const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*$/s, "");
        const fullName = prefix ? `${prefix}/${name}` : name;
        const size = Number.parseInt(
          header.subarray(124, 136).toString("ascii").replace(/\0.*$/s, "").trim() || "0",
          8
        );
        if (!Number.isSafeInteger(size) || size < 0) throw new Error("TAR entry size is invalid");
        const target = requested.has(fullName);
        if (target && size > maximumBytes) throw new Error(`TAR entry is too large: ${fullName}`);
        state = {
          mode: "file",
          name: fullName,
          remaining: size,
          padding: (512 - (size % 512)) % 512,
          target,
          chunks: []
        };
        if (size === 0) {
          if (target) found.set(fullName, "");
          state.mode = state.padding ? "padding" : "header";
        }
      } else if (state.mode === "file") {
        const take = Math.min(state.remaining, buffer.length);
        const portion = buffer.subarray(0, take);
        buffer = buffer.subarray(take);
        state.remaining -= take;
        if (state.target) state.chunks.push(portion);
        if (state.remaining === 0) {
          if (state.target) found.set(state.name, Buffer.concat(state.chunks).toString("utf8"));
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
  if (state.mode === "file" && state.remaining) throw new Error("TAR archive is truncated");
  for (const name of requested) {
    if (!found.has(name)) throw new Error(`TAR archive does not contain ${name}`);
  }
  return found;
}

export async function fetchSpamhausDrop(config, fetchImpl) {
  const options = {
    method: "GET",
    headers: { "User-Agent": `SentryLoom/${APP_VERSION}` },
    signal: AbortSignal.timeout(config.requestTimeoutMs)
  };
  const policy = {
    allowedHosts: SOURCE_HOSTS["spamhaus-drop"],
    maxBytes: 10 * 1024 * 1024,
    fetchImpl
  };
  const [ipv4, ipv6] = await Promise.all([
    fetchTextFeed("https://www.spamhaus.org/drop/drop_v4.json", options, policy),
    fetchTextFeed("https://www.spamhaus.org/drop/drop_v6.json", options, policy)
  ]);
  return `${ipv4}\n${ipv6}`;
}

function mispManifestTimestamp(item) {
  const numeric = Number(item?.publish_timestamp || item?.timestamp);
  if (Number.isFinite(numeric) && numeric > 0) return numeric * 1000;
  const parsed = Date.parse(item?.date || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

export async function fetchMispOsint(
  config,
  source,
  fetchImpl,
  maximumEvents = 20,
  onProgress = () => {}
) {
  const base = MISP_FEEDS[source];
  if (!base) throw new Error(`Unknown MISP feed source: ${source}`);
  const policy = { allowedHosts: SOURCE_HOSTS[source], maxBytes: 20 * 1024 * 1024, fetchImpl };
  const get = (url) => fetchJsonFeed(url, {
    method: "GET",
    headers: { "User-Agent": `SentryLoom/${APP_VERSION}` },
    signal: AbortSignal.timeout(config.requestTimeoutMs)
  }, policy);
  const manifest = await get(`${base}manifest.json`);
  const selected = Object.entries(manifest)
    .filter(([uuid]) => /^[a-f0-9-]{36}$/i.test(uuid))
    .sort((left, right) => mispManifestTimestamp(right[1]) - mispManifestTimestamp(left[1]))
    .slice(0, Math.max(1, Math.min(50, maximumEvents)));
  const events = [];
  for (let index = 0; index < selected.length; index += 1) {
    const [uuid] = selected[index];
    onProgress({
      source,
      phase: "download",
      message: `Fetching MISP event ${index + 1} of ${selected.length}`,
      received: index + 1,
      total: selected.length
    });
    events.push(await get(`${base}${uuid}.json`));
  }
  return {
    events,
    manifestEntries: Object.keys(manifest).length,
    fetchedEvents: events.length,
    newestTimestamp: selected.length ? new Date(mispManifestTimestamp(selected[0][1])).toISOString() : null
  };
}

export async function downloadLinuxMalwareDetect(config, onProgress, fetchImpl) {
  const destination = path.join(appPaths().threatArtifacts, "maldet-sigpack.tgz");
  onProgress({ source: "lmd", phase: "download", message: "Downloading Linux Malware Detect signatures" });
  const download = await downloadFeedFile(
    "https://cdn.rfxn.com/downloads/maldet-sigpack.tgz",
    destination,
    {
      allowedHosts: SOURCE_HOSTS.lmd,
      maxBytes: 64 * 1024 * 1024,
      timeoutMs: Math.max(config.requestTimeoutMs, 120000),
      fetchImpl,
      onProgress
    }
  );
  const files = await extractTarTextFiles(destination, [
    "sigs/sha256v2.dat",
    "sigs/maldet.sigs.ver"
  ]);
  return {
    entries: linuxMalwareDetectEntries(files.get("sigs/sha256v2.dat")),
    version: files.get("sigs/maldet.sigs.ver").trim().slice(0, 100),
    download
  };
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
