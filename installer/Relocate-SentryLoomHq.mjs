import crypto from "node:crypto";
import dgram from "node:dgram";
import fs from "node:fs/promises";
import https from "node:https";
import os from "node:os";
import path from "node:path";

const DISCOVERY_REQUEST = "SENTRYLOOM_HQ_DISCOVER_V1";
const MAGIC = Buffer.from("SLOOMHQ1", "ascii");
const dataDirectory = path.join(process.env.PROGRAMDATA || "", "SentryLoom");
const credentialFile = path.join(dataDirectory, "keys", "hq-credentials.enc");
const masterKeyFile = path.join(dataDirectory, "keys", "master.key");

function normalizeFingerprint(value) {
  return String(value || "").replace(/[^a-f0-9]/gi, "").toUpperCase();
}

function ipv4ToInteger(value) {
  const octets = String(value || "").split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) =>
    !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
  return octets.reduce((result, octet) => ((result << 8) | octet) >>> 0, 0);
}

function integerToIpv4(value) {
  const normalized = value >>> 0;
  return [
    (normalized >>> 24) & 255,
    (normalized >>> 16) & 255,
    (normalized >>> 8) & 255,
    normalized & 255
  ].join(".");
}

function broadcastAddresses() {
  const addresses = new Set(["255.255.255.255", "127.0.0.1"]);
  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if ((entry.family !== "IPv4" && entry.family !== 4) || entry.internal) continue;
      const address = ipv4ToInteger(entry.address);
      const netmask = ipv4ToInteger(entry.netmask);
      if (address === null || netmask === null) continue;
      addresses.add(integerToIpv4(((address & netmask) | (~netmask >>> 0)) >>> 0));
    }
  }
  return [...addresses];
}

async function decryptCredentials() {
  const [payload, key] = await Promise.all([
    fs.readFile(credentialFile),
    fs.readFile(masterKeyFile)
  ]);
  if (key.length !== 32 || payload.length < MAGIC.length + 28 ||
      !payload.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("The stored HQ credential is invalid");
  }
  const offset = MAGIC.length;
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    payload.subarray(offset, offset + 12)
  );
  decipher.setAuthTag(payload.subarray(offset + 12, offset + 28));
  return JSON.parse(Buffer.concat([
    decipher.update(payload.subarray(offset + 28)),
    decipher.final()
  ]).toString("utf8"));
}

async function saveCredentials(credentials) {
  const key = await fs.readFile(masterKeyFile);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(credentials), "utf8"),
    cipher.final()
  ]);
  const payload = Buffer.concat([MAGIC, iv, cipher.getAuthTag(), encrypted]);
  const temporary = `${credentialFile}.${process.pid}.tmp`;
  await fs.writeFile(temporary, payload, { mode: 0o600, flag: "wx" });
  await fs.rename(temporary, credentialFile);
}

function requestJson(serverUrl, route, credentials) {
  const url = new URL(route, `${serverUrl}/`);
  const expectedFingerprint = normalizeFingerprint(credentials.fingerprint256);
  return new Promise((resolve, reject) => {
    const request = https.request(url, {
      method: "GET",
      timeout: 5000,
      rejectUnauthorized: false,
      headers: credentials.token ? {
        Accept: "application/json",
        Authorization: `Bearer ${credentials.token}`,
        "X-SentryLoom-Device": credentials.deviceId
      } : { Accept: "application/json" }
    }, (response) => {
      const presented = normalizeFingerprint(
        response.socket?.getPeerCertificate?.()?.fingerprint256
      );
      if (!presented || presented !== expectedFingerprint) {
        response.resume();
        reject(new Error("HQ certificate fingerprint mismatch"));
        return;
      }
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        let body = {};
        try {
          body = chunks.length
            ? JSON.parse(Buffer.concat(chunks).toString("utf8"))
            : {};
        } catch {
          reject(new Error("HQ returned invalid JSON"));
          return;
        }
        resolve({ status: response.statusCode, body, fingerprint256: presented });
      });
    });
    request.on("timeout", () => request.destroy(new Error("HQ request timed out")));
    request.on("error", reject);
    request.end();
  });
}

async function authenticateAt(serverUrl, credentials) {
  const normalizedUrl = new URL(serverUrl);
  if (normalizedUrl.protocol !== "https:") throw new Error("HQ must use HTTPS");
  normalizedUrl.pathname = "";
  normalizedUrl.search = "";
  normalizedUrl.hash = "";
  const target = normalizedUrl.toString().replace(/\/$/, "");
  const identity = await requestJson(target, "/api/v1/hq", {
    fingerprint256: credentials.fingerprint256
  });
  if (identity.status < 200 || identity.status >= 300 ||
      normalizeFingerprint(identity.body.fingerprint256) !==
        normalizeFingerprint(credentials.fingerprint256)) {
    throw new Error("HQ identity verification failed");
  }
  const session = await requestJson(target, "/api/v1/device/session", credentials);
  const authenticated = session.status >= 200 && session.status < 300;
  const authenticatedLegacyRoute =
    session.status === 404 && session.body.error === "Device API route not found";
  if (!authenticated && !authenticatedLegacyRoute) {
    throw new Error(session.body.error || "HQ device authentication failed");
  }
  return {
    ...credentials,
    serverUrl: target,
    hqName: String(identity.body.name || credentials.hqName || "SentryLoom HQ"),
    fingerprint256: identity.fingerprint256
  };
}

function discoverHqServers(timeoutMs = 2500) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    const servers = new Map();
    const timers = [];
    const finish = () => {
      for (const timer of timers) clearTimeout(timer);
      socket.close(() => resolve([...servers.values()]));
    };
    socket.on("error", reject);
    socket.on("message", (message, remote) => {
      try {
        const response = JSON.parse(message.toString("utf8"));
        if (response.protocol !== "sentryloom-hq/1") return;
        const url = new URL(String(response.url));
        url.hostname = remote.address;
        servers.set(`${url.origin}|${response.fingerprint256}`, {
          url: url.origin,
          fingerprint256: normalizeFingerprint(response.fingerprint256)
        });
      } catch {}
    });
    socket.bind(0, "0.0.0.0", () => {
      socket.setBroadcast(true);
      const payload = Buffer.from(DISCOVERY_REQUEST, "utf8");
      const send = () => {
        for (const address of broadcastAddresses()) {
          socket.send(payload, 32110, address, () => {});
        }
      };
      send();
      timers.push(setTimeout(send, Math.floor(timeoutMs / 2)));
      timers.push(setTimeout(finish, timeoutMs));
    });
  });
}

async function main() {
  if (!process.env.PROGRAMDATA) return;
  const config = JSON.parse(await fs.readFile(
    path.join(dataDirectory, "config.json"),
    "utf8"
  ));
  if (!config.management?.enabled) return;
  const credentials = await decryptCredentials();
  try {
    await authenticateAt(credentials.serverUrl, credentials);
    return;
  } catch {}

  const candidates = [];
  if (process.env.SENTRYLOOM_HQ_URL?.trim()) {
    candidates.push({ url: process.env.SENTRYLOOM_HQ_URL.trim() });
  }
  candidates.push(...await discoverHqServers());
  const expectedFingerprint = normalizeFingerprint(credentials.fingerprint256);
  for (const candidate of candidates) {
    if (candidate.fingerprint256 &&
        candidate.fingerprint256 !== expectedFingerprint) continue;
    try {
      const relocated = await authenticateAt(candidate.url, credentials);
      if (relocated.serverUrl === credentials.serverUrl) return;
      await saveCredentials(relocated);
      process.stdout.write(`Relocated enrolled HQ to ${relocated.serverUrl}\n`);
      return;
    } catch {}
  }
}

main().catch((error) => {
  process.stderr.write(`HQ relocation bootstrap skipped: ${error.message}\n`);
});
