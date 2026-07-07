import fs from "node:fs/promises";
import path from "node:path";
import { isIP } from "node:net";
import { appPaths } from "../constants.js";
import { ensureDirectory, fileExists } from "./fs-safe.js";
import { FEED_SOURCES } from "./threat-feeds.js";

let sqliteModule;

async function sqlite() {
  sqliteModule ||= await import("node:sqlite");
  return sqliteModule;
}

function ipNumber(value) {
  const family = isIP(value);
  if (family === 4) {
    const parts = value.split(".").map(Number);
    return {
      family,
      value: parts.reduce((result, part) => (result << 8n) | BigInt(part), 0n),
      bits: 32
    };
  }
  if (family !== 6) return null;
  let normalized = value.toLowerCase().split("%")[0];
  if (normalized.includes(".")) {
    const lastColon = normalized.lastIndexOf(":");
    const ipv4 = ipNumber(normalized.slice(lastColon + 1));
    if (!ipv4) return null;
    normalized = `${normalized.slice(0, lastColon)}:${Number(ipv4.value >> 16n).toString(16)}:${Number(ipv4.value & 0xffffn).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const groups = [...left, ...Array(missing).fill("0"), ...right];
  if (groups.length !== 8 || groups.some((part) => !/^[a-f0-9]{1,4}$/i.test(part))) return null;
  return {
    family,
    value: groups.reduce((result, part) => (result << 16n) | BigInt(`0x${part}`), 0n),
    bits: 128
  };
}

export function parseCidr(value) {
  const [address, prefixText] = String(value || "").split("/");
  const parsed = ipNumber(address);
  const prefix = Number(prefixText);
  if (!parsed || !Number.isInteger(prefix) || prefix < 0 || prefix > parsed.bits) return null;
  const hostBits = BigInt(parsed.bits - prefix);
  const mask = hostBits === BigInt(parsed.bits)
    ? 0n
    : ((1n << BigInt(parsed.bits)) - 1n) ^ ((1n << hostBits) - 1n);
  const start = parsed.value & mask;
  return {
    family: parsed.family,
    prefix,
    start,
    end: start + ((1n << hostBits) - 1n)
  };
}

export function cidrContains(cidr, address) {
  const range = typeof cidr === "string" ? parseCidr(cidr) : cidr;
  const parsed = ipNumber(String(address || "").split("%")[0]);
  return Boolean(
    range && parsed && range.family === parsed.family &&
    parsed.value >= range.start && parsed.value <= range.end
  );
}

export async function openThreatIndex(options = {}) {
  const file = options.file || appPaths().threatIndex;
  await ensureDirectory(path.dirname(file));
  const { DatabaseSync } = await sqlite();
  const database = new DatabaseSync(file);
  database.exec(`
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA busy_timeout=10000;
    CREATE TABLE IF NOT EXISTS threat_hashes (
      algorithm TEXT NOT NULL CHECK (algorithm IN ('md5', 'sha1', 'sha256')),
      hash TEXT NOT NULL,
      size INTEGER NOT NULL DEFAULT -1,
      name TEXT NOT NULL,
      source TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'high',
      confirmed INTEGER NOT NULL DEFAULT 0,
      details TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (algorithm, hash, size, source)
    );
    CREATE INDEX IF NOT EXISTS idx_threat_lookup ON threat_hashes (algorithm, hash, size);
    CREATE TABLE IF NOT EXISTS network_iocs (
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      source TEXT NOT NULL,
      name TEXT NOT NULL,
      confidence INTEGER,
      first_seen TEXT,
      last_seen TEXT,
      details TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (type, value, source)
    );
    CREATE INDEX IF NOT EXISTS idx_network_ioc_lookup ON network_iocs (type, value);
    CREATE TABLE IF NOT EXISTS feed_status (
      source TEXT PRIMARY KEY,
      state TEXT NOT NULL,
      last_attempt TEXT,
      last_success TEXT,
      version TEXT,
      entry_count INTEGER NOT NULL DEFAULT 0,
      last_import_count INTEGER NOT NULL DEFAULT 0,
      error TEXT,
      metadata TEXT
    );
  `);

  const lookupStatement = database.prepare(`
    SELECT algorithm, hash, size, name, source, severity, confirmed, details
    FROM threat_hashes
    WHERE algorithm = ? AND hash = ? AND (size = ? OR size = -1)
    LIMIT 20
  `);
  let cidrCache = [];
  let cidrCacheAt = 0;
  const refreshCidrCache = () => {
    if (Date.now() - cidrCacheAt < 60000) return;
    cidrCache = database.prepare(`
      SELECT type, value, source, name, confidence, first_seen, last_seen, details
      FROM network_iocs WHERE type IN ('ipv4-cidr', 'ipv6-cidr')
    `).all().flatMap((row) => {
      const range = parseCidr(row.value);
      return range ? [{ row, range }] : [];
    });
    cidrCacheAt = Date.now();
  };
  const mapIoc = (row) => ({
    ...row,
    details: row.details ? JSON.parse(row.details) : null
  });
  return {
    file,
    database,
    lookup(hashes, size) {
      const results = [];
      for (const algorithm of ["sha256", "sha1", "md5"]) {
        const hash = hashes[algorithm];
        if (hash) results.push(...lookupStatement.all(algorithm, hash.toLowerCase(), size));
      }
      return results.map((row) => ({
        ...row,
        confirmed: Boolean(row.confirmed),
        details: row.details ? JSON.parse(row.details) : null
      }));
    },
    lookupIoc(value) {
      const raw = String(value).trim();
      const exact = database.prepare(`
        SELECT type, value, source, name, confidence, first_seen, last_seen, details
        FROM network_iocs WHERE value = ? OR value = ? LIMIT 50
      `).all(raw, raw.toLowerCase());
      if (isIP(raw.split("%")[0])) {
        refreshCidrCache();
        exact.push(...cidrCache
          .filter(({ range }) => cidrContains(range, raw))
          .map(({ row }) => row));
      }
      const unique = new Map(exact.map((row) => [
        `${row.type}|${row.value}|${row.source}`,
        mapIoc(row)
      ]));
      return [...unique.values()].slice(0, 50);
    },
    lookupHashValue(value) {
      const hash = String(value).trim().toLowerCase();
      return database.prepare(`
        SELECT algorithm, hash, size, name, source, severity, confirmed, details
        FROM threat_hashes WHERE hash = ? LIMIT 50
      `).all(hash).map((row) => ({
        ...row,
        confirmed: Boolean(row.confirmed),
        details: row.details ? JSON.parse(row.details) : null
      }));
    },
    close() {
      database.close();
    }
  };
}

export async function threatIndexStatus() {
  const file = appPaths().threatIndex;
  const defaults = Object.keys(FEED_SOURCES).map((source) => ({
    source,
    state: "never",
    entryCount: 0,
    lastImportCount: 0,
    lastAttempt: null,
    lastSuccess: null,
    version: null,
    error: null,
    metadata: null
  }));
  if (!(await fileExists(file))) return { totalEntries: 0, hashEntries: 0, networkEntries: 0, feeds: defaults };
  const index = await openThreatIndex({ file });
  try {
    const hashEntries = Number(index.database.prepare("SELECT COUNT(*) AS count FROM threat_hashes").get().count);
    const networkEntries = Number(index.database.prepare("SELECT COUNT(*) AS count FROM network_iocs").get().count);
    const rows = index.database.prepare(`
      SELECT source, state, last_attempt, last_success, version, entry_count, last_import_count, error, metadata
      FROM feed_status
    `).all();
    const bySource = new Map(rows.map((row) => [row.source, row]));
    return {
      totalEntries: hashEntries + networkEntries,
      hashEntries,
      networkEntries,
      feeds: defaults.map((fallback) => {
        const row = bySource.get(fallback.source);
        return row ? {
          source: row.source,
          state: row.state,
          entryCount: Number(row.entry_count),
          lastImportCount: Number(row.last_import_count),
          lastAttempt: row.last_attempt,
          lastSuccess: row.last_success,
          version: row.version,
          error: row.error,
          metadata: row.metadata ? JSON.parse(row.metadata) : null
        } : fallback;
      })
    };
  } finally {
    index.close();
  }
}

export async function withThreatDatabase(callback, options = {}) {
  const index = await openThreatIndex(options);
  try {
    return await callback(index.database);
  } finally {
    index.close();
  }
}
