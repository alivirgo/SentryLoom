import { appPaths } from "../constants.js";
import { withThreatDatabase } from "./threat-index.js";
import {
  FEED_SOURCES,
  downloadClamDatabases,
  parseClamCvd,
  fetchMalwareBazaar,
  malwareBazaarEntries,
  fetchUrlhaus,
  urlhausEntries,
  fetchFeodoTracker,
  feodoTrackerEntries,
  fetchThreatFox,
  threatFoxEntries,
  fetchSpamhausDrop,
  spamhausDropEntries,
  fetchMispOsint,
  mispEntries,
  downloadLinuxMalwareDetect
} from "./threat-feeds.js";
import { fetchHqThreatFeed } from "./hq-client.js";

function now() {
  return new Date().toISOString();
}

function normalizeSources(sources) {
  const values = sources?.length ? sources : Object.keys(FEED_SOURCES);
  const unique = [...new Set(values)];
  for (const source of unique) {
    if (!FEED_SOURCES[source]) throw new Error(`Unknown threat-intelligence source: ${source}`);
  }
  return unique;
}

function databaseWriter(database) {
  const insert = database.prepare(`
    INSERT INTO threat_hashes
      (algorithm, hash, size, name, source, severity, confirmed, details, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (algorithm, hash, size, source) DO UPDATE SET
      name = excluded.name,
      severity = excluded.severity,
      confirmed = excluded.confirmed,
      details = excluded.details,
      updated_at = excluded.updated_at
  `);
  const status = database.prepare(`
    INSERT INTO feed_status
      (source, state, last_attempt, last_success, version, entry_count, last_import_count, error, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (source) DO UPDATE SET
      state = excluded.state,
      last_attempt = excluded.last_attempt,
      last_success = excluded.last_success,
      version = excluded.version,
      entry_count = excluded.entry_count,
      last_import_count = excluded.last_import_count,
      error = excluded.error,
      metadata = excluded.metadata
  `);
  const insertIoc = database.prepare(`
    INSERT INTO network_iocs
      (type, value, source, name, confidence, first_seen, last_seen, details, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (type, value, source) DO UPDATE SET
      name = excluded.name,
      confidence = excluded.confidence,
      first_seen = excluded.first_seen,
      last_seen = excluded.last_seen,
      details = excluded.details,
      updated_at = excluded.updated_at
  `);
  const previous = database.prepare("SELECT * FROM feed_status WHERE source = ?");
  const countHashes = database.prepare("SELECT COUNT(*) AS count FROM threat_hashes WHERE source = ?");
  const countIocs = database.prepare("SELECT COUNT(*) AS count FROM network_iocs WHERE source = ?");
  return {
    insert(entry, timestamp) {
      insert.run(
        entry.algorithm,
        entry.hash,
        entry.size,
        entry.name,
        entry.source,
        entry.severity,
        entry.confirmed ? 1 : 0,
        entry.details ? JSON.stringify(entry.details) : null,
        timestamp
      );
    },
    insertIoc(entry, timestamp) {
      insertIoc.run(
        entry.type,
        entry.value,
        entry.source,
        entry.name,
        entry.confidence,
        entry.firstSeen,
        entry.lastSeen,
        entry.details ? JSON.stringify(entry.details) : null,
        timestamp
      );
    },
    previous(source) {
      return previous.get(source);
    },
    count(source) {
      return Number(countHashes.get(source).count) + Number(countIocs.get(source).count);
    },
    status(source, values) {
      const old = previous.get(source);
      status.run(
        source,
        values.state,
        values.lastAttempt ?? old?.last_attempt ?? null,
        values.lastSuccess ?? old?.last_success ?? null,
        values.version ?? old?.version ?? null,
        values.entryCount ?? Number(old?.entry_count || 0),
        values.lastImportCount ?? Number(old?.last_import_count || 0),
        values.error ?? null,
        values.metadata ? JSON.stringify(values.metadata) : old?.metadata ?? null
      );
    }
  };
}

function enforceInterval(writer, source, minimumMinutes, force) {
  if (force) return;
  const previous = writer.previous(source);
  if (!previous?.last_success) return;
  const elapsed = Date.now() - new Date(previous.last_success).getTime();
  const minimum = minimumMinutes * 60 * 1000;
  if (elapsed < minimum) {
    const remaining = Math.ceil((minimum - elapsed) / 60000);
    const error = new Error(`${FEED_SOURCES[source].name} was updated recently; try again in ${remaining} minute(s)`);
    error.code = "UPDATE_TOO_SOON";
    throw error;
  }
}

async function updateClamAv(database, writer, context) {
  const artifacts = await downloadClamDatabases(context.config, context.onProgress, context.fetchImpl);
  const timestamp = now();
  let imported = 0;
  const versions = [];
  database.exec("BEGIN IMMEDIATE");
  try {
    database.prepare("DELETE FROM threat_hashes WHERE source = 'clamav'").run();
    for (const artifact of artifacts) {
      context.onProgress({ source: "clamav", phase: "index", message: `Indexing ${artifact.database}.cvd`, imported });
      const result = await parseClamCvd(artifact.file, (entry) => {
        writer.insert(entry, timestamp);
        imported += 1;
      }, (progress) => context.onProgress({ source: "clamav", ...progress }));
      versions.push(`${artifact.database}:${result.version}`);
    }
    const entryCount = writer.count("clamav");
    writer.status("clamav", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: versions.join(", "),
      entryCount,
      lastImportCount: imported,
      metadata: {
        artifacts: artifacts.map((item) => ({
          database: item.database,
          bytes: item.download.bytes,
          etag: item.download.etag,
          modified: item.download.modified
        }))
      }
    });
    database.exec("COMMIT");
    return { source: "clamav", imported, entryCount, version: versions.join(", ") };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateMalwareBazaar(database, writer, context) {
  const payload = context.hqCredentials
    ? await (context.hqFetchImpl || fetchHqThreatFeed)(context.hqCredentials, "malwarebazaar", {
      timeoutMs: context.config.requestTimeoutMs
    })
    : await fetchMalwareBazaar(context.config, context.credentials.abuseChAuthKey, context.fetchImpl);
  const entries = malwareBazaarEntries(payload);
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    for (const entry of entries) writer.insert(entry, timestamp);
    const entryCount = writer.count("malwarebazaar");
    writer.status("malwarebazaar", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: `recent-detections-${timestamp.slice(0, 10)}`,
      entryCount,
      lastImportCount: entries.length,
      metadata: { windowHours: 168 }
    });
    database.exec("COMMIT");
    return { source: "malwarebazaar", imported: entries.length, entryCount };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateUrlhaus(database, writer, context) {
  const payload = context.hqCredentials
    ? await (context.hqFetchImpl || fetchHqThreatFeed)(context.hqCredentials, "urlhaus", {
      timeoutMs: context.config.requestTimeoutMs
    })
    : await fetchUrlhaus(context.config, context.credentials.abuseChAuthKey, context.fetchImpl);
  const entries = urlhausEntries(payload);
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    for (const entry of entries) writer.insert(entry, timestamp);
    const entryCount = writer.count("urlhaus");
    writer.status("urlhaus", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: `recent-payloads-${timestamp.slice(0, 10)}`,
      entryCount,
      lastImportCount: entries.length,
      metadata: { confirmed: false, reason: "URLhaus warns collected payloads are not always malicious" }
    });
    database.exec("COMMIT");
    return { source: "urlhaus", imported: entries.length, entryCount };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateFeodoTracker(database, writer, context) {
  const payload = await fetchFeodoTracker(context.config, context.fetchImpl);
  const entries = feodoTrackerEntries(payload);
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    database.prepare("DELETE FROM threat_hashes WHERE source = 'feodotracker'").run();
    database.prepare("DELETE FROM network_iocs WHERE source = 'feodotracker'").run();
    for (const entry of entries.hashes) writer.insert(entry, timestamp);
    for (const entry of entries.iocs) writer.insertIoc(entry, timestamp);
    const imported = entries.hashes.length + entries.iocs.length;
    const entryCount = writer.count("feodotracker");
    writer.status("feodotracker", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: `recommended-${timestamp.slice(0, 10)}`,
      entryCount,
      lastImportCount: imported,
      metadata: { license: "CC0", list: "recommended", networkOnly: true }
    });
    database.exec("COMMIT");
    return { source: "feodotracker", imported, entryCount };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateThreatFox(database, writer, context) {
  const payload = context.hqCredentials
    ? await (context.hqFetchImpl || fetchHqThreatFeed)(context.hqCredentials, "threatfox", {
      timeoutMs: context.config.requestTimeoutMs
    })
    : await fetchThreatFox(context.config, context.credentials.abuseChAuthKey, context.fetchImpl);
  const entries = threatFoxEntries(payload);
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    for (const entry of entries.hashes) writer.insert(entry, timestamp);
    for (const entry of entries.iocs) writer.insertIoc(entry, timestamp);
    database.prepare("DELETE FROM threat_hashes WHERE source = 'threatfox' AND updated_at < datetime('now', '-180 days')").run();
    database.prepare("DELETE FROM network_iocs WHERE source = 'threatfox' AND updated_at < datetime('now', '-180 days')").run();
    const imported = entries.hashes.length + entries.iocs.length;
    const entryCount = writer.count("threatfox");
    writer.status("threatfox", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: `recent-iocs-${timestamp.slice(0, 10)}`,
      entryCount,
      lastImportCount: imported,
      metadata: { windowDays: 7, expiredAfterDays: 180, hashes: entries.hashes.length, networkIocs: entries.iocs.length }
    });
    database.exec("COMMIT");
    return { source: "threatfox", imported, entryCount, hashes: entries.hashes.length, networkIocs: entries.iocs.length };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateSpamhausDrop(database, writer, context) {
  const entries = spamhausDropEntries(
    await fetchSpamhausDrop(context.config, context.fetchImpl)
  );
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    database.prepare("DELETE FROM network_iocs WHERE source = 'spamhaus-drop'").run();
    for (const entry of entries.iocs) writer.insertIoc(entry, timestamp);
    const entryCount = writer.count("spamhaus-drop");
    writer.status("spamhaus-drop", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: entries.metadata?.timestamp
        ? new Date(Number(entries.metadata.timestamp) * 1000).toISOString()
        : timestamp.slice(0, 10),
      entryCount,
      lastImportCount: entries.iocs.length,
      metadata: {
        list: "DROP IPv4 and IPv6",
        records: entries.metadata?.records || entries.iocs.length,
        terms: entries.metadata?.terms || "https://www.spamhaus.org/drop/terms/",
        advisory: "CIDR matches are report-only unless IOC blocking is explicitly enabled"
      }
    });
    database.exec("COMMIT");
    return { source: "spamhaus-drop", imported: entries.iocs.length, entryCount };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateMisp(database, writer, context, source) {
  const payload = await fetchMispOsint(
    context.config,
    source,
    context.fetchImpl,
    20,
    context.onProgress
  );
  const entries = mispEntries(payload.events, source);
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    for (const entry of entries.hashes) writer.insert(entry, timestamp);
    for (const entry of entries.iocs) writer.insertIoc(entry, timestamp);
    database.prepare("DELETE FROM threat_hashes WHERE source = ? AND updated_at < datetime('now', '-180 days')")
      .run(source);
    database.prepare("DELETE FROM network_iocs WHERE source = ? AND updated_at < datetime('now', '-180 days')")
      .run(source);
    const imported = entries.hashes.length + entries.iocs.length;
    const entryCount = writer.count(source);
    writer.status(source, {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: payload.newestTimestamp || timestamp.slice(0, 10),
      entryCount,
      lastImportCount: imported,
      metadata: {
        format: "MISP",
        manifestEntries: payload.manifestEntries,
        fetchedEvents: payload.fetchedEvents,
        retainedDays: 180,
        hashes: entries.hashes.length,
        networkIocs: entries.iocs.length
      }
    });
    database.exec("COMMIT");
    return {
      source, imported, entryCount,
      hashes: entries.hashes.length,
      networkIocs: entries.iocs.length
    };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

async function updateLinuxMalwareDetect(database, writer, context) {
  const payload = await downloadLinuxMalwareDetect(
    context.config,
    context.onProgress,
    context.fetchImpl
  );
  const timestamp = now();
  database.exec("BEGIN IMMEDIATE");
  try {
    database.prepare("DELETE FROM threat_hashes WHERE source = 'lmd'").run();
    for (const entry of payload.entries) writer.insert(entry, timestamp);
    const entryCount = writer.count("lmd");
    writer.status("lmd", {
      state: "ready",
      lastAttempt: context.startedAt,
      lastSuccess: timestamp,
      version: payload.version,
      entryCount,
      lastImportCount: payload.entries.length,
      metadata: {
        license: "GPL-2.0",
        platformFocus: "Linux",
        algorithm: "SHA-256",
        artifactBytes: payload.download.bytes
      }
    });
    database.exec("COMMIT");
    return { source: "lmd", imported: payload.entries.length, entryCount, version: payload.version };
  } catch (error) {
    database.exec("ROLLBACK");
    throw error;
  }
}

export async function updateThreatFeeds(options) {
  const sources = normalizeSources(options.sources);
  const results = [];
  return withThreatDatabase(async (database) => {
    const writer = databaseWriter(database);
    for (const source of sources) {
      const startedAt = now();
      try {
        if (FEED_SOURCES[source].requiresAuth &&
            !options.credentials?.abuseChAuthKey &&
            !options.hqCredentials) {
          throw new Error("An abuse.ch Auth-Key is required locally or through SentryLoom HQ");
        }
        enforceInterval(writer, source, options.config.minimumUpdateIntervalMinutes, options.force);
        writer.status(source, { state: "updating", lastAttempt: startedAt, error: null });
        options.onProgress?.({ source, phase: "start", message: `Updating ${FEED_SOURCES[source].name}` });
        const context = {
          ...options,
          startedAt,
          onProgress: options.onProgress || (() => {})
        };
        let result;
        if (source === "clamav") result = await updateClamAv(database, writer, context);
        else if (source === "malwarebazaar") result = await updateMalwareBazaar(database, writer, context);
        else if (source === "urlhaus") result = await updateUrlhaus(database, writer, context);
        else if (source === "feodotracker") result = await updateFeodoTracker(database, writer, context);
        else if (source === "threatfox") result = await updateThreatFox(database, writer, context);
        else if (source === "spamhaus-drop") result = await updateSpamhausDrop(database, writer, context);
        else if (source === "lmd") result = await updateLinuxMalwareDetect(database, writer, context);
        else result = await updateMisp(database, writer, context, source);
        results.push({ ...result, ok: true });
        options.onProgress?.({ source, phase: "complete", message: `${FEED_SOURCES[source].name} updated`, ...result });
      } catch (error) {
        if (error.code === "UPDATE_TOO_SOON") {
          results.push({ source, ok: true, skipped: true, message: error.message });
          options.onProgress?.({ source, phase: "complete", message: error.message, skipped: true });
          continue;
        }
        writer.status(source, { state: "error", lastAttempt: startedAt, error: error.message });
        results.push({ source, ok: false, error: error.message });
        options.onProgress?.({ source, phase: "error", message: error.message });
      }
    }
    return { completedAt: now(), results };
  }, { file: options.databaseFile || appPaths().threatIndex });
}
