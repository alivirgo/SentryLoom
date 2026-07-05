const SOURCE_POLICY = Object.freeze({
  malwarebazaar: {
    url: "https://mb-api.abuse.ch/api/v1/",
    maxBytes: 50 * 1024 * 1024,
    request(authKey) {
      return {
        method: "POST",
        headers: {
          "Auth-Key": authKey,
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "SentryLoom-HQ/0.4"
        },
        body: new URLSearchParams({ query: "recent_detections", hours: "168" })
      };
    }
  },
  urlhaus: {
    url: "https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/",
    maxBytes: 50 * 1024 * 1024,
    request(authKey) {
      return {
        method: "GET",
        headers: { "Auth-Key": authKey, "User-Agent": "SentryLoom-HQ/0.4" }
      };
    }
  },
  threatfox: {
    url: "https://threatfox-api.abuse.ch/api/v1/",
    maxBytes: 100 * 1024 * 1024,
    request(authKey) {
      return {
        method: "POST",
        headers: {
          "Auth-Key": authKey,
          "Content-Type": "application/json",
          "User-Agent": "SentryLoom-HQ/0.4"
        },
        body: JSON.stringify({ query: "get_iocs", days: 7 })
      };
    }
  }
});

async function boundedJson(response, maximumBytes) {
  if (!response.ok) throw new Error(`abuse.ch returned HTTP ${response.status}`);
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maximumBytes) throw new Error("abuse.ch response exceeds the HQ size limit");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maximumBytes) throw new Error("abuse.ch response exceeds the HQ size limit");
  return JSON.parse(bytes.toString("utf8"));
}

export class ThreatGateway {
  constructor(secretStore, options = {}) {
    this.secretStore = secretStore;
    this.fetch = options.fetch || fetch;
    this.cacheMs = Math.max(60000, Number(options.cacheMs) || 15 * 60 * 1000);
    this.timeoutMs = Math.max(5000, Number(options.timeoutMs) || 60000);
    this.cache = new Map();
    this.inflight = new Map();
  }

  async status() {
    return this.secretStore.status();
  }

  clearCache() {
    this.cache.clear();
  }

  async fetchSource(source) {
    const policy = SOURCE_POLICY[String(source || "").toLowerCase()];
    if (!policy) throw new Error("The requested abuse.ch feed is not allowed");
    const cached = this.cache.get(source);
    if (cached && Date.now() - cached.fetchedAt < this.cacheMs) {
      return { source, payload: cached.payload, fetchedAt: cached.fetchedAtIso, cached: true };
    }
    if (this.inflight.has(source)) return this.inflight.get(source);
    const pending = this.fetchFresh(source, policy).finally(() => this.inflight.delete(source));
    this.inflight.set(source, pending);
    return pending;
  }

  async fetchFresh(source, policy) {
    let authKey = await this.secretStore.getAbuseChAuthKey();
    if (!authKey) {
      throw new Error("SentryLoom HQ does not have an abuse.ch Auth-Key configured");
    }
    try {
      const response = await this.fetch(policy.url, {
        ...policy.request(authKey),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs)
      });
      const payload = await boundedJson(response, policy.maxBytes);
      const fetchedAt = Date.now();
      const fetchedAtIso = new Date(fetchedAt).toISOString();
      this.cache.set(source, { payload, fetchedAt, fetchedAtIso });
      return { source, payload, fetchedAt: fetchedAtIso, cached: false };
    } finally {
      authKey = null;
    }
  }
}
