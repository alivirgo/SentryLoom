import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const AUTH_KEY_PATTERN = /^[A-Za-z0-9._~-]{16,256}$/;
const ENTROPY = "SentryLoom HQ abuse.ch credential v1";

function powershellPath() {
  if (process.platform !== "win32") {
    throw new Error("SentryLoom HQ DPAPI secret protection requires Windows");
  }
  return path.join(
    process.env.WINDIR || "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
  );
}

async function dpapi(mode, value) {
  const script = [
    "$ErrorActionPreference = 'Stop';",
    "Add-Type -AssemblyName System.Security;",
    "$payload = [Convert]::FromBase64String($env:SENTRYLOOM_HQ_SECRET_PAYLOAD);",
    `$entropy = [Text.Encoding]::UTF8.GetBytes('${ENTROPY}');`,
    "try {",
    mode === "protect"
      ? " $result = [System.Security.Cryptography.ProtectedData]::Protect($payload, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);"
      : " $result = [System.Security.Cryptography.ProtectedData]::Unprotect($payload, $entropy, [System.Security.Cryptography.DataProtectionScope]::LocalMachine);",
    " [Console]::Out.Write([Convert]::ToBase64String($result));",
    "} finally {",
    " if ($payload) { [Array]::Clear($payload, 0, $payload.Length) };",
    " if ($result) { [Array]::Clear($result, 0, $result.Length) }",
    "}"
  ].join(" ");
  const { stdout } = await execFileAsync(powershellPath(), [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command", script
  ], {
    windowsHide: true,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
    env: {
      ...process.env,
      SENTRYLOOM_HQ_SECRET_PAYLOAD: Buffer.from(value).toString("base64")
    }
  });
  return Buffer.from(stdout.trim(), "base64");
}

export async function protectWithDpapi(value) {
  return (await dpapi("protect", Buffer.from(value))).toString("base64");
}

export async function unprotectWithDpapi(value) {
  return dpapi("unprotect", Buffer.from(String(value), "base64"));
}

export class HqSecretStore {
  constructor(file, options = {}) {
    this.file = path.resolve(file);
    this.protect = options.protect || protectWithDpapi;
    this.unprotect = options.unprotect || unprotectWithDpapi;
    this.cachedRecord = undefined;
  }

  async readRecord() {
    if (this.cachedRecord !== undefined) return this.cachedRecord;
    try {
      const record = JSON.parse(await fs.readFile(this.file, "utf8"));
      if (record?.schemaVersion !== 1 || !record.abuseCh?.protectedValue ||
          !/^[a-f0-9-]{36}$/i.test(String(record.abuseCh.revision || ""))) {
        throw new Error("The HQ protected-secret store is invalid");
      }
      this.cachedRecord = record;
      return record;
    } catch (error) {
      if (error.code === "ENOENT") {
        this.cachedRecord = null;
        return null;
      }
      throw error;
    }
  }

  async status() {
    const record = await this.readRecord();
    return {
      abuseChConfigured: Boolean(record?.abuseCh),
      revision: record?.abuseCh?.revision || null,
      updatedAt: record?.abuseCh?.updatedAt || null,
      protection: "Windows DPAPI LocalMachine + restricted HQ data ACL"
    };
  }

  async setAbuseChAuthKey(value) {
    const key = String(value || "").trim();
    if (!AUTH_KEY_PATTERN.test(key)) throw new Error("The abuse.ch Auth-Key format is invalid");
    const protectedValue = await this.protect(Buffer.from(key, "utf8"));
    const record = {
      schemaVersion: 1,
      abuseCh: {
        protectedValue,
        revision: crypto.randomUUID(),
        updatedAt: new Date().toISOString()
      }
    };
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const temporary = `${this.file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    await fs.writeFile(temporary, `${JSON.stringify(record, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx"
    });
    await fs.rename(temporary, this.file);
    this.cachedRecord = record;
    return this.status();
  }

  async clearAbuseChAuthKey() {
    await fs.rm(this.file, { force: true });
    this.cachedRecord = null;
    return this.status();
  }

  async getAbuseChAuthKey() {
    const record = await this.readRecord();
    if (!record?.abuseCh) return null;
    const plaintext = await this.unprotect(record.abuseCh.protectedValue);
    const value = plaintext.toString("utf8");
    plaintext.fill(0);
    if (!AUTH_KEY_PATTERN.test(value)) throw new Error("The protected abuse.ch Auth-Key is invalid");
    return value;
  }
}
