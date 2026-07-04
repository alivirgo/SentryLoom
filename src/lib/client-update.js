import fs from "node:fs/promises";
import path from "node:path";
import { execFile, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { APP_VERSION, appPaths } from "../constants.js";
import { ensureDirectory, readJson, writeJsonAtomic } from "./fs-safe.js";
import { downloadHqPackage, hqRequest } from "./hq-client.js";
import { isProcessElevated } from "./windows-monitoring.js";

const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/i;

export function compareClientVersions(left, right) {
  const a = String(left || "0.0.0").split(".").map((part) => Number(part) || 0);
  const b = String(right || "0.0.0").split(".").map((part) => Number(part) || 0);
  for (let index = 0; index < Math.max(a.length, b.length, 3); index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) - (b[index] || 0);
  }
  return 0;
}

export function validateClientUpdateManifest(value) {
  if (!value || !VERSION_PATTERN.test(String(value.version || ""))) {
    throw new Error("HQ returned an invalid client update version");
  }
  if (!HASH_PATTERN.test(String(value.sha256 || ""))) {
    throw new Error("HQ returned an invalid client update hash");
  }
  if (!Number.isSafeInteger(value.size) || value.size < 1024 || value.size > 1024 * 1024 * 1024) {
    throw new Error("HQ returned an invalid client update size");
  }
  const fileName = path.basename(String(value.fileName || ""));
  if (fileName !== value.fileName || !/^SentryLoom-Setup-\d+\.\d+\.\d+\.exe$/i.test(fileName)) {
    throw new Error("HQ returned an invalid client update package name");
  }
  if (fileName.toLowerCase() !== `sentryloom-setup-${value.version}.exe`.toLowerCase()) {
    throw new Error("HQ update package name does not match its version");
  }
  const signerThumbprint = String(value.signerThumbprint || "").replace(/\s/g, "").toUpperCase();
  if (!/^[A-F0-9]{40,64}$/.test(signerThumbprint)) {
    throw new Error("HQ returned an invalid update signer thumbprint");
  }
  const signerSubject = String(value.signerSubject || "").trim();
  if (!signerSubject || signerSubject.length > 500) {
    throw new Error("HQ returned an invalid update signer subject");
  }
  return {
    version: String(value.version),
    fileName,
    size: value.size,
    sha256: String(value.sha256).toUpperCase(),
    signerThumbprint,
    signerSubject,
    publishedAt: String(value.publishedAt || ""),
    releaseNotes: String(value.releaseNotes || "")
  };
}

function powershellPath() {
  return path.join(process.env.ProgramFiles || "C:\\Program Files", "PowerShell", "7", "pwsh.exe");
}

function windowsPowerShellPath() {
  return path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

async function resolvePowerShell() {
  return fs.access(powershellPath()).then(() => powershellPath()).catch(() => windowsPowerShellPath());
}

async function verifyAuthenticode(file) {
  const shell = await resolvePowerShell();
  const script = [
    "$signature=Get-AuthenticodeSignature -LiteralPath $env:SENTRYLOOM_UPDATE_FILE",
    "$item=Get-Item -LiteralPath $env:SENTRYLOOM_UPDATE_FILE",
    "[pscustomobject]@{Status=[string]$signature.Status;Thumbprint=[string]$signature.SignerCertificate.Thumbprint;Subject=[string]$signature.SignerCertificate.Subject;Version=[string]$item.VersionInfo.ProductVersion}|ConvertTo-Json -Compress"
  ].join(";");
  const output = await new Promise((resolve, reject) => {
    execFile(shell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
      windowsHide: true,
      timeout: 30000,
      maxBuffer: 1024 * 1024,
      env: { ...process.env, SENTRYLOOM_UPDATE_FILE: file }
    }, (error, stdout, stderr) => error ? reject(new Error(stderr.trim() || error.message)) : resolve(stdout));
  });
  return JSON.parse(output);
}

export async function getClientUpdateStatus() {
  return readJson(appPaths().clientUpdateStatus, {
    state: "idle",
    currentVersion: APP_VERSION,
    targetVersion: null,
    updatedAt: null,
    error: null
  });
}

export async function stageClientUpdate(credentials, options = {}) {
  const request = options.request || hqRequest;
  const download = options.download || downloadHqPackage;
  const verify = options.verify || verifyAuthenticode;
  const elevated = options.isElevated || isProcessElevated;
  const launch = options.launch;
  const response = await request(credentials.serverUrl, "/api/v1/device/update", {
    credentials,
    fingerprint256: credentials.fingerprint256,
    allowHttp: options.allowHttp
  });
  if (!response.body.update) {
    return { state: "up-to-date", currentVersion: APP_VERSION, targetVersion: null };
  }
  const manifest = validateClientUpdateManifest(response.body.update);
  if (compareClientVersions(manifest.version, APP_VERSION) <= 0) {
    return { state: "up-to-date", currentVersion: APP_VERSION, targetVersion: manifest.version };
  }
  if (!await elevated()) {
    throw new Error("The elevated SentryLoom protection task must be running to install client updates");
  }
  const paths = appPaths();
  await ensureDirectory(paths.clientUpdates);
  const destination = path.join(paths.clientUpdates, manifest.fileName);
  await writeJsonAtomic(paths.clientUpdateStatus, {
    state: "downloading",
    currentVersion: APP_VERSION,
    targetVersion: manifest.version,
    updatedAt: new Date().toISOString(),
    error: null
  });
  try {
    await download(credentials, "/api/v1/device/update/package", destination, manifest, {
      allowHttp: options.allowHttp,
      maximumBytes: manifest.size
    });
    const signature = await verify(destination);
    const thumbprint = String(signature.thumbprint || "").replace(/\s/g, "").toUpperCase();
    if (signature.status !== "Valid" ||
        thumbprint !== manifest.signerThumbprint ||
        String(signature.subject || "").trim() !== manifest.signerSubject ||
        String(signature.version || "").trim() !== manifest.version) {
      throw new Error("The client update failed Authenticode publisher or version verification");
    }
    const installRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
    const helper = path.join(installRoot, "Update-SentryLoom.ps1");
    await fs.access(helper);
    await writeJsonAtomic(paths.clientUpdateStatus, {
      state: "staged",
      currentVersion: APP_VERSION,
      targetVersion: manifest.version,
      sha256: manifest.sha256,
      signerThumbprint: manifest.signerThumbprint,
      updatedAt: new Date().toISOString(),
      error: null
    });
    const argumentsList = [
      "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
      "-ExecutionPolicy", "Bypass", "-File", helper,
      "-SetupFile", destination,
      "-ExpectedVersion", manifest.version,
      "-ExpectedSha256", manifest.sha256,
      "-ExpectedSignerThumbprint", manifest.signerThumbprint,
      "-ExpectedSignerSubject", manifest.signerSubject,
      "-StatusFile", paths.clientUpdateStatus,
      "-ParentProcessId", String(process.pid)
    ];
    const shell = await resolvePowerShell();
    if (launch) {
      await launch({ shell, argumentsList, manifest, destination });
    } else {
      const child = spawn(shell, argumentsList, {
        detached: true,
        stdio: "ignore",
        windowsHide: true
      });
      child.unref();
    }
    return {
      state: "scheduled",
      currentVersion: APP_VERSION,
      targetVersion: manifest.version,
      sha256: manifest.sha256,
      signerThumbprint: manifest.signerThumbprint
    };
  } catch (error) {
    await writeJsonAtomic(paths.clientUpdateStatus, {
      state: "failed",
      currentVersion: APP_VERSION,
      targetVersion: manifest.version,
      updatedAt: new Date().toISOString(),
      error: error.message.slice(0, 1000)
    });
    throw error;
  }
}
