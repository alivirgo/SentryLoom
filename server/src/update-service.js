import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { createReadStream } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/i;
const SETUP_PATTERN = /^SentryLoom-Setup-(\d+\.\d+\.\d+)\.exe$/i;
const execFileAsync = promisify(execFile);

export function compareVersions(left, right) {
  const a = String(left || "0.0.0").split(".").map((part) => Number(part) || 0);
  const b = String(right || "0.0.0").split(".").map((part) => Number(part) || 0);
  for (let index = 0; index < Math.max(a.length, b.length, 3); index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) - (b[index] || 0);
  }
  return 0;
}

function powershellPath() {
  if (process.platform !== "win32") {
    throw new Error("Authenticode inspection is available only on Windows");
  }
  return path.join(
    process.env.WINDIR || "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
  );
}

export async function inspectAuthenticodePackage(file) {
  const command = [
    "$item = Get-Item -LiteralPath $env:SENTRYLOOM_STAGED_SETUP -ErrorAction Stop;",
    "$signature = Get-AuthenticodeSignature -LiteralPath $item.FullName -ErrorAction Stop;",
    "[pscustomobject]@{",
    "version=([string]$item.VersionInfo.ProductVersion).Trim();",
    "status=[string]$signature.Status;",
    "thumbprint=[string]$signature.SignerCertificate.Thumbprint;",
    "subject=[string]$signature.SignerCertificate.Subject",
    "} | ConvertTo-Json -Compress"
  ].join(" ");
  const { stdout } = await execFileAsync(powershellPath(), [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-Command", command
  ], {
    windowsHide: true,
    timeout: 30000,
    maxBuffer: 1024 * 1024,
    env: {
      ...process.env,
      SENTRYLOOM_STAGED_SETUP: path.resolve(file)
    }
  });
  return JSON.parse(stdout);
}

async function sha256File(file) {
  const hash = crypto.createHash("sha256");
  await new Promise((resolve, reject) => {
    const stream = createReadStream(file);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", resolve);
  });
  return hash.digest("hex").toUpperCase();
}

export async function latestStagedSetup(directory) {
  const root = path.resolve(String(directory || ""));
  const entries = await fs.readdir(root, { withFileTypes: true });
  const candidates = await Promise.all(entries
    .filter((entry) => entry.isFile() && SETUP_PATTERN.test(entry.name))
    .map(async (entry) => {
      const match = entry.name.match(SETUP_PATTERN);
      const file = path.join(root, entry.name);
      const stat = await fs.stat(file);
      return { file, fileName: entry.name, version: match[1], modifiedAt: stat.mtimeMs };
    }));
  candidates.sort((left, right) =>
    compareVersions(right.version, left.version) || right.modifiedAt - left.modifiedAt
  );
  return candidates[0] || null;
}

function validateManifest(value) {
  if (!value || !VERSION_PATTERN.test(String(value.version || ""))) {
    throw new Error("The published client update has an invalid version");
  }
  if (!HASH_PATTERN.test(String(value.sha256 || ""))) {
    throw new Error("The published client update has an invalid SHA-256 hash");
  }
  if (!Number.isSafeInteger(value.size) || value.size < 1024 || value.size > 1024 * 1024 * 1024) {
    throw new Error("The published client update has an invalid package size");
  }
  const fileName = path.basename(String(value.fileName || ""));
  if (fileName !== value.fileName || !/^SentryLoom-Setup-\d+\.\d+\.\d+\.exe$/i.test(fileName)) {
    throw new Error("The published client update has an invalid package name");
  }
  if (fileName.toLowerCase() !== `sentryloom-setup-${value.version}.exe`.toLowerCase()) {
    throw new Error("The published client update package name does not match its version");
  }
  if (!/^[a-f0-9]{40,64}$/i.test(String(value.signerThumbprint || ""))) {
    throw new Error("The published client update has an invalid signer thumbprint");
  }
  const signerSubject = String(value.signerSubject || "").trim();
  if (!signerSubject || signerSubject.length > 500) {
    throw new Error("The published client update has an invalid signer subject");
  }
  return {
    schemaVersion: 1,
    version: String(value.version),
    fileName,
    size: value.size,
    sha256: String(value.sha256).toUpperCase(),
    signerThumbprint: String(value.signerThumbprint).replace(/\s/g, "").toUpperCase(),
    signerSubject,
    publishedAt: String(value.publishedAt || ""),
    releaseNotes: String(value.releaseNotes || "").slice(0, 4000)
  };
}

export class UpdateService {
  constructor(directory) {
    this.directory = path.resolve(directory);
    this.manifestPath = path.join(this.directory, "latest.json");
    this.stagingCache = null;
  }

  async latest() {
    let manifest;
    try {
      manifest = validateManifest(JSON.parse(await fs.readFile(this.manifestPath, "utf8")));
    } catch (error) {
      if (error.code === "ENOENT") return null;
      throw error;
    }
    const packagePath = path.resolve(this.directory, manifest.fileName);
    if (!packagePath.startsWith(`${this.directory}${path.sep}`)) {
      throw new Error("The published update package path is invalid");
    }
    const stat = await fs.stat(packagePath);
    if (!stat.isFile() || stat.size !== manifest.size) {
      throw new Error("The published update package does not match its manifest");
    }
    return { ...manifest, packagePath };
  }

  async stagingStatus(stagingDirectory) {
    const directory = path.resolve(String(stagingDirectory || ""));
    if (this.stagingCache?.directory === directory &&
        Date.now() - this.stagingCache.cachedAt < 15000) {
      return this.stagingCache.value;
    }
    const remember = (value) => {
      this.stagingCache = { directory, cachedAt: Date.now(), value };
      return value;
    };
    try {
      let timeout;
      const latest = await Promise.race([
        latestStagedSetup(directory),
        new Promise((unusedResolve, reject) => {
          timeout = setTimeout(() => reject(new Error(
            "The staging-folder access check timed out. Use a reachable local or UNC path."
          )), 3000);
          timeout.unref?.();
        })
      ]).finally(() => clearTimeout(timeout));
      return remember({
        directory,
        accessible: true,
        latest: latest ? {
          fileName: latest.fileName,
          version: latest.version,
          modifiedAt: new Date(latest.modifiedAt).toISOString()
        } : null
      });
    } catch (error) {
      return remember({
        directory,
        accessible: false,
        latest: null,
        error: error.code === "ENOENT"
          ? "The staging folder is not visible to the SentryLoom HQ service account."
          : String(error.message || error)
      });
    }
  }

  async publishLatest(stagingDirectory, options = {}) {
    const staged = await latestStagedSetup(stagingDirectory);
    if (!staged) {
      throw new Error("No SentryLoom-Setup-x.y.z.exe file was found in the staging folder");
    }
    const inspect = options.inspect || inspectAuthenticodePackage;
    const signature = await inspect(staged.file);
    const productVersion = String(signature?.version || "").trim();
    const thumbprint = String(signature?.thumbprint || "").replace(/\s/g, "").toUpperCase();
    const subject = String(signature?.subject || "").trim();
    if (String(signature?.status || "") !== "Valid" || !thumbprint || !subject) {
      throw new Error("Windows did not validate the newest staged Setup Authenticode signature");
    }
    if (productVersion !== staged.version) {
      throw new Error(
        `The newest staged Setup filename says ${staged.version}, but its product version is ${productVersion || "missing"}`
      );
    }

    await fs.mkdir(this.directory, { recursive: true });
    const fileName = `SentryLoom-Setup-${productVersion}.exe`;
    const destination = path.join(this.directory, fileName);
    const suffix = `${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    const temporaryPackage = `${destination}.${suffix}`;
    const temporaryManifest = `${this.manifestPath}.${suffix}`;
    try {
      await fs.copyFile(staged.file, temporaryPackage);
      const copied = await fs.stat(temporaryPackage);
      if (!copied.isFile() || copied.size < 1024 || copied.size > 1024 * 1024 * 1024) {
        throw new Error("The staged Setup package has an invalid size");
      }
      const manifest = validateManifest({
        schemaVersion: 1,
        version: productVersion,
        fileName,
        size: copied.size,
        sha256: await sha256File(temporaryPackage),
        signerThumbprint: thumbprint,
        signerSubject: subject,
        publishedAt: new Date().toISOString(),
        releaseNotes: String(options.releaseNotes || "").slice(0, 4000)
      });
      await fs.rename(temporaryPackage, destination);
      await fs.writeFile(temporaryManifest, `${JSON.stringify(manifest, null, 2)}\n`, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx"
      });
      await fs.rename(temporaryManifest, this.manifestPath);
      this.stagingCache = null;
      return { ...manifest, sourceFile: staged.file };
    } finally {
      await Promise.all([
        fs.rm(temporaryPackage, { force: true }).catch(() => {}),
        fs.rm(temporaryManifest, { force: true }).catch(() => {})
      ]);
    }
  }

  publicManifest(update) {
    if (!update) return null;
    const { packagePath, sourceFile, ...manifest } = update;
    return manifest;
  }
}
