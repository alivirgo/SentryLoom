import fs from "node:fs/promises";
import path from "node:path";

const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/i;

export function compareVersions(left, right) {
  const a = String(left || "0.0.0").split(".").map((part) => Number(part) || 0);
  const b = String(right || "0.0.0").split(".").map((part) => Number(part) || 0);
  for (let index = 0; index < Math.max(a.length, b.length, 3); index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) return (a[index] || 0) - (b[index] || 0);
  }
  return 0;
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

  publicManifest(update) {
    if (!update) return null;
    const { packagePath, ...manifest } = update;
    return manifest;
  }
}
