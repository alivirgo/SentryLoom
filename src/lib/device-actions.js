import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";

function run(file, args = [], timeout = 30000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr?.trim() || stdout?.trim() || error.message, { cause: error }));
      else resolve(stdout?.trim() || "");
    });
  });
}

export async function lockDevice(platform = process.platform) {
  if (platform === "win32") await run("rundll32.exe", ["user32.dll,LockWorkStation"]);
  else if (platform === "darwin") await run("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", ["-suspend"]);
  else if (platform === "linux") await run("loginctl", ["lock-sessions"]);
  else throw new Error(`Remote lock is not supported on ${platform}`);
  return { lockedAt: new Date().toISOString(), platform };
}

export function validateWipeRoots(roots, allowedRoots) {
  if (!Array.isArray(roots) || !roots.length) throw new Error("No managed company-data roots are configured");
  const allowed = new Set((allowedRoots || []).map((item) => path.resolve(item).toLowerCase()));
  return [...new Set(roots.map((item) => path.resolve(item)))].map((root) => {
    const normalized = root.toLowerCase();
    if (!allowed.has(normalized)) throw new Error(`Wipe target is outside managed company-data roots: ${root}`);
    const parsed = path.parse(root);
    const protectedLocations = [
      parsed.root,
      path.resolve(process.cwd()),
      path.resolve(os.homedir()),
      process.env.SystemRoot && path.resolve(process.env.SystemRoot),
      process.env.ProgramFiles && path.resolve(process.env.ProgramFiles),
      process.env.PROGRAMDATA && path.resolve(process.env.PROGRAMDATA)
    ].filter(Boolean).map((item) => item.toLowerCase());
    if (protectedLocations.includes(normalized)) {
      throw new Error(`Unsafe wipe target was rejected: ${root}`);
    }
    return root;
  });
}

export async function wipeCompanyData(roots, allowedRoots) {
  const targets = validateWipeRoots(roots, allowedRoots);
  const removed = [];
  for (const root of targets) {
    await fs.rm(root, { recursive: true, force: true });
    await fs.mkdir(root, { recursive: true });
    removed.push(root);
  }
  return { wipedAt: new Date().toISOString(), scope: "managed-company-data", removed };
}
