import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

export async function ensureDirectory(directory) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
}

export async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return structuredClone(fallback);
    throw new Error(`Cannot read JSON file ${file}: ${error.message}`, { cause: error });
  }
}

export async function writeJsonAtomic(file, value) {
  await ensureDirectory(path.dirname(file));
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx"
  });
  let lastError;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      await fs.rename(temporary, file);
      return;
    } catch (error) {
      lastError = error;
      if (!["EPERM", "EACCES", "EBUSY"].includes(error.code)) throw error;
      await new Promise((resolve) => setTimeout(resolve, 20 * (attempt + 1)));
    }
  }
  await fs.rm(temporary, { force: true });
  throw lastError;
}

export async function fileExists(file) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

export function isPathInside(candidate, parent) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

export function normalizeForComparison(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

export function matchesExclusion(file, exclusions = []) {
  const normalized = normalizeForComparison(file);
  return exclusions.some((entry) => {
    const rule = normalizeForComparison(entry);
    return normalized === rule || normalized.startsWith(`${rule}${path.sep}`);
  });
}
