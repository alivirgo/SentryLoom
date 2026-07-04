import fs from "node:fs/promises";
import path from "node:path";
import {
  discoverRemovableDrives,
  readPersistenceSnapshot,
  readProcessSnapshot
} from "./windows-telemetry.js";

const ACTIVE_EXTENSION = /\.(?:exe|com|scr|cpl|dll|sys|bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk)$/i;
const EMBEDDED_PATH = /"([^"]+\.(?:exe|com|scr|cpl|dll|sys|bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk))"|((?:[a-z]:\\|\\\\)[^|"'`\r\n]+?\.(?:exe|com|scr|cpl|dll|sys|bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk))/gi;

function normalizeCandidate(value) {
  if (typeof value !== "string") return null;
  const candidate = value.trim().replace(/^"+|"+$/g, "");
  if (!candidate || candidate.length > 32767 || !ACTIVE_EXTENSION.test(candidate)) return null;
  return path.normalize(candidate);
}

export function persistenceExecutableCandidates(items) {
  const candidates = new Set();
  for (const item of items || []) {
    if (item?.type === "startup-file") {
      const candidate = normalizeCandidate(item.id);
      if (candidate) candidates.add(candidate);
    }
    const raw = typeof item?.value === "string" ? item.value : JSON.stringify(item?.value ?? "");
    for (const match of raw.matchAll(EMBEDDED_PATH)) {
      const candidate = normalizeCandidate(match[1] || match[2]);
      if (candidate) candidates.add(candidate);
    }
  }
  return [...candidates];
}

async function existingFiles(candidates) {
  const files = [];
  for (const candidate of new Set(candidates.filter(Boolean))) {
    try {
      if ((await fs.stat(candidate)).isFile()) files.push(candidate);
    } catch {
      // Stale persistence entries and protected process images are expected.
    }
  }
  return files;
}

export async function discoverStartupTargets() {
  const persistence = await readPersistenceSnapshot();
  return existingFiles(persistenceExecutableCandidates(persistence));
}

export async function discoverProcessImageTargets() {
  const processes = await readProcessSnapshot();
  return existingFiles(processes.map((item) => item.executablePath));
}

export async function discoverExternalDriveTargets() {
  const drives = await discoverRemovableDrives();
  return [...new Set(drives.map((drive) => drive.root).filter(Boolean))];
}
