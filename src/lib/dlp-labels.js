import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { appPaths } from "../constants.js";
import { readJson, writeJsonAtomic } from "./fs-safe.js";

export const DLP_LABELS = Object.freeze(["public", "internal", "confidential", "super-confidential"]);
const DOCUMENT = /\.(?:docx?|xlsx?|pptx?|pdf|odt|ods|odp|rtf|txt|csv)$/i;

function labelFile() { return path.join(appPaths().data, "dlp", "labels.json"); }
function normalized(file) { return path.resolve(file); }

export function isDocument(file) { return DOCUMENT.test(String(file || "")); }

export async function listDocumentLabels() {
  const state = await readJson(labelFile(), { schemaVersion: 1, documents: {} });
  return Object.values(state.documents || {}).sort((a, b) => String(b.detectedAt).localeCompare(String(a.detectedAt)));
}

export async function observeDocument(file) {
  if (!isDocument(file)) return null;
  const target = normalized(file);
  const state = await readJson(labelFile(), { schemaVersion: 1, documents: {} });
  const id = crypto.createHash("sha256").update(target.toLowerCase()).digest("hex");
  if (state.documents[id]) return state.documents[id];
  const record = { id, path: target, label: null, detectedAt: new Date().toISOString(), labeledAt: null };
  state.documents[id] = record;
  await writeJsonAtomic(labelFile(), state);
  return record;
}

export async function labelDocument(id, label) {
  if (!DLP_LABELS.includes(label)) throw new Error("Invalid DLP label");
  const state = await readJson(labelFile(), { schemaVersion: 1, documents: {} });
  const record = state.documents?.[id];
  if (!record) throw new Error("Document label request was not found");
  await fs.access(record.path);
  record.label = label;
  record.labeledAt = new Date().toISOString();
  await writeJsonAtomic(labelFile(), state);
  return record;
}

export function authorizeTransfer(document, channel, destination, allowlist = []) {
  const normalizedChannel = String(channel || "").toLowerCase();
  if (!["email", "internet", "external-storage"].includes(normalizedChannel)) {
    throw new Error("Unsupported DLP transfer channel");
  }
  if (document?.label !== "super-confidential") {
    return { allowed: true, reason: "classification-does-not-require-block" };
  }
  const target = String(destination || "").trim().toLowerCase();
  const allowed = (allowlist || []).some((entry) => {
    const item = String(entry || "").trim().toLowerCase();
    return item && (target === item || target.endsWith(`.${item}`));
  });
  return {
    allowed,
    reason: allowed ? "explicit-destination-exception" : "super-confidential-deny-by-default"
  };
}
