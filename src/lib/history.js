import { appPaths } from "../constants.js";
import { readJson, writeJsonAtomic } from "./fs-safe.js";

export async function saveScanSummary(report) {
  const history = await readJson(appPaths().scanHistory, { schemaVersion: 1, scans: [] });
  const summary = {
    id: report.id,
    target: report.target,
    signatureVersion: report.signatureVersion,
    startedAt: report.startedAt,
    endedAt: report.endedAt,
    durationMs: report.durationMs,
    scanned: report.scanned,
    skipped: report.skipped,
    detections: report.detections,
    errorCount: report.errors.length,
    detectedFiles: report.results.filter((item) => item.status === "detected")
  };
  history.scans.unshift(summary);
  history.scans = history.scans.slice(0, 100);
  await writeJsonAtomic(appPaths().scanHistory, history);
  return summary;
}

export async function saveScanJobSummary(job) {
  const history = await readJson(appPaths().scanHistory, { schemaVersion: 1, scans: [] });
  const detectedFiles = job.reports.flatMap((report) => (
    report.results.filter((item) => item.status === "detected")
  ));
  const summary = {
    id: job.id,
    type: job.type,
    target: job.targets.length === 1 ? job.targets[0] : `${job.targets.length} targets`,
    targets: job.targets,
    signatureVersion: job.reports.find((report) => report.signatureVersion)?.signatureVersion || null,
    startedAt: job.startedAt,
    endedAt: job.endedAt,
    durationMs: new Date(job.endedAt) - new Date(job.startedAt),
    scanned: job.scanned,
    skipped: job.skipped,
    detections: job.detections,
    errorCount: job.errorCount,
    detectedFiles
  };
  history.scans.unshift(summary);
  history.scans = history.scans.slice(0, 100);
  await writeJsonAtomic(appPaths().scanHistory, history);
  return summary;
}

export async function readScanHistory(limit = 30) {
  const history = await readJson(appPaths().scanHistory, { schemaVersion: 1, scans: [] });
  return history.scans.slice(0, limit);
}
