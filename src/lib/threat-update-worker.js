import { parentPort, workerData } from "node:worker_threads";

process.env.SENTRYLOOM_DATA_DIR = workerData.dataDirectory;

const { updateThreatFeeds } = await import("./threat-updater.js");

try {
  const result = await updateThreatFeeds({
    sources: workerData.sources,
    config: workerData.config,
    credentials: workerData.credentials,
    force: workerData.force,
    onProgress: (progress) => parentPort.postMessage({ type: "progress", progress })
  });
  parentPort.postMessage({ type: "complete", result });
} catch (error) {
  parentPort.postMessage({ type: "fatal", error: error.message });
}
