import { Worker } from "node:worker_threads";
import { appPaths } from "../constants.js";
import { loadThreatCredentials } from "./credential-store.js";
import { appendAudit } from "./audit-log.js";

export class ThreatUpdateManager {
  constructor(config, onEvent = () => {}) {
    this.config = config;
    this.onEvent = onEvent;
    this.running = false;
    this.progress = null;
    this.lastResult = null;
  }

  async update(sources, options = {}) {
    if (this.running) throw new Error("A threat-intelligence update is already running");
    this.running = true;
    this.progress = { phase: "starting", sources, startedAt: new Date().toISOString() };
    const credentials = await loadThreatCredentials();
    await appendAudit("threat-intel.update-started", { sources });
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL("./threat-update-worker.js", import.meta.url), {
        workerData: {
          dataDirectory: appPaths().data,
          sources,
          config: this.config.threatIntel,
          credentials,
          force: Boolean(options.force)
        },
        execArgv: ["--disable-warning=ExperimentalWarning"]
      });
      let settled = false;
      const finish = async (error, result) => {
        if (settled) return;
        settled = true;
        this.running = false;
        this.lastResult = result || { error: error?.message };
        this.progress = null;
        if (error) {
          await appendAudit("threat-intel.update-failed", { sources, error: error.message }).catch(() => {});
          reject(error);
        } else {
          await appendAudit("threat-intel.update-completed", { sources, results: result.results }).catch(() => {});
          resolve(result);
        }
      };
      worker.on("message", (message) => {
        if (message.type === "progress") {
          this.progress = { ...message.progress, at: new Date().toISOString() };
          this.onEvent({ type: "threat-intel.progress", progress: this.progress });
        } else if (message.type === "complete") finish(null, message.result);
        else if (message.type === "fatal") finish(new Error(message.error));
      });
      worker.on("error", (error) => finish(error));
      worker.on("exit", (code) => {
        if (code !== 0) finish(new Error(`Threat update worker exited with code ${code}`));
      });
    });
  }
}
