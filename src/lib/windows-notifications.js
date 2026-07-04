import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
const applicationDirectory = path.resolve(moduleDirectory, "..", "..");

function findingName(result) {
  return result?.findings?.[0]?.name || "Suspicious file";
}

function fileLabel(value) {
  if (!value) return "A file";
  return path.basename(value) || value;
}

export function notificationForEvent(event) {
  if (!event?.type) return null;

  if (event.type === "scan.completed" && Number(event.result?.detections) > 0) {
    const count = Number(event.result.detections);
    return {
      key: `scan:${event.result.id}`,
      title: `${count} threat${count === 1 ? "" : "s"} detected`,
      message: `The ${event.result.type || "requested"} scan found ${count} threat${count === 1 ? "" : "s"}. Click to review Quarantine.`,
      page: "quarantine"
    };
  }

  if (event.type === "detection") {
    return {
      key: `file:${event.result?.sha256 || event.result?.path || event.id}`,
      title: "Threat detected",
      message: `${findingName(event.result)} was detected in ${fileLabel(event.result?.path)}. Click to review.`,
      page: "quarantine"
    };
  }

  if (event.type === "process.detection") {
    return {
      key: `process:${event.process?.pid || ""}:${event.result?.sha256 || event.result?.path || event.id}`,
      title: "Malicious process detected",
      message: `${findingName(event.result)} was detected in ${fileLabel(event.result?.path || event.process?.executablePath)}. Click to review.`,
      page: "quarantine"
    };
  }

  if (event.type === "network.detection") {
    const endpoint = event.observation?.domain || event.observation?.endpoint || event.observation?.remote?.host || "a remote endpoint";
    return {
      key: `network:${event.channel}:${endpoint}`,
      title: "Network threat detected",
      message: `SentryLoom matched ${endpoint} to known threat intelligence. Click to review detections.`,
      page: "quarantine"
    };
  }

  if (event.type === "ransomware.canary-tampered") {
    return {
      key: `ransomware-canary:${event.path}`,
      title: "Possible ransomware activity",
      message: `A protected decoy file was ${event.missing ? "removed" : "changed"}. Click to review detections now.`,
      page: "quarantine"
    };
  }

  if (event.type === "ransomware.write-burst") {
    return {
      key: `ransomware-burst:${Math.floor(new Date(event.at || Date.now()).getTime() / 60000)}`,
      title: "Unusual file activity detected",
      message: `${event.events} file changes occurred in a short period. Click to review detections.`,
      page: "quarantine"
    };
  }

  if (event.type === "windows.security-event" && Number(event.event?.eventId) === 1116) {
    return {
      key: `defender:${event.event?.recordId || event.id}`,
      title: "Windows security detection",
      message: "Windows reported a malware detection. Click to review SentryLoom Quarantine.",
      page: "quarantine"
    };
  }

  if (event.type === "hq.connection-lost" || event.type === "hq.connection-error") {
    return {
      key: `hq-offline:${event.serverUrl || event.hqName || "managed"}:${event.id || event.at || ""}`,
      title: "Management connection interrupted",
      message: `${event.error || "SentryLoom HQ is unreachable"}. Local protection remains active and reconnection is automatic.`,
      page: "settings",
      severity: "Warning"
    };
  }

  if (event.type === "hq.connection-restored") {
    return {
      key: `hq-restored:${event.serverUrl || event.hqName || "managed"}:${event.id || event.at || ""}`,
      title: "Management connection restored",
      message: "This endpoint is online with SentryLoom HQ again.",
      page: "settings",
      severity: "Info"
    };
  }

  const failure = /(?:^|[.-])(?:error|failed|failure|unavailable)$/.test(event.type);
  if (failure) {
    return {
      key: `failure:${event.type}:${event.channel || event.source || ""}`,
      title: "SentryLoom needs attention",
      message: `${event.type.replaceAll(".", " ")}: ${event.error || event.reason || event.message || "an operation failed"}`,
      page: event.type.startsWith("scan.") ? "scan" : "activity",
      severity: "Error"
    };
  }

  return null;
}

export function showDetectionNotification(notification) {
  if (process.platform !== "win32" || !notification) return false;
  const script = path.join(applicationDirectory, "Show-SentryLoomNotification.ps1");
  const installedLauncher = path.join(applicationDirectory, "SentryLoom.exe");
  const developmentLauncher = path.join(applicationDirectory, "build", "output", "SentryLoom.exe");
  const launcher = fs.existsSync(installedLauncher) ? installedLauncher : developmentLauncher;
  if (!fs.existsSync(script) || !fs.existsSync(launcher)) return false;

  const powershell = path.join(
    process.env.SystemRoot || "C:\\Windows",
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
  );
  const child = spawn(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-WindowStyle",
    "Hidden",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    script,
    "-Title",
    String(notification.title).slice(0, 63),
    "-Message",
    String(notification.message).slice(0, 255),
    "-LauncherPath",
    launcher,
    "-Page",
    notification.page || "quarantine",
    "-Severity",
    notification.severity || "Warning"
  ], {
    detached: true,
    stdio: "ignore",
    windowsHide: true
  });
  child.on("error", () => {});
  child.unref();
  return true;
}
