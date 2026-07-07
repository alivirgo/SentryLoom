import os from "node:os";

const COMMON_COMMANDS = Object.freeze([
  "scan.quick",
  "scan.full",
  "scan.startup",
  "scan.processes",
  "scan.external",
  "scan.cancel",
  "update.databases",
  "protection.fix-all",
  "protection.restart"
]);

export function platformFamily(platform = process.platform) {
  if (platform === "win32") return "windows";
  if (platform === "darwin") return "macos";
  if (platform === "linux") return "linux";
  return platform || "unknown";
}

export function endpointCapabilities(platform = process.platform) {
  const family = platformFamily(platform);
  const capabilities = [
    "antivirus.scan",
    "antivirus.quarantine",
    "antivirus.realtime",
    "monitor.process",
    "monitor.persistence",
    "monitor.ransomware",
    "monitor.removable-media",
    "monitor.network-metadata",
    "threat-intelligence.update",
    "audit.integrity",
    "management.verified-enrollment",
    "management.allowlisted-commands",
    "control.wake-on-lan",
    "telemetry.system",
    "telemetry.network",
    "telemetry.security"
  ];
  if (family === "windows") {
    capabilities.push(
      "monitor.windows-events",
      "monitor.firewall",
      "control.firewall-ioc",
      "control.dns-filtering",
      "control.usb-storage",
      "client.self-update",
      "ui.native-path-picker",
      "notification.desktop"
    );
  } else if (family === "linux") {
    capabilities.push(
      "monitor.linux-journal",
      "monitor.firewall",
      "control.firewall-ioc",
      "service.systemd",
      "notification.desktop"
    );
  } else if (family === "macos") {
    capabilities.push(
      "monitor.macos-unified-log",
      "monitor.firewall",
      "service.launchd",
      "notification.desktop"
    );
  }
  return [...new Set(capabilities)].sort();
}

export function supportedCommands(platform = process.platform) {
  const commands = [...COMMON_COMMANDS];
  if (platform === "win32") commands.push("client.update");
  return commands;
}

export function platformDescriptor() {
  return {
    family: platformFamily(),
    platform: os.platform(),
    release: os.release(),
    architecture: os.arch(),
    capabilities: endpointCapabilities(),
    supportedCommands: supportedCommands()
  };
}
