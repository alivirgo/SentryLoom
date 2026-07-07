import {
  discoverRemovableDrives as discoverWindowsRemovableDrives,
  readAuthenticodeStatus,
  readFirewallSnapshot as readWindowsFirewallSnapshot,
  readPersistenceSnapshot as readWindowsPersistenceSnapshot,
  readProcessSnapshot as readWindowsProcessSnapshot,
  readWindowsSecurityEvents
} from "./windows-telemetry.js";
import {
  discoverRemovableDrives as discoverUnixRemovableDrives,
  readExecutableTrust,
  readFirewallSnapshot as readUnixFirewallSnapshot,
  readPersistenceSnapshot as readUnixPersistenceSnapshot,
  readProcessSnapshot as readUnixProcessSnapshot,
  readSecurityEvents as readUnixSecurityEvents
} from "./unix-telemetry.js";

const windows = () => process.platform === "win32";

export function readProcessSnapshot() {
  return windows() ? readWindowsProcessSnapshot() : readUnixProcessSnapshot();
}

export function readPersistenceSnapshot() {
  return windows() ? readWindowsPersistenceSnapshot() : readUnixPersistenceSnapshot();
}

export function readSecurityEvents(since) {
  return windows() ? readWindowsSecurityEvents(since) : readUnixSecurityEvents(since);
}

export function readExecutableTrustStatus(file) {
  return windows() ? readAuthenticodeStatus(file) : readExecutableTrust(file);
}

export function discoverRemovableDrives() {
  return windows() ? discoverWindowsRemovableDrives() : discoverUnixRemovableDrives();
}

export function readFirewallSnapshot() {
  return windows() ? readWindowsFirewallSnapshot() : readUnixFirewallSnapshot();
}
