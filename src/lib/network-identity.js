import os from "node:os";
import { isIP } from "node:net";

const MAC_PATTERN = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function privateIpv4(address) {
  const [first, second] = String(address).split(".").map(Number);
  return first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 169 && second === 254);
}

export function collectWakeNetworkInterfaces(interfaces = os.networkInterfaces()) {
  const result = [];
  const seen = new Set();
  for (const [name, addresses] of Object.entries(interfaces || {})) {
    for (const item of addresses || []) {
      const family = item.family === 4 ? "IPv4" : String(item.family || "");
      const mac = String(item.mac || "").toLowerCase();
      const address = String(item.address || "");
      const netmask = String(item.netmask || "");
      if (family !== "IPv4" || item.internal || isIP(address) !== 4 || !privateIpv4(address) ||
          isIP(netmask) !== 4 ||
          !MAC_PATTERN.test(mac) || mac === "00:00:00:00:00:00") {
        continue;
      }
      const key = `${mac}|${address}|${netmask}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push({
        name: String(name).slice(0, 200),
        address,
        netmask,
        mac
      });
    }
  }
  return result.slice(0, 16);
}
