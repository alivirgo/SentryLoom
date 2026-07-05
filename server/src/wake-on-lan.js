import dgram from "node:dgram";
import { isIP } from "node:net";

const MAC_PATTERN = /^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;

function privateIpv4(address) {
  const [first, second] = String(address).split(".").map(Number);
  return first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 169 && second === 254);
}

export function normalizeMac(value) {
  const mac = String(value || "").trim();
  if (!MAC_PATTERN.test(mac)) return null;
  return mac.replaceAll("-", ":").toLowerCase();
}

export function createMagicPacket(macAddress) {
  const mac = normalizeMac(macAddress);
  if (!mac) throw new Error("Wake-on-LAN requires a valid client MAC address");
  const address = Buffer.from(mac.split(":").map((part) => Number.parseInt(part, 16)));
  return Buffer.concat([Buffer.alloc(6, 0xff), ...Array.from({ length: 16 }, () => address)]);
}

export function ipv4BroadcastAddress(address, netmask) {
  if (isIP(address) !== 4 || !privateIpv4(address) || isIP(netmask) !== 4) return null;
  const addressBytes = address.split(".").map(Number);
  const maskBytes = netmask.split(".").map(Number);
  const maskBits = maskBytes.map((part) => part.toString(2).padStart(8, "0")).join("");
  const prefixLength = maskBits.indexOf("0");
  if (!/^1+0+$/.test(maskBits) || prefixLength < 8 || prefixLength > 30) return null;
  return addressBytes.map((part, index) => (part | (255 ^ maskBytes[index])) & 255).join(".");
}

export function wakeTargets(device) {
  const interfaces = Array.isArray(device?.status?.device?.networkInterfaces)
    ? device.status.device.networkInterfaces
    : [];
  const targets = [];
  const seen = new Set();
  for (const item of interfaces) {
    const mac = normalizeMac(item?.mac);
    const broadcast = ipv4BroadcastAddress(String(item?.address || ""), String(item?.netmask || ""));
    if (!mac || !broadcast) continue;
    const key = `${mac}|${broadcast}`;
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({ mac, broadcast });
  }
  return targets;
}

export function sendMagicPacket(packet, broadcast, port = 9) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.close();
      if (error) reject(error);
      else resolve();
    };
    socket.once("error", finish);
    socket.bind(0, "0.0.0.0", () => {
      try {
        socket.setBroadcast(true);
      } catch (error) {
        finish(error);
        return;
      }
      socket.send(packet, port, broadcast, finish);
    });
  });
}

export async function wakeDevice(device, options = {}) {
  const send = options.send || sendMagicPacket;
  const repeats = Math.max(1, Math.min(5, Number(options.repeats) || 3));
  const targets = wakeTargets(device);
  if (!targets.length) {
    throw new Error(
      "This endpoint has not reported a usable physical MAC address and IPv4 subnet. " +
      "Update the client and wait for one telemetry report before using Wake-on-LAN."
    );
  }

  let packetsSent = 0;
  for (const target of targets) {
    const packet = createMagicPacket(target.mac);
    for (let attempt = 0; attempt < repeats; attempt += 1) {
      await send(packet, target.broadcast, 9);
      packetsSent += 1;
    }
  }
  return {
    deviceId: device.id,
    deviceName: device.name,
    macAddresses: [...new Set(targets.map((item) => item.mac))],
    broadcasts: [...new Set(targets.map((item) => item.broadcast))],
    packetsSent,
    sentAt: new Date().toISOString()
  };
}
