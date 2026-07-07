import test from "node:test";
import assert from "node:assert/strict";
import {
  endpointCapabilities,
  platformFamily,
  supportedCommands
} from "../src/lib/platform-capabilities.js";
import { parseDfOutput } from "../src/lib/system-information.js";
import { parseLsblkJson, parsePsOutput } from "../src/lib/unix-telemetry.js";
import { parseLsofOutput, parseSsOutput } from "../src/lib/network-monitor.js";
import { deviceSupportsCommand } from "../server/src/server.js";

test("platform capabilities expose only implemented controls", () => {
  assert.equal(platformFamily("win32"), "windows");
  assert.equal(platformFamily("darwin"), "macos");
  assert.equal(platformFamily("linux"), "linux");
  assert.ok(endpointCapabilities("linux").includes("service.systemd"));
  assert.ok(endpointCapabilities("darwin").includes("service.launchd"));
  assert.ok(!endpointCapabilities("darwin").includes("control.firewall-ioc"));
  assert.ok(supportedCommands("win32").includes("client.update"));
  assert.ok(!supportedCommands("linux").includes("client.update"));
});

test("HQ capability negotiation rejects actions an endpoint did not advertise", () => {
  const modern = { status: { capabilities: { commands: ["scan.quick"] } } };
  assert.equal(deviceSupportsCommand(modern, "scan.quick"), true);
  assert.equal(deviceSupportsCommand(modern, "client.update"), false);
  assert.equal(deviceSupportsCommand({ status: {} }, "client.update"), true);
});

test("Unix process, storage, and removable-media parsers are bounded and deterministic", () => {
  assert.deepEqual(parsePsOutput(
    "42 1 1710000000 /usr/bin/node /usr/bin/node /opt/sentryloom/src/cli.js protect"
  )[0], {
    pid: 42,
    parentPid: 1,
    name: "node",
    executablePath: "/usr/bin/node",
    commandLine: "/usr/bin/node /opt/sentryloom/src/cli.js protect",
    creationDate: "1710000000"
  });
  const disks = parseDfOutput(
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda2 1000 400 600 40% /\n"
  );
  assert.equal(disks[0].availableBytes, 600 * 1024);
  const removable = parseLsblkJson(JSON.stringify({
    blockdevices: [{
      name: "sdb",
      rm: true,
      mountpoint: "/media/usb",
      label: "USB",
      fstype: "ext4",
      size: 1234
    }]
  }));
  assert.equal(removable[0].root, "/media/usb");
});

test("Linux ss and macOS lsof connection parsers normalize remote endpoints", () => {
  const linux = parseSsOutput(
    'ESTAB 0 0 192.168.1.5:41000 203.0.113.10:443 users:(("node",pid=42,fd=20))'
  );
  assert.equal(linux[0].remote.host, "203.0.113.10");
  assert.equal(linux[0].pid, 42);
  const mac = parseLsofOutput(
    "p77\nn192.168.1.5:51000->198.51.100.7:443\n"
  );
  assert.equal(mac[0].remote.port, 443);
  assert.equal(mac[0].pid, 77);
});
