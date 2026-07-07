# Cross-platform clients

## Capability negotiation

Every endpoint includes `capabilities.features` and `capabilities.commands`
in telemetry. HQ disables unsupported controls in the device dialog and
rejects unsupported commands server-side. Older Windows clients that predate
capability negotiation retain their original allowlist for compatibility.

This prevents a Windows update package, Android Device Owner command, or
Linux-only control from being queued to the wrong endpoint.

## Ubuntu and Linux

The existing Node endpoint now selects Linux collectors for:

- process inventory with parent, executable, creation time, and hashed command
  line telemetry;
- enabled systemd services and desktop autostart persistence;
- warning-and-higher systemd journal security events;
- removable volumes from `lsblk`;
- host firewall posture from UFW/nftables;
- TCP connection metadata from `ss`;
- operating-system release, CPU, memory, load, boot time, storage, users, and
  network-interface inventory;
- realtime file monitoring, scanning, encrypted quarantine, threat feeds,
  ransomware canaries, audit integrity, and HQ management;
- opt-in high-confidence IOC blocks in a dedicated `inet sentryloom` nftables
  table.

Install from a release tree:

```text
sudo bash installer/install-unix.sh
sudo sentryloom dashboard
```

Node.js does not need to be preinstalled. The installer downloads and verifies
an official private Node.js 24 runtime, installs Ubuntu collector packages with
APT, and records every loaded command in
`/opt/sentryloom/dependencies.txt`. See
[`UNIX-DEPENDENCIES.md`](UNIX-DEPENDENCIES.md) for the exact package-to-feature
mapping.

The installer uses `/opt/sentryloom` for immutable program files,
`/var/lib/sentryloom` for mutable state, `/usr/local/bin/sentryloom` for the
CLI, and `sentryloom.service` for resident protection.

Dependencies used when available are `ss`, `lsblk`, `systemctl`, `journalctl`,
`nft`, `ufw`, `zenity`, and `notify-send`. Missing optional utilities degrade
their individual collector without stopping local file protection.

## macOS

The same Node endpoint selects macOS collectors for:

- process inventory;
- LaunchAgents and LaunchDaemons;
- error/fault entries from the unified log;
- mounted removable volumes under `/Volumes`;
- application firewall and packet-filter posture;
- established TCP metadata from `lsof`;
- executable signature status from `codesign`;
- native file/folder selection with AppleScript and desktop notifications;
- operating-system, hardware, memory, load, storage, user, and interface
  telemetry;
- scanning, quarantine, threat feeds, audit integrity, ransomware canaries,
  realtime monitoring, and HQ management.

`installer/install-unix.sh` creates
`/Library/LaunchDaemons/org.sentryloom.endpoint.plist`. Grant Full Disk Access
to the Node/SentryLoom executable if protected user data must be monitored.
macOS does not permit an unsigned user-mode application to claim kernel-level
pre-execution protection or unrestricted device control.

## Android

The native client under `clients/android` reports hardware, OS/build, patch,
battery, memory, storage, network/private-DNS/proxy, application inventory,
signers, permission-risk signals, usage, management ownership, and runtime
state. Its persistent protection service monitors package and network changes,
checks security posture, retains tamper-evident events and scan history, hashes
installed APKs, and implements certificate-pinned verified enrollment with
credentials protected by Android Keystore.

Remote controls are ownership-aware:

| Control | Normal app | Device Admin | Profile Owner | Device Owner |
| --- | ---: | ---: | ---: | ---: |
| Inventory and APK hash scan | Yes | Yes | Yes | Yes |
| Refresh telemetry | Yes | Yes | Yes | Yes |
| Lock device | No | Yes | Yes | Yes |
| Bluetooth-sharing policy | No | No | Yes | Yes |
| Camera and screen-capture policy | No | No | Yes | Yes |
| Unknown-source and safe-boot policy | No | No | Yes | Yes |
| Factory-reset prevention | No | No | Yes | Yes |
| USB data-signaling policy | No | No | No | Yes |
| Reboot device | No | No | No | Yes |

See [the Android client README](../clients/android/README.md) for building,
provisioning, and Android platform boundaries.

## Security invariants

- All management transport is pinned HTTPS.
- New endpoints require a six-digit out-of-band enrollment check.
- Endpoint credentials are encrypted at rest.
- HQ accepts only predefined command identifiers.
- The endpoint independently rejects commands outside its advertised
  platform allowlist.
- Telemetry has bounded arrays and string lengths and omits stored secrets.
- Loss of HQ connectivity never disables local desktop protection.
