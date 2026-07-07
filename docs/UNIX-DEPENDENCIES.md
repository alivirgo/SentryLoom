# Ubuntu and macOS dependencies

`installer/install-unix.sh` is a root installer and dependency bootstrapper.
It does not require Node.js to be installed beforehand.

## Node.js runtime

The installer detects `uname -s` and `uname -m`, maps them to one of:

- `linux-x64`
- `linux-arm64`
- `darwin-x64`
- `darwin-arm64`

It downloads the official Node.js 24.18.0 LTS `.tar.xz` archive and
`SHASUMS256.txt` from `https://nodejs.org/dist/v24.18.0/`, verifies the
archive's SHA-256 digest, and extracts it into:

```text
/opt/sentryloom/runtime/node
```

The system Node.js installation is not changed. The CLI wrapper, systemd
service, and launchd service all invoke the private binary directly:

```text
/opt/sentryloom/runtime/node/bin/node
```

Set `SENTRYLOOM_NODE_VERSION` only when deliberately testing another Node 24
release that exists in the official Node.js archive.

## Ubuntu packages

On Ubuntu/Debian, the installer runs `apt-get update` and installs:

| Package | Loaded capability |
| --- | --- |
| `ca-certificates`, `curl`, `xz-utils` | Verified private Node.js download and extraction |
| `procps` | Process inventory through `ps` |
| `iproute2` | TCP connection metadata through `ss` |
| `util-linux` | Removable-volume inventory through `lsblk` |
| `nftables` | Dedicated SentryLoom IOC block table |
| `ufw` | Host-firewall posture reporting |
| `clamav`, `clamav-freshclam` | Optional ClamAV second-opinion scan and database updates |
| `libnotify-bin` | Desktop notifications through `notify-send` |
| `zenity` | Native file and folder picker |
| `xdg-utils` | Opening the local dashboard with `xdg-open` |

`systemctl` and `journalctl` are supplied by the existing Ubuntu systemd
installation. The installer writes `/etc/systemd/system/sentryloom.service`
and starts it with `systemctl enable --now`.

## macOS commands

The following operating-system commands are validated before installation:

| Command | Loaded capability |
| --- | --- |
| `ps` | Process inventory |
| `log` | Unified security-event collection |
| `codesign` | Executable signature verification |
| `mount` | Removable-volume inventory |
| `pfctl` | Packet-filter posture |
| `lsof` | TCP connection metadata |
| `osascript` | Native selection and desktop notification |
| `launchctl` | Resident launchd service |
| `curl`, `tar`, `shasum` | Verified private Node.js runtime |

ClamAV is optional on macOS. If Homebrew already exists, the installer invokes
it as the console user to install `clamav`. It does not install Homebrew
silently. Without ClamAV, SentryLoom's built-in signatures, hashing,
heuristics, quarantine, monitoring, telemetry, and HQ management remain
active.

The launch daemon is written to:

```text
/Library/LaunchDaemons/org.sentryloom.endpoint.plist
```

## Runtime PATH and diagnostics

Both service definitions receive this explicit PATH:

```text
/opt/sentryloom/runtime/node/bin:/opt/homebrew/bin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin
```

After installation, every discovered and missing collector command is written
to:

```text
/opt/sentryloom/dependencies.txt
```

This file is the first place to inspect when a platform collector is shown as
unavailable in HQ.
