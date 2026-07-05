# SentryLoom HQ

SentryLoom HQ is the on-premises management service for SentryLoom endpoints.
It uses HTTPS, per-device bearer credentials, certificate pinning,
administrator-approved enrollment requests, SQLite persistence, and
allowlisted remote actions.

## Live endpoint operations

Open an enrolled endpoint from **Fleet overview** to see its complete current
security state. Approved clients report approximately every two seconds; the
open endpoint view refreshes on the same cadence.

The operations view includes:

- Security score, posture issues, online state, and recent trends
- Real-time file and deep Downloads scanning health
- Network, DNS, process, persistence, ransomware, Windows event, removable
  media, and firewall-integrity monitoring
- Active scan progress and completed scan history
- Signature, ClamAV, and threat-intelligence update health
- DNS filtering, USB storage, and firewall policy state
- Quarantine inventory metadata, security events, audit activity, and runtime
  resource usage
- Allowlisted remote-action status and result history

HQ stores the latest full sanitized snapshot for immediate display and samples
historical trend points at a bounded interval. Clients do not send quarantined
file contents, private keys, authentication secrets, or threat-feed credentials.

## Server-managed abuse.ch access

Add or rotate the abuse.ch Auth-Key under **HQ data and operations settings**.
HQ protects it with Windows DPAPI and restricts its data directory to
`SYSTEM` and local administrators. The key is never returned by an API and is
never sent to an endpoint.

Managed clients obtain MalwareBazaar, URLhaus, and ThreatFox data through an
allowlisted HQ gateway over their authenticated, certificate-pinned device
session. HQ adds the key only to the upstream abuse.ch request, enforces
response-size and timeout limits, and caches responses to avoid a fleet-wide
request burst. The client displays **Auth-Key is added and maintained by
SentryLoom HQ** after HQ confirms configuration.

DPAPI `LocalMachine` protection intentionally binds the secret ciphertext to
the HQ Windows machine. After disaster recovery onto different hardware,
enter the key again instead of copying `hq-secrets.json`.

## Publish and deploy client updates

Remote updates require clients running SentryLoom 0.16.0 or later. Install that
version normally once to bootstrap the local update agent. Future releases can
then be installed without visiting the endpoint.

Build a release with your trusted Authenticode code-signing certificate, then
publish the signed Setup executable from an elevated HQ PowerShell session:

```powershell
.\Publish-SentryLoomUpdate.ps1 `
  -SetupFile C:\Releases\SentryLoom-Setup-0.16.11.exe `
  -ReleaseNotes 'Security engine and stability update'
```

The publisher rejects unsigned packages and invalid Windows signatures. In the
HQ console, review **Managed updates** and select **Deploy to eligible
devices**. The client downloads through its
authenticated, certificate-pinned HQ session and independently verifies:

- Exact package name, size, version, and SHA-256
- A Windows-valid Authenticode signature
- The manifest signer certificate thumbprint
- The exact Authenticode certificate thumbprint and subject recorded by HQ

To queue every newer signed release automatically, set
`updates.autoDeploy` to `true` in `data\config.json` and restart HQ. Update
commands remain allowlisted and cannot execute arbitrary commands.

### One-click staging-folder deployment

HQ server settings default the staging folder to:

```text
Z:\Extreme Control\SentryLoom Updates
```

Place signed packages there using the required
`SentryLoom-Setup-x.y.z.exe` filename. The settings page reports whether the
HQ `SYSTEM` task can read the folder and which semantic version is newest.
Select **Publish latest and deploy** to validate the newest file's embedded
version and Authenticode signature, copy it atomically into the HQ repository,
write its SHA-256 manifest, and queue every eligible client.

Drive mappings are session-specific. If `Z:` is a mapped network drive, use
the share's UNC path in server settings, such as
`\\fileserver\releases\SentryLoom Updates`. Grant both share and NTFS read
permission to the HQ computer account (`DOMAIN\HQSERVER$`). Do not grant write
access to HQ; the development/signing account should remain the only publisher
that can place files in staging.

For a local staging volume, Setup grants the HQ `SYSTEM` identity read and
execute access when the folder already exists.

## Wake-on-LAN

Current clients report sanitized physical MAC, IPv4 address, and subnet
metadata. Open an endpoint in HQ and select **Wake on LAN** to send three
UDP/9 magic packets to each reported directed-broadcast address.

Setup enables the required HQ outbound firewall rule and requests
`WakeOnMagicPacket` on compatible client adapters. Wake-on-LAN must also be
enabled in the endpoint firmware and NIC driver. Directed broadcasts normally
work only on the same LAN/VLAN unless routers are explicitly configured to
forward them.

## Initialize on the HQ Windows server

Run `SentryLoom-HQ-Setup-0.4.5.exe` and provide the server's DNS/computer name.
Setup installs prerequisites, initializes new servers, preserves existing data
during upgrades, registers the self-restarting startup task, and asks for the
administrator password with confirmation. On upgrade, the entered password
becomes the new HQ console password.

The HQ console also provides rotating endpoint maintenance passwords. These
are separate from the HQ console password: they are long, expiring,
use-limited, revocable, and stored only as hashes. Endpoints can request a
one-time password for immediate administrator approval; the approval window is
20 seconds and delivery is encrypted to that endpoint.

The **HQ data and operations settings** panel provides discrete controls for
30/90/365-day logging retention, offline alert delay, administrator session
lifetime, failed-login limits, maintenance-password defaults, and automatic
deployment of trusted signed updates. Settings are written atomically to the
existing HQ configuration.

Setup upgrades stop HQ before making a restricted administrator-only backup of
the database, TLS certificate, configuration, update repository, and
operational history. Existing values are retained unless a versioned schema
migration explicitly changes them.

For a source installation, run PowerShell as Administrator:

```powershell
cd .\server
.\Initialize-SentryLoomHq.ps1 -PublicHost security-hq -RegisterStartupTask
```

Save the generated administrator password and certificate SHA-256 fingerprint.
Open `https://security-hq:8443`. New endpoints appear in the approval queue;
approve or reject them before management begins.

Allow inbound TCP 8443 and UDP 32110 only from managed LAN/VPN ranges. Do not
publish the service directly to the public internet.

## Security model

- Standalone endpoints do not contact HQ.
- Discovery advertises only HQ name, URL, and certificate fingerprint.
- Enrollment requests require no client-side user authentication, are rate-limited, and require explicit administrator approval.
- Pending clients use an automatically generated high-entropy request secret so another machine cannot claim an approved credential.
- Each endpoint receives an independent revocable 256-bit token.
- Clients pin the TLS certificate fingerprint, including with a self-signed HQ certificate.
- The server can queue only predefined SentryLoom actions; it has no shell-command API.
- Local protection continues if HQ is offline.

## Restart after an update

From an Administrator PowerShell window:

```powershell
.\Restart-SentryLoomHq.ps1
```

Alternatively, double-click `Restart-SentryLoomHq-Admin.bat`. It requests
administrator permission automatically and displays the restart result.
