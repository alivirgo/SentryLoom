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

## Publish and deploy client updates

Remote updates require clients running SentryLoom 0.16.0 or later. Install that
version normally once to bootstrap the local update agent. Future releases can
then be installed without visiting the endpoint.

Build a release with your trusted Authenticode code-signing certificate, then
publish the signed Setup executable from an elevated HQ PowerShell session:

```powershell
.\Publish-SentryLoomUpdate.ps1 `
  -SetupFile C:\Releases\SentryLoom-Setup-0.16.1.exe `
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

## Initialize on the HQ Windows server

Run `SentryLoom-HQ-Setup-0.4.0.exe` and provide the server's DNS/computer name.
Setup installs prerequisites, initializes new servers, preserves existing data
during upgrades, registers the self-restarting startup task, and asks for the
administrator password with confirmation. On upgrade, the entered password
becomes the new HQ console password.

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
