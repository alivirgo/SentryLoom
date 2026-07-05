# Changelog

All notable changes to SentryLoom will be documented here.

The project uses semantic versioning where practical.

## [0.16.10] - 2026-07-05

SentryLoom Endpoint Security v0.16.10 ships with SentryLoom HQ v0.4.5.

### Managed upgrade authorization recovery

- Added a bounded pre-install bootstrap that recovers an enrolled HQ after its
  address changes, before the protected installed files are replaced.
- The bootstrap updates only the encrypted HQ URL after the existing pinned
  certificate and device token both authenticate at the discovered address.
- Valid HQ maintenance passwords now work during upgrades even when the old
  stored HQ address is offline.
- Clean and previously standalone installations continue without an HQ
  password. Previously managed installations still require authorization
  before downgrading to standalone mode.

## [0.16.9] - 2026-07-05

SentryLoom Endpoint Security v0.16.9 ships with SentryLoom HQ v0.4.5.

### Verified enrollment and moved-HQ recovery

- Added client-generated six-digit enrollment verification without disclosing
  the code in the initial request. The client validates the administrator's
  proof before accepting its HQ credential.
- Added selectable LAN discovery and automatic verified re-enrollment after
  the HQ revokes or loses a device credential.
- Added safe address recovery when an enrolled HQ moves to another IP. The
  client accepts the new URL only when the pinned TLS certificate and existing
  device token both authenticate there.
- Released terminal enrollment leases after rejection or a wrong code so a
  corrected request can proceed without restarting background protection.
- Restored cancellation to standalone mode while approval is still pending.

## [0.16.8] - 2026-07-05

SentryLoom Endpoint Security v0.16.8 ships with SentryLoom HQ v0.4.4.

### Quarantine index self-repair

- Prevented a missing or malformed quarantine index from aborting dashboard
  bootstrap and leaving every protection card indefinitely in `Checking`.
- Added an atomic last-known-good index, cross-process writer locking, and
  automatic recovery when the primary index is deleted or corrupted.
- Preserved malformed index bytes as SHA-256-addressed evidence and recorded
  every recovery in the authenticated audit log.
- Reconciled surviving encrypted quarantine containers after metadata loss.
  Recovered items remain isolated and visible without offering an unsafe
  restore to an unknown original path.

## [0.16.7] - 2026-07-05

SentryLoom Endpoint Security v0.16.7 ships with SentryLoom HQ v0.4.4.

### Server-owned abuse.ch authentication

- Moved the abuse.ch Auth-Key to HQ and removed the credential page from
  endpoint Setup.
- Protected the HQ key with Windows DPAPI, a dedicated random revision, and
  SYSTEM/administrator-only data-directory ACLs. The plaintext key is never
  written to configuration, logs, manifests, telemetry, or client storage.
- Added an authenticated, certificate-pinned HQ gateway for MalwareBazaar,
  URLhaus, and ThreatFox. HQ applies the key only to allowlisted upstream
  requests and caches bounded JSON responses to prevent fleet request bursts.
- Made managed client key controls read-only. Clients now show that abuse.ch
  access is maintained by HQ after the server confirms configuration, and
  remove any prior locally stored key when management enrollment begins.
- Preserved local encrypted key support for standalone endpoints only.

## [0.16.6] - 2026-07-05

SentryLoom Endpoint Security v0.16.6 ships with SentryLoom HQ v0.4.3.

### Unattended staged client releases

- Added a configurable HQ staging folder, defaulting to
  `Z:\Extreme Control\SentryLoom Updates`, with live service-account access
  status in server settings.
- Added one-click publication of the highest semantic-versioned client Setup.
  HQ independently validates its Windows Authenticode signature and embedded
  product version, copies it atomically into the update repository, creates
  the SHA-256 manifest, and queues every eligible endpoint.
- Kept update installation under the endpoint `SYSTEM` task so no user needs
  to touch the client.

### Wake-on-LAN and restart recovery

- Added sanitized physical MAC/subnet reporting and an HQ Wake-on-LAN action
  that sends repeated directed-broadcast magic packets.
- Added the required HQ outbound UDP/9 firewall rule and best-effort client
  NIC magic-packet configuration.
- Fixed the resident `protect` startup command so it starts the HQ connector
  after a reboot without waiting for someone to open the desktop console.

## [0.16.5] - 2026-07-04

SentryLoom Endpoint Security v0.16.5 fixes an enrolled-client state split that
could show **STANDALONE** in the desktop console while the resident endpoint
was already enrolled and reporting to HQ.

### Installation-directory tamper protection

- Made the installed application tree `SYSTEM`-owned and read/execute-only for
  users and administrators, blocking direct file modification and deletion.
- Added an elevated Start Menu maintenance action that validates the existing
  HQ one-time password before opening a five-minute writable window.
- Integrated the same authorization boundary with uninstall and interactive
  upgrades, with automatic permission relocking when maintenance is abandoned.
- Kept signed automatic updates operational under the machine account without
  exposing a reusable local bypass credential.

### One machine identity across Setup, protection, and GUI

- Moved endpoint configuration, encrypted enrollment, device identity,
  connector state, logs, quarantine, and update state from per-user
  `LocalAppData` to the machine-wide `%ProgramData%\SentryLoom` directory.
- Added a permission-controlled Setup migration that finds enrolled state from
  either the installing administrator or the active desktop user, preserving
  the existing device ID, HQ credential, settings, and history.
- Setup detects an already-approved enrollment and preserves it instead of
  submitting a duplicate approval request. Moving to another HQ remains a
  protected Settings action requiring the current HQ maintenance password.
- Resident protection now starts under the Windows machine account at system
  startup, independently of which administrator installed the application or
  which user signs in.
- Split the interactive tray icon from resident protection. The tray starts in
  each desktop session and reads the same machine-wide HQ connection state.
- Setup launches the console as the original desktop user, while common Start
  Menu and Desktop shortcuts remain available to all users.

### Read-only HQ discovery

- Finding HQ while already enrolled no longer replaces the visible active
  server fields. Discovery reports its results with **active HQ unchanged**,
  and the operator must explicitly select a result before starting a protected
  server move.
- Added regression coverage proving network discovery cannot clear or replace
  enrolled credentials.

## [0.16.4] - 2026-07-04

SentryLoom Endpoint Security v0.16.4 makes managed-client setup changes
explicit and auditable.

### Client Settings submission controls

- Added a persistent **Save server and request approval** button beside the HQ
  URL and certificate fingerprint fields.
- Added a dedicated **Submit password for next change** button for
  server-generated maintenance passwords. Submitted passwords remain only in
  client memory, are sent directly to HQ with the next protected action, and
  are cleared after a successful change.
- Added Enter-key submission, inline progress, validation errors, and
  state-specific instructions for standalone, pending, rejected, and enrolled
  endpoints.
- The 20-second administrator approval flow now loads its approved password
  through the same one-change submission path.

### Managed server-change protection

- Enrolled endpoints can now submit a different HQ server directly from
  Settings.
- Changing an existing HQ target requires a valid maintenance password from
  the current HQ before stored credentials are replaced or a request is sent
  to the new server.
- Added regression coverage for both visible submission controls and the
  maintenance-authorization boundary around HQ server changes.

## [0.16.3] - 2026-07-04

SentryLoom Endpoint Security v0.16.3 ships with SentryLoom HQ v0.4.2. This
release focuses on reliable cross-computer enrollment, state-preserving
Windows Setup upgrades, explicit protected-setting authorization, configurable
on-premises security telemetry retention, and trustworthy ClamAV updates.

### Cross-computer HQ enrollment and compatibility

- Fixed an upgrade defect where preserved credentials for an old HQ, such as
  `192.168.1.9`, remained authoritative after Setup successfully submitted an
  approval request to a newly entered server, such as `192.168.1.12`.
- A successfully submitted enrollment request now removes the previous
  encrypted HQ credential and stale connector snapshot. The resident client
  polls the new server, receives the approved token, resumes telemetry, and
  uses that server for maintenance authorization.
- Direct enrollment now clears obsolete pending-request state.
- Added HQ capability/version negotiation so older servers produce one
  actionable compatibility message instead of repeated “Device API route not
  found” errors.
- Changed absent remote capability metadata from “unsupported” to
  “legacy/unknown and verify on use,” preventing false HQ upgrade warnings
  between clients and servers running on different computers.
- Compatibility errors now identify the actual HQ URL being contacted so an
  operator can immediately detect an unintended server address.

### Endpoint settings and ClamAV reliability

- Added explicit per-setting authorization badges for standalone, password
  required, HQ offline, compatibility-checking, and HQ-upgrade-required states.
- Fixed FreshClam HTTPS error 60 on Windows by exporting the Windows trusted
  root stores to a private PEM bundle and passing it through
  `CURL_CA_BUNDLE`; TLS verification remains enabled.
- Added actionable FreshClam diagnostics for clock, TLS inspection, and
  trusted-root policy failures.

### Upgrade-safe endpoint and HQ state

- Added state-preserving Setup upgrades for endpoint settings, enrollment,
  credentials, quarantine, logs, history, threat data, certificates, HQ
  databases, and operational metadata.
- Added versioned configuration migrations, restricted pre-upgrade backups,
  and preservation manifests; state changes only through explicit schema
  migrations.

### HQ data retention and server policy

- Added discrete HQ controls for 30/90/365-day logging and telemetry retention,
  offline alert delay, administrator session lifetime, failed-login rate
  limits, maintenance password defaults, and signed-update auto-deployment.
- Retention cleanup runs immediately after a policy change and every six hours
  while preserving current device state and active security records.

### Documentation and quality

- Added a management PowerPoint with real endpoint and HQ screenshots.
- Added a complete Word operator guide covering installation on separate
  computers, enrollment, firewall rules, daily operation, maintenance
  authorization, updates, recovery, and troubleshooting.
- Added regression coverage proving that a new HQ request supersedes preserved
  credentials for a previous server.

## [0.16.1] - 2026-07-04

SentryLoom Endpoint Security v0.16.1 ships with SentryLoom HQ v0.4.1.

### Security and administration

- Added long, randomly generated HQ maintenance passwords that are shown once,
  stored only as SHA-256 hashes, expire after 5–60 minutes, have bounded use
  counts, and can be revoked immediately.
- Added device-scoped one-time passwords for endpoint-initiated maintenance
  requests. HQ administrators have 20 seconds to approve or reject each
  request, and approved passwords are RSA-OAEP encrypted for the requesting
  endpoint.
- Required maintenance authorization for managed critical settings, protection
  disablement, HQ disconnection, DNS/USB/firewall control changes, and the
  supported Windows uninstall flow.
- Added HQ rate limiting for invalid maintenance-password attempts and complete
  maintenance lifecycle records without retaining plaintext passwords.

### Setup and authentication

- Fixed HQ installer-selected passwords by transferring the exact Unicode value
  without placing it on the command line, hashing it with PBKDF2-SHA256, and
  verifying the stored hash before Setup can report success.
- Added actionable setup failure diagnostics and a persistent HQ installation
  log under `%ProgramData%\SentryLoom HQ\Logs`.
- Added detailed live installation activity panes to both Windows setup
  packages while keeping background commands hidden.

### Networking and Windows Firewall

- Added repeated directed-broadcast discovery on every active IPv4 subnet,
  alongside global broadcast and loopback discovery.
- Bound the HQ UDP responder to all IPv4 interfaces and added resilient
  discovery error reporting.
- Added named, grouped, verified Windows Firewall rules for HQ HTTPS,
  discovery requests, discovery responses, endpoint HTTPS, and endpoint
  discovery traffic.
- Scoped HQ inbound rules to `LocalSubnet`, supported Domain/Private/Public
  Windows profiles, and removed all SentryLoom-owned rules during uninstall.

### Endpoint and HQ interfaces

- Kept the endpoint enrollment request button visible for new, pending,
  rejected, and retryable approval requests.
- Added the endpoint one-time maintenance-password field and 20-second
  administrator request workflow.
- Added the HQ rotating-password generator, expiry/use selection, active
  password inventory, immediate revocation, live client approval queue, and
  desktop notification support.

### Quality

- Added automated coverage for Unicode setup passwords, stored-password
  verification, directed IPv4 discovery, password consumption, expiration,
  client-specific encrypted delivery, and 20-second maintenance approval.
- Bumped the Windows endpoint to v0.16.1 and SentryLoom HQ to v0.4.1.

## [0.16.0] - 2026-07-04

- Open-sourced the endpoint and HQ under Apache License 2.0.
- Added resilient client/HQ reconnect behavior and lifecycle notifications.
- Added notification-area HQ reachability status.
- Added windowless background protection and bounded output viewing.
- Added separate endpoint and HQ installers.
- Added installer-selected HQ administrator passwords.
- Added automated GitHub stars/contributors history.
- Added authenticated HQ client updates.
- Added detailed endpoint operations and telemetry views.
- Added local reputation lookup and expanded monitoring.
