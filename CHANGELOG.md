# Changelog

All notable changes to SentryLoom will be documented here.

The project uses semantic versioning where practical.

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
