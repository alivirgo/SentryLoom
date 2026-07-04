# Changelog

All notable changes to SentryLoom will be documented here.

The project uses semantic versioning where practical.

## [Unreleased]

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
