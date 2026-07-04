# Architecture

## Trust boundaries

```text
Local files ──> Scanner ──> Detection policy ──> Encrypted quarantine
                    │               │
             Local signatures      Audit chain
                    │               │
             Signed import      Local dashboard/CLI
                                         │
                              Optional pinned HTTPS
                                         │
                                 SentryLoom HQ
```

The scanner does not execute inspected content. The dashboard binds only to `127.0.0.1` (or `::1` when explicitly configured), requires a random launch token to establish a session, uses an HttpOnly SameSite cookie, and requires a separate CSRF token for every mutation.

## Components

- `src/lib/scanner.js`: bounded file sampling, SHA-256 hashing, exact rules, content rules, and structural heuristics.
- `src/lib/quarantine.js`: authenticated encryption and lifecycle metadata.
- `src/lib/protection.js`: debounced filesystem monitoring and policy enforcement.
- `src/lib/signature-store.js`: built-in rules, trusted Ed25519 keys, and verified bundle imports.
- `src/lib/threat-feeds.js`: allowlisted downloads and provider-specific parsing.
- `src/lib/threat-index.js`: disk-backed exact-hash and network-IOC lookup plus feed state.
- `src/lib/threat-update-manager.js`: isolated worker orchestration for large updates.
- `src/lib/windows-monitoring.js`: fixed-drive discovery, elevation status, and DNS cache collection.
- `src/lib/network-monitor.js`: TCP endpoint polling and network-IOC correlation.
- `src/lib/advanced-monitoring.js`: process, persistence, canary, security-event, removable-volume, and firewall collectors.
- `src/lib/windows-telemetry.js`: bounded Windows CIM, event-log, Authenticode, volume, and firewall queries.
- `src/lib/firewall-policy.js`: validated high-confidence IP rules delegated to Windows Defender Firewall/WFP.
- `src/lib/windows-dns.js`: adapter discovery, DNS profile state, reversible backup, and scoped elevation.
- `src/lib/dns-profiles.js`: reviewed public filtering-resolver definitions.
- `src/lib/audit-log.js`: HMAC-SHA-256 record chain.
- `src/lib/engine.js`: shared orchestration for every interface.
- `src/lib/hq-client.js`: LAN discovery, certificate-pinned enrollment, telemetry, and allowlisted command delivery.
- `src/server.js`: loopback dashboard and protected API.
- `src/cli.js`: automation and service entry point.
- `server/`: on-premises HTTPS fleet service, SQLite state, discovery responder,
  management dashboard, and rotating maintenance authorization service.

Managed endpoints use HQ-issued maintenance passwords for critical local
changes. Administrator-generated passwords are the primary path and are
hash-only, expiring, use-limited, and revocable. For interactive requests the
endpoint creates an ephemeral RSA key pair, HQ allows 20 seconds for approval,
and the approved one-time password is encrypted to that key before delivery.

## Detection policy

Exact hash or explicitly confirmed content signatures may be quarantined automatically. Filename, entropy, format mismatch, and behavior-like script rules are heuristic and report-only by default. This separation is deliberate: aggressive automatic heuristics cause destructive false positives.

Files larger than the configured limit are reported as skipped. Symbolic links are not followed by default. Exclusions are path-boundary aware.

## Quarantine format

```text
SLOOMQ1 | 12-byte nonce | AES-256-GCM ciphertext | 16-byte authentication tag
```

The 256-bit master key is generated locally. Containers are verified during restore and written to a temporary exclusive path before being atomically moved into place. Existing destinations are not overwritten.

## Offline update chain

Signature databases are JSON payloads wrapped in an Ed25519-signed envelope. An endpoint imports a bundle only when its `keyId` is already in the local trust store and verification succeeds. The private key belongs on a separate secured signing workstation.

Community updates are a separate, explicitly networked path. The updater accepts only HTTPS URLs on hard-coded provider hosts, applies response limits and timeouts, validates ClamAV CVD checksums, and performs transactional SQLite imports in a worker thread. Scanning queries this index locally and makes no provider requests.

HQ is a second, explicitly opt-in network boundary. Standalone mode creates no
HQ connection. A prospective managed endpoint submits a rate-limited request
without user credentials and stores an encrypted high-entropy request secret.
Only administrator approval allows HQ to issue the independent device
credential. Managed endpoints pin the server certificate SHA-256 fingerprint,
push sanitized operational telemetry, and poll for predefined commands. The
command protocol has no arbitrary executable, script, path, or shell-command
field. Loss of HQ connectivity does not alter local protection state.

Hash indicators from ClamAV, MalwareBazaar, URLhaus, and ThreatFox join file scanning. Feodo Tracker and non-hash ThreatFox records are stored in `network_iocs`; they support local investigation without automatically mutating firewall or DNS policy.

Realtime file monitoring registers recursive Windows change notifications at each ready fixed-drive root. Events are debounced, bounded, and scanned with limited concurrency. The network monitor correlates active TCP endpoint metadata and cached DNS names with `network_iocs`. It does not intercept or decrypt packets.

DNS filtering is a user-initiated system mutation. The dashboard calls a narrowly scoped PowerShell helper through UAC instead of elevating the browser-facing dashboard process. The helper accepts only built-in profile IDs, registers provider DoH templates, applies addresses to the adapters recorded in the backup, tests resolution, and transactionally restores the backup on failure.

## Operational model

`Register-SentryLoom.ps1` registers per-user scheduled tasks:

- quick scan daily at 02:00, with start-when-available;
- full scan weekly while idle;
- realtime monitoring at user logon.

The native WinForms launcher runs resident protection and scheduled scans
without a console window, owns the notification-area health icon, and captures
bounded background output. The dashboard may also host realtime monitoring
while open. A local connector lease prevents duplicate HQ telemetry streams.
