# Security policy and deployment boundary

## Supported versions

Security fixes are applied to the current `main` branch and the latest
published release. Older development builds may not receive backports.

## Report a vulnerability privately

Use GitHub's **Security → Report a vulnerability** flow:

https://github.com/alivirgo/SentryLoom/security/advisories/new

Do not open a public issue for an unpatched vulnerability. Include affected
versions, impact, prerequisites, reproduction steps, and a minimal safe proof
of concept. Never send live malware, credentials, private keys, certificates,
quarantine objects, personal files, or customer telemetry.

Maintainers will acknowledge a complete report as soon as practical, validate
the issue, coordinate a fix and disclosure, and credit reporters who want
public attribution.

## Use alongside Windows security

SentryLoom does not disable Microsoft Defender, Windows Firewall, SmartScreen, UAC, Secure Boot, or BitLocker. Keep those controls enabled.

## Implemented safeguards

- no cloud dependency; optional on-premises HQ telemetry is disabled in standalone mode and explicitly enrolled with certificate pinning;
- HTTPS-only, allowlisted feed hosts with download size, timeout, redirect, and update-frequency limits;
- standalone abuse.ch credentials encrypted locally with AES-256-GCM;
- managed abuse.ch credentials retained only by HQ under Windows DPAPI and
  restricted ACLs, with allowlisted feed responses delivered through the
  authenticated certificate-pinned device API;
- per-device HQ tokens encrypted locally with AES-256-GCM, independently revocable, and never returned by the dashboard API;
- HQ enrollment uses rate-limited device requests, explicit administrator approval, encrypted request secrets, pinned HTTPS, authenticated telemetry, admin CSRF protection, and allowlisted remote actions without a shell channel;
- network IOCs are indexed for lookup but never silently applied as Windows Firewall rules;
- public filtering DNS is applied only after confirmation and UAC approval, with a pre-change adapter backup and automatic failure rollback;
- advanced monitoring is report-only except exact file quarantine and explicitly enabled high-confidence firewall IOC rules;
- fixed-drive filesystem events and TCP/DNS metadata are monitored, but packet payloads and TLS contents are not intercepted;
- optional USB removable-storage blocking uses the documented Windows storage-class policy and preserves the prior policy for restoration;
- no execution of scanned content;
- bounded file size/sample size and bounded request bodies;
- symlink rejection during quarantine;
- authenticated encryption with exclusive temporary files;
- signed signature imports;
- loopback-only dashboard with launch/session/CSRF controls;
- strict content security policy and no third-party UI assets;
- tamper-evident audit chain;
- heuristics are not auto-quarantined by default;
- restore never overwrites an existing file.

## Not yet equivalent to a commercial enterprise antivirus

A commercial endpoint platform requires capabilities that cannot be honestly supplied as a small user-mode application:

- Microsoft-signed minifilter and process-protection drivers;
- Anti-Malware Scan Interface, ETW, ELAM, and Windows Security Center registration;
- pre-execution blocking, memory scanning, exploit prevention, and behavioral process graphs;
- boot-sector, firmware, NTFS alternate-data-stream, and offline recovery scanning;
- TLS/web/email traffic inspection and malicious-site reputation;
- kernel-enforced packet filtering or payload inspection through Windows Filtering Platform;
- whole-device traffic redirection, which requires a signed WFP connect-redirect callout driver and protected local proxy service;
- sandbox detonation and large continuously curated malware intelligence;
- anti-tamper protected services and enterprise identity/RBAC;
- mature RBAC, SIEM/SOAR integration, remote isolation, investigation workflows, and high-availability fleet operations;
- independent AV-TEST/AV-Comparatives testing, Microsoft signing, and false-positive certification;
- a staffed vulnerability response and malware research program.

The built-in database intentionally remains small. Optional community feeds add broad exact-hash coverage, but hash matching cannot detect polymorphic or previously unseen malware and is not a substitute for a fully integrated behavioral engine.

## Hardening roadmap

1. Move the service into a signed Windows Service running under a restricted service SID.
2. Protect the master key with Windows DPAPI/TPM and apply explicit ACLs to all state.
3. Add a signed minifilter for pre-open/pre-execution enforcement.
4. Integrate AMSI, ETW, Authenticode validation, and Windows Security Center.
5. Replace one-process-per-target `clamscan` execution with a restricted local `clamd` service and authenticated IPC.
6. Add archive/document parsers in isolated low-privilege worker processes.
7. Replace report-only ransomware signals with reliable ETW/WFP process attribution and conservative containment.
8. Build deterministic MSI/MSIX packaging, SBOMs, code signing, and reproducible releases.
9. Commission penetration testing, fuzzing, false-positive studies, and independent certification.

The prioritized monitoring expansion review is maintained in [docs/MONITORING-ROADMAP.md](docs/MONITORING-ROADMAP.md).

## Public bug reports

For non-sensitive bugs, record the engine version, Windows build, command,
sanitized error, and output of `node src/cli.js audit verify`. Do not include
malware samples, private keys, quarantine keys, credentials, or personal files.
