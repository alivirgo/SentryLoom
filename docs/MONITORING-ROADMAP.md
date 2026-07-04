# Monitoring expansion status

## Implemented in 0.6.0

- Process/parent discovery, command-line hashing, Authenticode status, and executable signature scanning.
- Persistence baselines for Run keys, startup folders, automatic services, scheduled tasks, and WMI consumers.
- Hidden ransomware canaries and report-only write-burst detection.
- PowerShell, Defender/AMSI-correlated, Code Integrity, Task Scheduler, and Security event collection with unavailable-channel isolation.
- Removable-volume arrival detection and automatic local scans.
- Windows Firewall profile and inbound-allow integrity monitoring.
- Opt-in confidence-gated outbound IP blocking through Windows Defender Firewall/WFP.

## Remaining native and containment work

1. Replace process polling with a signed native ETW consumer for loss-resistant process, thread, and image-load events.
2. Attribute filesystem bursts and canary tampering to a process before offering suspension or termination.
3. Add drivers, browser extensions, Office add-ins, AppLocker/WDAC, and mapped-network-volume baselines.
4. Enable native AMSI content integration after establishing a signed protected service and privacy/retention policy.

## Network-focused additions

1. **Native WFP flow telemetry** — current enforcement delegates IP rules to Microsoft-signed Windows Defender Firewall/WFP. A separately Microsoft-signed callout driver is still needed for loss-resistant per-flow telemetry owned directly by SentryLoom.
2. **DNS policy integrity** — detect adapter changes, VPN overrides, browser-owned DoH, proxy changes, NRPT/Group Policy, and DNS leakage. Reapply only under an explicit “enforce profile” policy.
3. **TLS metadata** — record destination, SNI where visible, certificate chain and signer anomalies without decrypting content. TLS interception should remain a separate opt-in enterprise product with managed trust roots.
4. **Local firewall change monitoring** — baseline Windows Firewall rules and alert on newly opened inbound ports, disabled profiles, or broad allow rules. Never delete rules automatically without policy attribution.
5. **Packet inspection** — full payload IDS requires a signed capture/WFP driver, protocol parsers, stream reassembly, strict memory bounds, fuzzing, and privacy controls. It should not be improvised inside the dashboard process.

## Platform hardening that monitoring depends on

- Run collectors as a signed, auto-start Windows service under a restricted service SID.
- Use authenticated local IPC and keep the dashboard unprivileged.
- Protect configuration and evidence with explicit ACLs, DPAPI/TPM-bound secrets, rotation, and bounded retention.
- Add tamper signals for service stops, task changes, log deletion, clock rollback, and signature/configuration replacement.
- Provide policy versioning, safe mode, health watchdogs, back-pressure metrics, and deterministic rollback.

The order matters: process/persistence telemetry and ransomware correlation provide more defensive value than collecting packet payloads, while carrying substantially less privacy and stability risk.
