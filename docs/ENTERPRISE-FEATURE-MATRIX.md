# Enterprise feature matrix

Platform detail and permission boundaries are documented in
[`CROSS-PLATFORM-CLIENTS.md`](CROSS-PLATFORM-CLIENTS.md). Desktop rows apply to
Windows, Linux, and macOS where the operating system exposes the required
user-mode API; Android uses the separate ownership-aware controls listed
below.

| Capability | Current state | Notes |
|---|---|---|
| Offline on-demand scanning | Implemented | Quick, full, custom file/folder, startup targets, active process images, removable drives |
| Native custom-scan picker | Implemented | Authenticated backend opens Windows file or folder dialogs |
| Exact signatures | Implemented | SHA-256, local database |
| Heuristic scanning | Implemented | Script, extension, format, PE entropy |
| Realtime file monitoring | Implemented (user mode) | All fixed drives; elevated task for protected paths |
| Downloads deep protection | Implemented | Dedicated recursive watcher, priority queue, write stabilization, local intelligence, and ClamAV verification |
| Network metadata monitoring | Implemented | TCP endpoints and DNS cache against local IOCs |
| Process/image telemetry | Implemented (polling) | Parent PID, executable, command-line hash, Authenticode, local signature scan |
| Persistence monitoring | Implemented | Run keys, startup, services, tasks, WMI consumers |
| Ransomware behavior signals | Implemented (report-only) | Canary tamper and write-burst detection |
| Windows security events | Implemented | PowerShell, Defender/AMSI-correlated, Code Integrity, task and Security channels |
| Removable-media arrival scan | Implemented | Automatic scan when the scanner is available |
| Firewall integrity monitoring | Implemented | Profiles and new inbound allow rules |
| IOC network blocking | Implemented (opt-in) | Windows Defender Firewall/WFP; confidence >= 90 |
| Ad/tracker DNS filtering | Implemented | Selectable AdGuard, Control D, or Mullvad profile; Windows DoH and reversible adapter backup |
| Packet payload inspection | Not implemented | Requires a signed WFP/Npcap-class driver |
| Quarantine | Implemented | AES-256-GCM, authenticated restore |
| Realtime quarantine UI | Implemented | Table synchronizes when the count changes and whenever the tab opens |
| Actionable detection notifications | Implemented | Windows alert for file, scan, process, network, ransomware, and Defender detections; click opens Quarantine |
| Offline signed updates | Implemented | Ed25519 trust store and import |
| Community threat feeds | Implemented | ClamAV, MalwareBazaar, URLhaus, Feodo Tracker, ThreatFox, Spamhaus DROP, CIRCL/Botvrij MISP OSINT, Linux Malware Detect |
| Network IOC index | Implemented | IP, CIDR, domain, URL, and IP:port lookup; no automatic blocking |
| Manual update controls | Implemented | Per-source and update-all dashboard buttons |
| Audit trail | Implemented | HMAC-chained JSONL |
| Scheduling | Implemented | Windows Task Scheduler |
| Idle-time scanning | Implemented | Weekly full scan gated by Windows idle state |
| Local management UI | Implemented | Authenticated loopback dashboard |
| On-premises fleet management | Implemented (initial) | Automatic enrollment requests, administrator approve/reject, certificate pinning, telemetry, command status, and fleet dashboard |
| Remote antivirus actions | Implemented (allowlisted) | Quick/full/startup/process/external scans, cancel, updates, Fix All, and protection restart; no shell execution |
| Security score and Action Center | Implemented | Runtime/configuration-derived score with conservative Fix All |
| Scan history and reports | Implemented | Job-level summaries with detection and error outcomes |
| Local reputation explorer | Implemented | Hash, IP, domain, URL, and IP:port lookup; no user data uploaded |
| Runtime performance telemetry | Implemented | Engine resident memory and uptime |
| Antivirus test-file coverage | Implemented | EICAR plus published FortiGuard ML, sandbox, and zero-hour test markers |
| Dark and light themes | Implemented | Persisted local appearance preference |
| USB removable-storage control | Implemented | Reversible Windows removable-storage policy; USB HID keyboards and mice remain available |
| Whole-device traffic redirection | Not implemented | Requires a signed WFP connect-redirect callout driver and protected proxy service |
| TLS interception | Not implemented by design | A private root CA would create credential and certificate-pinning risk without providing complete traffic coverage |
| Policy/exclusions | Implemented | Local configuration |
| CLI automation | Implemented | JSON output and exit codes |
| Kernel pre-execution blocking | Not implemented | Requires a Microsoft-signed minifilter |
| Memory/exploit protection | Not implemented | Requires ETW/AMSI/driver engineering |
| Active-process image scan | Implemented | Scans executable files backing running processes; does not claim raw memory inspection |
| Native ETW process/image collector | Not implemented | Current collector uses bounded polling plus Windows event channels |
| Ransomware process containment | Not implemented | Signals are report-only; suspension requires reliable process attribution |
| Archive/Office deep parsing | Not implemented | Needs sandboxed parsers and fuzzing |
| Malware reputation/intelligence | Not implemented | Offline curated feed required |
| Enterprise fleet console | Implemented (initial) | Optional on-premises SentryLoom HQ; standalone mode remains fully supported |
| Independent certification | Not completed | Requires external labs and operational maturity |
| Linux service and telemetry | Implemented | systemd service; process, persistence, journal, removable media, firewall, TCP, hardware, storage, and network inventory |
| macOS service and telemetry | Implemented | launchd service; process, LaunchAgent/Daemon, unified log, removable media, firewall, TCP, code-signing, hardware, and storage inventory |
| Cross-platform command negotiation | Implemented | Endpoint advertises supported commands; HQ disables and rejects incompatible actions |
| Android system/app inventory | Implemented | Hardware, OS/build/patch, battery, memory, storage, network/private DNS/proxy, installed applications, signer hashes, permissions, usage, ownership, and APK hashes |
| Android protection/event telemetry | Implemented | Persistent package/network monitoring, posture checks, tamper-evident events, scan history, command audit, and HQ diagnostics |
| Android remote lock | Implemented (permission-gated) | Requires user-approved Device Administrator or enterprise owner state |
| Android Bluetooth-sharing policy | Implemented (permission-gated) | Requires Profile Owner or Device Owner |
| Android enterprise restrictions | Implemented (permission-gated) | Camera, screen capture, unknown sources, safe boot, factory reset, and USB data signaling depend on Profile/Device Owner capabilities |
| Android remote reboot | Implemented (permission-gated) | Requires Device Owner; HQ asks for administrator confirmation |
| Android arbitrary personal-file scan | Platform-limited | Scoped storage requires user-granted document/folder access |
| Android remote wipe | Not implemented by design | Destructive deprovisioning needs a separately authorized enterprise workflow |
