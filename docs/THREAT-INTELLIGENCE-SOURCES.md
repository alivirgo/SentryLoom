# Threat-intelligence source policy

SentryLoom consumes indicators and detection signatures. It does not download
malware binaries, APK collections, password-protected sample archives, or
source-code collections intended to reproduce malware.

## Enabled sources

| Source | Imported data | Access and license note |
| --- | --- | --- |
| ClamAV Official | Cross-platform signatures | Official updater and database terms |
| MalwareBazaar | Exact file hashes | Free abuse.ch Auth-Key and provider terms |
| URLhaus | Payload hashes | Free abuse.ch Auth-Key and provider terms |
| Feodo Tracker | Botnet C2 IPs | Public abuse.ch feed |
| ThreatFox | Hashes and network IOCs | Free abuse.ch Auth-Key and provider terms |
| Spamhaus DROP | IPv4 and IPv6 CIDR ranges | Free of charge under the [DROP fair-use terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/) |
| CIRCL MISP OSINT | Detection-marked hashes and network IOCs | Public MISP feed; recent events are retained locally |
| Botvrij MISP OSINT | Detection-marked hashes and network IOCs | Public MISP feed; recent events are retained locally |
| Linux Malware Detect | Linux-focused SHA-256 hashes | GPL-2.0 signature pack from R-fx Networks |

Downloads use allowlisted HTTPS hosts, strict response-size and timeout limits,
transactional database writes, and minimum update intervals. Files are matched
against the local SQLite index after updating; scan-time provider lookups are
not performed.

ClamAV, MalwareBazaar, MISP, and the other general sources include indicators
for Windows, Linux, macOS, and Android malware. Linux Malware Detect adds
Linux-focused coverage. There is no trustworthy, unrestricted Objective-See or
Apple XProtect hash feed for SentryLoom to redistribute; macOS retains its
built-in XProtect protection alongside SentryLoom's cross-platform sources.

## Not bundled

| Provider | Reason |
| --- | --- |
| VirusTotal public API | It has per-minute, daily, and monthly quotas; its public API is not permitted for commercial products or business workflows. It is not an unlimited feed. |
| AndroZoo | Access is academic, personal, expires after six months, is capped at 500,000 APK requests, forbids commercial use, and forbids redistribution. |
| theZoo | It distributes live malware samples. Pulling those samples onto managed endpoints would create risk without improving the safe IOC index. |
| Arbitrary MISP default feeds | MISP's catalog contains feeds with independent licenses, credentials, lockouts, and false-positive profiles. SentryLoom enables two public MISP-format OSINT feeds rather than pretending every catalog entry has uniform terms. |

An organization may export authorized indicators from its own MISP into a
reviewed signed SentryLoom signature bundle. Provider authorization and data
handling obligations remain the organization's responsibility.
