# Privacy

SentryLoom is local-first and has no analytics, advertising, tracking SDK,
mandatory account, or hosted telemetry service.

## Standalone endpoint

In standalone mode, security telemetry, scan history, quarantine metadata,
audit records, policy, and credentials remain on the endpoint.

Network access occurs only for an operator-requested function:

- downloading enabled threat-intelligence databases from ClamAV or abuse.ch
  services;
- resolving names through a filtering DNS provider the administrator
  explicitly selected;
- checking and downloading an update from an explicitly enrolled SentryLoom HQ
  server.

Provider requests necessarily expose the endpoint's public IP address to that
provider. Provider-specific privacy policies and terms apply independently.

## Managed endpoint

Managed mode is optional. The installer or endpoint administrator explicitly
selects an on-premises HQ URL and an HQ administrator must approve enrollment.

The endpoint sends sanitized operational data to that HQ, including:

- device name, host name, platform, app version, and installation identifier;
- protection state, security posture, scan counts, performance metrics, and
  configured policy;
- detection, monitoring, update, audit, quarantine-metadata, and command
  status.

It does not send file contents, quarantine contents, private keys, master keys,
passwords, bearer tokens, feed credentials, or certificate private keys.

## SentryLoom HQ

HQ stores enrolled-device records, sanitized telemetry, command history,
administrator password hashes, TLS configuration, and update metadata in its
local data directory. SentryLoom does not operate a central service that
receives this information.

HQ administrators control retention, host access, backups, firewall scope, and
deletion. Uninstalling preserves server data unless the administrator
explicitly requests its removal.

## Local secrets

Endpoint credentials are encrypted locally with AES-256-GCM. HQ administrator
passwords use PBKDF2-SHA256 with a unique random salt. Signing keys,
certificates, runtime databases, and encrypted credential stores are excluded
from source control.

## Public support

Never post logs, screenshots, databases, certificates, credentials, personal
files, customer telemetry, quarantine objects, or malware to a public issue.
Use GitHub private vulnerability reporting for sensitive security reports.
