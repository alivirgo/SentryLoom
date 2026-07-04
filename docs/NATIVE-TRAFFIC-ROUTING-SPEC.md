# Native traffic-routing implementation contract

## Goal

Route supported outbound Windows connections through a protected local inspection service without relying on application proxy settings and without silently installing a TLS interception authority.

## Required components

1. A Microsoft-signed Windows Filtering Platform callout driver registered at:
   - `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`
   - `FWPM_LAYER_ALE_CONNECT_REDIRECT_V6`
2. A signed, auto-start Windows service running under a restricted service SID.
3. Authenticated local IPC between the unprivileged dashboard, service, and driver.
4. A local proxy service that preserves the original destination from WFP redirect context and opens the corresponding upstream socket.
5. A watchdog and transactional policy store that fail open and remove redirect filters if the service becomes unhealthy.

## Toggle behavior

Enable:

1. Verify driver and service signatures.
2. Start the proxy service and complete a loopback health check.
3. Install WFP redirect filters in a single transaction.
4. Verify DNS, IPv4, and IPv6 connectivity.
5. Roll back every filter if verification fails.

Disable:

1. Remove WFP filters in a transaction.
2. Verify direct connectivity.
3. Stop the proxy service only after no redirected flows remain.

The dashboard must always expose filter state, service health, redirected-flow count, bypass policy, and a one-click emergency restore.

## TLS policy

Routing and TLS interception are separate features. The default routing mode tunnels TLS without decryption and evaluates destination metadata and locally indexed reputation.

Any future TLS inspection mode requires:

- an explicit enterprise administrator policy;
- a hardware- or DPAPI-protected private key;
- a separately managed root certificate with removal and rotation;
- certificate-pinning bypass policy;
- exclusions for financial, health, identity, update, and mutually authenticated services;
- clear user disclosure and auditable activation;
- independent penetration testing.

SentryLoom 0.9.0 does not install a root certificate or claim whole-device traffic routing.
