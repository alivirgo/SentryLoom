# Code signing policy

## Current status

SentryLoom's first public preview installers are reproducible but unsigned.
Their GitHub release is explicitly marked as an unsigned preview and publishes
SHA-256 checksums. They must not be represented as Authenticode-signed builds.

The project is seeking sponsored HSM-backed Authenticode signing for future
open-source releases. If accepted by the SignPath Foundation program, future
signed release pages will include the required statement:

> Free code signing provided by SignPath.io, certificate by SignPath Foundation.

## Signing goals

- Build release artifacts only from the public GitHub repository.
- Require successful Windows tests, CodeQL analysis, and secret auditing.
- Keep private signing keys out of developer machines and the repository.
- Require manual release approval.
- Timestamp every Authenticode signature.
- Publish hashes and preserve a traceable source tag for every binary.
- Sign only SentryLoom artifacts built from SentryLoom source.

## Team roles

- Committer and reviewer: [@alivirgo](https://github.com/alivirgo)
- Signing approver: [@alivirgo](https://github.com/alivirgo)

These roles will expand as trusted maintainers join the project. A contributor
must not approve their own security-sensitive release change without an
independent reviewer once multiple maintainers are available.

## Privacy statement

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or
operating it.

Optional network features and their destinations are documented in
[PRIVACY.md](PRIVACY.md). There is no analytics, advertising, crash-reporting,
or mandatory SentryLoom cloud service.

## Certificate verification

Before publishing a signed artifact, maintainers verify:

1. Windows reports the Authenticode signature as valid.
2. The file version matches the Git tag and release.
3. The timestamp is present and valid.
4. SHA-256 matches the release notes.
5. Endpoint and HQ installers contain only expected public-source files.
6. The GitHub release identifies the signer subject and certificate
   thumbprint.

Compromised signing credentials, unauthorized signatures, or provenance
failures are security incidents and must be reported through GitHub private
vulnerability reporting.
