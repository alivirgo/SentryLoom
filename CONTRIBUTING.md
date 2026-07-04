# Contributing to SentryLoom

Thank you for helping build understandable, local-first endpoint security.
Contributions are welcome from developers, defenders, malware researchers,
designers, writers, students, and operators.

## Before you begin

1. Read [SECURITY.md](SECURITY.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
2. Search existing issues and discussions.
3. Open an issue before a large feature, new system mutation, protocol change,
   telemetry expansion, or detection rule likely to affect false positives.
4. Never attach live malware, private keys, PFX files, credentials, quarantine
   objects, personal files, or customer telemetry.

## Development setup

Requirements:

- Windows 10/11 or Windows Server 2022+
- Node.js 24+
- PowerShell 5.1 or 7

```powershell
git clone https://github.com/alivirgo/SentryLoom.git
cd SentryLoom
npm test
```

There are no runtime npm dependencies.

## Pull-request workflow

1. Fork the repository and create a focused branch.
2. Keep unrelated refactors out of the change.
3. Add deterministic tests for behavior changes.
4. Run `npm run check`.
5. Run `node tools/secret-audit.js`.
6. Update documentation when behavior, configuration, security boundaries, or
   operator workflows change.
7. Explain security impact, false-positive risk, rollback behavior, and manual
   verification in the pull request.

## Engineering principles

- Local protection must continue if HQ is absent.
- Scanned content is data and must never be executed.
- Inputs, paths, downloads, buffers, queues, and subprocesses must be bounded.
- Exact/confirmed evidence and heuristics must remain visibly distinct.
- New destructive responses must be opt-in, reversible where possible, and
  conservative by default.
- Browser-facing processes should not run elevated.
- Secrets must come from protected runtime input and must not enter source,
  logs, command lines, telemetry, tests, screenshots, or fixtures.
- Remote actions must remain explicitly allowlisted. Do not add a remote shell.
- Prefer Node built-ins and platform facilities over adding dependencies.

## Tests and safe samples

Use harmless industry test markers or synthetic fixtures. Do not commit,
download, generate, or execute real malware as part of the test suite.

Tests should isolate data with `SENTRYLOOM_DATA_DIR`, clean up temporary files,
avoid internet access, and produce deterministic results.

## Licensing of contributions

By submitting a contribution, you agree that it is provided under the Apache
License 2.0 and that you have the right to submit it. Third-party code or data
must include compatible licensing and attribution.
