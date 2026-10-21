# Changelog

## Unreleased

## [0.1.2] - 2026-10-22

- Resume interrupted PostgreSQL and ClickHouse downloads instead of restarting them. Each attempt continues from the data already received, a stalled connection is reopened, and rerunning the installer after a failure or Ctrl+C resumes the partial download.
- Download ClickHouse for Linux from ClickHouse's official package repository, `packages.clickhouse.com`, and fall back to the GitHub release. Every source must match the pinned SHA-256 checksum.
- Show how much of each database has downloaded and the current speed every 10 seconds.
- Stop in-progress database transfers when setup is cancelled, so a rerun never shares a partial download with a leftover transfer.
- Wait for the macOS service to finish stopping its databases before uninstall cleanup, instead of reporting that Tally is still running.
- Reject occupied private database ports when another service listens on all IPv4 addresses, including macOS where a loopback bind alone can miss that listener. Report the affected database and port before starting either database.

## [0.1.1] - 2026-10-21

- Keep fresh installations under `~/.godel-tally`, including configuration, scripts, application and database binaries, persistent data, logs, and certificates. Set `TALLY_HOME` to choose another root.
- Download pinned PostgreSQL and ClickHouse runtimes concurrently, verify SHA-256 checksums, and reuse cached runtimes. Default setup no longer needs Homebrew, apt/yum, Python, or sudo.
- Start private databases before Tally, wait for authenticated readiness, and stop the application and databases together. Detect crashed or unresponsive databases and let the user service restart the stack.
- Keep private databases stopped with `--no-start` and `--no-service`; support manual startup and Ctrl+C shutdown.
- Show seven colored setup stages with plain-language errors and recovery instructions; respect `NO_COLOR` and plain captured output.
- Preserve settings and data on reinstall, migrate owned legacy database service definitions, and refuse unsupported PostgreSQL major-version upgrades before changing the application.
- Retain downloaded runtimes on normal uninstall; remove owned runtimes and database data only with `--remove-databases`.

Private PostgreSQL downloads require macOS 15+ or Linux with glibc 2.36+ (for example Debian 12 or Ubuntu 24.04). Docker, Apple containers, and existing database modes remain available.

## [0.1.0] - 2026-10-21

Initial public release of Gödel Tally, the open-source AI discovery, inventory, and governance application.

- One executable with the HTTPS web console, authentication, API, connector worker, and registry embedded.
- Linux and macOS binaries for amd64 and arm64, with a checksum-verified installer and user services.
- Native PostgreSQL and ClickHouse by default; Docker, Apple containers, and existing databases are optional.
- Selectable HTTPS port, visible installation progress, and start/stop/restart instructions.
- Data-preserving uninstall, with optional removal of installer-owned databases, packages, and data.
- AI source connectors, individual activity findings, inventory relationships, provider/model governance, and evaluation data.
- Local accounts, invitations, password recovery, and configurable email delivery.
- Metadata-only discovery with encrypted credentials and configurable AI-log retention.
- Native Rust and Next.js development with live reload.
- Guided upgrade to Gödel Gate; Gate and its embedded Tally deployment require Docker.

Tally is alpha software. APIs, schemas, and operational behavior may change before 1.0.

[0.1.0]: https://github.com/godellabs-ai/godel-tally/releases/tag/v0.1.0

[0.1.1]: https://github.com/godellabs-ai/godel-tally/releases/tag/v0.1.1

[0.1.2]: https://github.com/godellabs-ai/godel-tally/releases/tag/v0.1.2
