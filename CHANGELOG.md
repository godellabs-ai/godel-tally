# Changelog

## Unreleased

- Change the default HTTPS port from 8443 to 2357 for the installer, `make run`, Docker Compose, and Apple container deployments. Existing installations keep their saved port; Compose and Apple container deployments without `TALLY_URL` and `TALLY_PUBLISH_BIND` in `.env` move to 2357.

## [0.1.3] - 2026-10-22

- Deploy Tally fully in containers from the published `quay.io/godellabs-ai/godel-tally` image: download `docker-compose.yml`, create `.env`, and run `docker compose up`, with no Tally binary or source checkout. All settings, including generated secrets, live in `.env`.
- Run the same deployment with Apple container using `deploy/apple/tally-container.sh` and the same `.env`.
- Create a self-signed certificate in the container's data volume on first start, or use `tally.crt` and `tally.key` from the `tls` folder; the container drops root before starting Tally.
- Publish the linux/amd64 and linux/arm64 image with `make push-image`, packaging the cross-compiled release binary so no Rust code is compiled under emulation.
- `make docker-up` builds the image from a source checkout through `docker-compose.build.yml` and keeps its existing state directory.
- Publish a GitHub release with `make publish-release`: it builds or reuses verified archives for the current commit, tags it, uploads the four platform archives and `SHA256SUMS`, and checks the published files.

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

[0.1.3]: https://github.com/godellabs-ai/godel-tally/releases/tag/v0.1.3
