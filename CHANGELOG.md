# Changelog

## Unreleased

- Throttle sign-in per client address instead of locking accounts after five failures. Five failed attempts for one email pause only the client that made them for 15 minutes, and 30 failures across emails pause that client entirely, so a stranger can no longer lock somebody else out. Credential endpoints also share a per-client budget of 20 requests a minute and answer `429` with `Retry-After`. The account-wide lock remains as a backstop after 50 consecutive failures.
- Make every sign-in attempt cost one password verification, so response time no longer reveals whether an account exists or is locked.
- Refuse passwords made of fewer than four distinct characters, common passwords, and passwords containing the account's email address. Length limits count characters, as the message says.
- Invitations choose a role, Member or Administrator, and administrators can change a user's role. Tally refuses to demote or disable the last enabled administrator. Administrators can list pending invitations and revoke them, and re-inviting an address revokes its earlier link.
- Record the signed-in user as the actor on audit entries instead of `local_operator`. Sign-ins, account lockouts, registrations, invitations, role, name, password and reset-link changes, user enable and disable, email settings and data deletions are now audited. Deleting audit logs leaves a record of the deletion.
- Check the session and role on account routes before reading the request body, so anonymous callers no longer see request formats.
- Send `Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` and `Cross-Origin-Opener-Policy` on every response, and HSTS for HTTPS origins with a real host name.
- Refuse connector URLs that point at link-local or instance-metadata addresses. Private and loopback addresses remain allowed for self-hosted sources.
- Serve the console's "page not found" page for unknown URLs instead of an empty response.
- Return to sign-in when a session ends while the console is open, then back to the same page. Pages a member cannot open say that administrator access is required instead of suggesting a connection problem.
- Fix updating a running macOS installation: the installer now waits for launchd to remove the previous service before starting the new one, instead of leaving Tally stopped.
- Stop ClickHouse logging DNS errors when the machine's host name does not resolve; existing installations are updated on the next installer run.
- Return `422 import_empty` for an empty import instead of `413`.
- Accessibility: name the Registry selection checkboxes, return focus to the control that opened a dialog, raise the active Connectors badge contrast to WCAG AA, fix the Connectors heading order, label the invitation email field, and use 12px minimum text in the Overview diagram.
- Say in standalone Registry copy that decisions are recorded, not enforced. Stop polling authentication status on the sign-in page once it has loaded.
- Update Next.js to 16.4.2 and `ctutils` to 0.4.5 (RUSTSEC-2026-0385).

## [0.1.4] - 2026-10-23

- Run the Tally image from `scratch` with a static musl binary and a CA bundle. Certificate generation, supplied-certificate validation, privilege dropping, and readiness checks are built into `tallyd`; no shell, curl, or OpenSSL is needed in the image. Existing data volumes and certificates are reused.
- Probe the internal HTTPS listener directly, independently of proxy settings, public DNS, and published ports, while still verifying the configured hostname and certificate. Report connection, TLS, timeout, and unhealthy-dependency errors in Docker health output. Allow an 8-second probe within a 10-second Docker timeout and a 30-second startup grace period.
- Keep container-to-database traffic out of HTTP proxies, preserving operator-supplied proxy exclusions for other destinations.
- Log startup progress through PostgreSQL migrations, registry loading, ClickHouse migrations, authentication setup, and listener startup. Use `docker compose exec tallyd /usr/local/bin/tallyd healthcheck` to diagnose readiness.

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

[0.1.4]: https://github.com/godellabs-ai/godel-tally/releases/tag/v0.1.4
