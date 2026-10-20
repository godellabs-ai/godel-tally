# Changelog

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
