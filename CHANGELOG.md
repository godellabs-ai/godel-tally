# Changelog

Notable changes to Gödel Tally will be documented in this file.

The project follows [Semantic Versioning](https://semver.org/) for tagged releases. While the version
is below 1.0, minor releases may contain breaking API, schema, migration, or configuration changes.

## [0.1.0] - 2026-10-19

- Initial public release, with Linux and macOS binaries for amd64 and arm64. The production web
  console is embedded in `tallyd`; PostgreSQL and ClickHouse are the only separate server processes.
- The GitHub-hosted installer selects the latest platform binary, verifies its checksum, provisions
  native databases, and starts a user service. Docker, Apple containers, and existing databases are
  optional database modes; Gate upgrades still require Docker.
- Native Rust and Next.js development retains live reload, with Docker databases by default.

- The product is Gödel Tally. Packages, binaries, routes, configuration, database objects,
  installation paths, and release assets use the Tally name, including `godel-tally`, `tallyd`,
  `TALLY_*`, and `/api/v1/tally`.
- This breaking rename requires fresh standalone configuration and databases; compatibility
  aliases and migration of previous standalone installations are not provided.

Tally remains alpha software; APIs, schemas, and operational behavior may change before 1.0.

[0.1.0]: https://github.com/godellabs-ai/godel-tally/releases/tag/v0.1.0
