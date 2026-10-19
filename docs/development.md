# Development

## Requirements

- Rust 1.99.0 with `clippy` and `rustfmt` (declared in `rust-toolchain.toml`)
- Node.js 24 and npm 11
- Docker (default database runtime), Apple container, or existing databases
- OpenSSL
- `cargo-watch` when using `./dev-run.sh`
- `cargo-deny` 0.19.9 when running the dependency policy locally

Install the JavaScript dependencies exactly as locked:

```bash
npm --prefix apps/web ci
```

Install the optional live-reload helper:

```bash
cargo install cargo-watch --locked
cargo install cargo-deny --version 0.19.9 --locked
```

## Development stack

`make dev` builds the registry and combined `tallyd` binary before starting the databases and
live-reload processes. The Rust process includes the API, connector worker and the Gate upgrade runtime; Next.js
runs separately with hot reload and direct HTTPS on port 8080. Only PostgreSQL and ClickHouse run
in containers. The first build finishes before the readiness timer starts.

```bash
make web-install
make dev
TALLY_DB_MODE=apple make dev
```

Docker is the default database runtime. Apple mode requires Apple silicon and macOS 26+ with
[container](https://github.com/apple/container) installed. Existing mode accepts
`TALLY_POSTGRES_URL`, `TALLY_CLICKHOUSE_URL` and `TALLY_CLICKHOUSE_PASSWORD`. Mixed modes use
`TALLY_POSTGRES_MODE` and `TALLY_CLICKHOUSE_MODE`. `TALLY_KEEP_DB=1` leaves containers running
on exit. `TALLY_RESET_DB=1 make dev` explicitly deletes the selected managed container volumes
and starts empty databases. Back up anything needed first; reset is rejected for existing/native databases.

Open <https://localhost:8080>. The script creates a persistent self-signed certificate in
`.local/tls`; it does not install trust roots. Use `TALLY_TLS_CERT_FILE` and `TALLY_TLS_KEY_FILE`
for a trusted certificate. Set `TALLY_DEV_BIND`, a matching `TALLY_URL` and
`TALLY_ALLOWED_DEV_ORIGINS` for remote development. Rust's private API listener remains on
127.0.0.1:8788. No nginx container is involved.

Stop an old dev launcher before using the combined one: the old collector and the Gate upgrade runtime watchers are
now part of `tallyd`. Existing dev Docker volumes are reused. Switching between Docker and Apple
container does not transfer data between their separate volume stores.

## Production build

```bash
make build
make run
TALLY_DB_MODE=apple make run
make package
```

`make build` first runs a static Next.js export in an isolated temporary directory, excluding the
development-only API proxy handlers. It then compiles the UI assets into `tallyd` with the
`embedded-ui` feature. Customer data is fetched after sign-in, never during the export. Production
needs no Node.js or nginx. `cargo run -p tallyd` remains the development backend without embedded
assets; the feature is explicit so Rust edits do not require rebuilding the UI.

The installer and user-service lifecycle are documented in [quickstart](quickstart.md). The
optional full container stack is started explicitly by `make docker-up`.

## Configuration

Safe local defaults are documented in `.env.example`. Never commit `.env`, connector credentials,
cloud service-account material, private keys, source exports, or production URLs containing tokens.
The first standalone user becomes administrator. Additional users need invitations. Administrators configure email delivery
in Settings; see [password recovery](user-guide.md#accounts-and-password-recovery). Keep the local self-signed certificate on
loopback and use a trusted certificate for shared access.

## Generated contracts and registry artifacts

Registry source lives in `registry-data/source/`. Generated registry artifacts under
`registry-data/dist/` and JSON schemas under `specs/` must match their source. Installation-local
overlays are managed through Tally and stored in PostgreSQL; they are not loaded from this source
directory. Registry manifests identify the canonical source with `source_sha256`; generation does
not depend on the repository commit or require a Git checkout.

```bash
make registry-lint
make registry-build
make schema-check
```

Run `make schemas` only when intentionally updating checked-in schemas, then review the complete
diff. A registry change should include sourced evidence, positive and negative matcher coverage, and
the newly generated default artifact when its version changes.

## Checks

The complete local gate is:

```bash
make check
```

It runs registry generation, Rust formatting, Clippy with warnings denied, all workspace tests,
schema drift checks, registry linting, ESLint, TypeScript checking, and a static Next.js export.
Run `bash scripts/test-deployment.sh` for mocked installer/service/container lifecycle checks.

Additional checks are available separately:

```bash
make audit          # Rust license/advisory policy and npm audit
make secret-scan    # full Git history with Gitleaks in a pinned container
make compose-check  # render and validate docker-compose.yml
make web-e2e        # Playwright tests; requires a running stack
```

### Authentication regression tests

The ordinary Rust suite does not require a database. The full authentication regression uses an
**empty disposable PostgreSQL database** and a local SMTP sink; it sends no external mail:

```bash
TALLY_AUTH_TEST_DATABASE_URL=postgres://tally:tally@127.0.0.1:5433/tally_auth_test \
TALLY_URL=https://tally.example.test EMAIL_ENABLED=false \
cargo test -p tallyd auth_integration -- --ignored
```

Create the empty database first and remove it after the run. The test refuses to use a database
with existing public tables. It covers every registered Tally API route, concurrent first-user
registration, invitations, role restrictions, failed-login revocation, lockout, email delivery,
concurrent reset requests, token reuse, password changes, encrypted settings and disabled accounts.

For browser tests, point `TALLY_WEB_URL` at an isolated test console and set
`TALLY_E2E_STORAGE_STATE` to a Playwright storage-state JSON file for its test administrator.
Set `TALLY_E2E_EMAIL` and `TALLY_E2E_PASSWORD` for the real sign-in regression; without those,
that single test is skipped. Mocked UI specs can also run with a test authentication backend.
Upgrade UI specs mock host operations and never start an installation. Use test accounts and
an isolated authentication backend for browser checks.

## Database changes

The October 2026 baseline requires fresh PostgreSQL and ClickHouse databases. Historical migration
ledgers cannot be reused or cleared to force a replay.

Migrations in `migrations/postgres/` are ordered and applied automatically by `tallyd`. Add a new
migration instead of editing a migration that has shipped. Include transaction and replay tests for
changes to finding identity, usage counts, attribution, connector cursors, or deletion behavior.

## Pull requests

Keep changes focused, update user-facing docs and generated contracts with behavior changes, use
sanitized fixtures, and describe the validation actually run. See [CONTRIBUTING.md](../CONTRIBUTING.md)
for the full contribution contract.
