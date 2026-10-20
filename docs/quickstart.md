# Install and run Tally

Tally's primary deployment is one executable containing the UI, API, authentication, connector
worker, registry, migrations and the Gate upgrade runtime. PostgreSQL and ClickHouse are its only server dependencies.
Docker is optional. No nginx or Node.js process is required in production.

## Customer installation

Download and install the latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/godellabs-ai/godel-tally/main/install.sh -o install-tally.sh && bash install-tally.sh
```

Run as a regular user, with Bash, curl, tar and OpenSSL available. With Apple's system LibreSSL,
Python 3 is also needed during installation for certificate hostname validation; Homebrew OpenSSL 3
can be used instead. The installer never changes system or browser certificate trust.
Native macOS databases require [Homebrew](https://brew.sh). Linux native database packages require
sudo and apt, yum or dnf. A Linux installation that registers services requires a working systemd
user session. The selected database packages must support the host's distribution and architecture.

The installer selects Linux/macOS and amd64/arm64, downloads the corresponding archive, verifies
its SHA-256 digest, and installs under `~/.local/lib/godel-tally`. Configuration is stored in
`~/.config/godel-tally/tally.env`, with mode 0600. Data defaults to `~/.local/share/godel-tally`.
Override these using `TALLY_INSTALL_DIR`, `TALLY_CONFIG_DIR` and `TALLY_DATA_DIR` before installation.
Configuration files use literal `KEY=value` lines; do not add shell quotes or variable substitutions.

Default native mode installs PostgreSQL (Homebrew `postgresql@18`, PostgreSQL 18 from PGDG on Debian/Ubuntu and Enterprise Linux; distribution PostgreSQL on Fedora) and ClickHouse (Homebrew cask or the official ClickHouse apt/rpm repository). It creates
**private Tally instances**, bound to loopback ports 5433 and 8124, plus a `tally` PostgreSQL database.
It leaves existing clusters, users and database service configuration intact. The installer creates
the ClickHouse database; Tally runs the embedded SQL migrations at startup. Change managed database ports
with `TALLY_POSTGRES_PORT` and `TALLY_CLICKHOUSE_PORT` before the first installation.

Open <https://localhost:8443>. The generated certificate is self-signed for local evaluation;
use your trusted certificate for shared deployments. The first registered account becomes the
administrator. Subsequent accounts require an invitation.

## Choose database deployment independently

```bash
bash install-tally.sh --db docker
bash install-tally.sh --db apple

export TALLY_POSTGRES_URL='postgres://tally:URL_ENCODED_PASSWORD@db.example.com:5432/tally?sslmode=require'
bash install-tally.sh --postgres existing --clickhouse docker
```

Docker must already be installed and running. Apple mode requires the
[Apple container runtime](https://github.com/apple/container), an Apple silicon Mac and macOS 26+.
It uses the real `container` CLI, not a Docker socket or Compose emulation. The installer starts
`container system` as needed. Both runtimes retain database data in named volumes. Their host ports
bind only to 127.0.0.1. Tally's service starts the managed containers before launching the binary.

For both existing databases:

```bash
export TALLY_POSTGRES_URL='postgres://tally:URL_ENCODED_PASSWORD@db.example.com:5432/tally?sslmode=require'
export TALLY_CLICKHOUSE_URL='https://clickhouse.example.com:8443?user=tally'
export TALLY_CLICKHOUSE_PASSWORD='your-clickhouse-password'
export TALLY_CLICKHOUSE_DATABASE=tally
bash install-tally.sh --db existing
```

Use PostgreSQL 15+ and ClickHouse 26.9+. Create a dedicated PostgreSQL database and database owner before using existing mode. Tally needs
permission to run migrations in that database. Create the ClickHouse database too; its user needs
permission to create tables and perform reads and writes. Existing mode does not install, start, stop or reset
customer database servers. It still runs Tally's migrations. Back up populated databases first.

Keep `TALLY_SECRET_KEY` stable: changing it makes existing encrypted connector credentials unreadable.
Re-running the installer preserves configuration, secrets and data. A database-mode change is refused
on an existing installation: migrate data and update the configuration explicitly first.

## Services and upgrades

Linux:

```bash
systemctl --user start tally-server
systemctl --user status tally-server
journalctl --user -u tally-server -f
systemctl --user restart tally-server
systemctl --user stop tally-server
```

Native database units are `tally-postgres` and `tally-clickhouse`. User services normally depend on a
user session. For startup before login and continued operation after logout, an administrator can
run `sudo loginctl enable-linger "$USER"`. The installer does not change lingering automatically.

macOS:

```bash
launchctl print "gui/$(id -u)/ai.godel.tally.server"
# Stop
launchctl bootout "gui/$(id -u)/ai.godel.tally.server"
# Start after stopping (loads the LaunchAgent again)
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/ai.godel.tally.server.plist"
# Restart a loaded service
launchctl kickstart -k "gui/$(id -u)/ai.godel.tally.server"
tail -f ~/.local/share/godel-tally/server.log
```

LaunchAgents start at login, not before a user logs in. Native database LaunchAgents use labels
`ai.godel.tally.postgres` and `ai.godel.tally.clickhouse`.
Stopping Tally leaves the databases running. Starting Tally also starts its managed database services
or containers if needed. After a failed installation, rerun the installer; service commands apply once
the application service has been registered.

Pin a release with `TALLY_VERSION=v0.1.1 bash install-tally.sh` (substitute a published tag).
Run the installer again to update. `--no-start` installs and registers Tally without starting it;
native database provisioning still starts the databases. `--no-service` skips Tally's service
registration and prints a manual launcher; native databases still use user services.
`--dry-run` describes platform selection without making changes.

Release builds and tests run locally; this repository does not use GitHub Actions. Maintainers
upload the four platform archives and `SHA256SUMS` to GitHub Releases after validation.
Database package availability and user-service setup depend on your host; see the prerequisites above.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/godellabs-ai/godel-tally/main/uninstall.sh -o uninstall-tally.sh
bash uninstall-tally.sh --dry-run
bash uninstall-tally.sh
```

Run as the installing user, without sudo. For a custom configuration directory, prefix the command
with `TALLY_CONFIG_DIR=/absolute/config/path`. The script also works with partially installed v0.1.0
deployments. New release bundles install a local copy at `~/.local/lib/godel-tally/uninstall.sh`.

Uninstall stops and removes Tally's application and native database user services, stops database
containers marked as owned by this installation, and removes known application files. Docker or
Apple container must be available to stop owned containers. Other installations' service files are
rejected. Existing/shared databases and unrelated containers are never stopped.

Configuration (including the encryption key), database data, certificates, containers, volumes,
and database packages are retained. The installer can reuse them on the next installation.
Files added by an operator inside the installation directory are retained too.

## Use your existing HTTPS certificate

```bash
export TALLY_URL=https://tally.example.com:8443
export TALLY_HTTP_BIND=0.0.0.0:8443
export TALLY_TLS_CERT_FILE=/absolute/path/to/fullchain.pem
export TALLY_TLS_KEY_FILE=/absolute/path/to/privkey.pem
bash install-tally.sh
```

The certificate and unencrypted private key must be readable by the installing user. Certificates
are validated and never overwritten. `TALLY_URL` is the exact public origin, with no trailing slash;
it controls CSRF validation and email links. Behind an existing TLS ingress, Tally can serve HTTP by
omitting both TLS settings when running the binary directly; the public origin remains HTTPS.
After certificate renewal, restart Tally. No nginx is bundled or required.

## Development

```bash
make web-install
make dev
TALLY_DB_MODE=apple make dev
```

Development runs PostgreSQL and ClickHouse in Docker by default, `cargo watch -x 'run -p tallyd'`
for all Rust services, and `npm run dev` for Next.js hot reload. Next.js serves development HTTPS on
<https://localhost:8080>. Rust listens privately on 127.0.0.1:8788 and the Gate upgrade runtime's internal listener uses
127.0.0.1:8789. Set `TALLY_DEV_BIND` and a matching `TALLY_URL` to change the UI address.
`TALLY_KEEP_DB=1` leaves managed database containers running after Ctrl-C.
`TALLY_RESET_DB=1 make dev` deletes the selected managed container volumes and starts empty DBs;
use it only when the development data is disposable. Existing/native DBs cannot be reset this way.

For existing DBs set both URLs and `TALLY_DB_MODE=existing`. For per-database overrides use
`TALLY_POSTGRES_MODE` and `TALLY_CLICKHOUSE_MODE`. Local credentials default to `tally` (PostgreSQL)
and `tally-local` (ClickHouse); customer installation generates random credentials instead.

Stop the old dev launcher before switching to this version: its separate collector and the Gate upgrade runtime
watchers would conflict with the combined runtime. Existing Docker dev volumes are reused by
name (`godel-tally_tally-postgres` and `godel-tally_tally-clickhouse`). Do not start old Compose DBs
and the new launcher against the same volumes simultaneously. Apple uses its own volume store;
switching engines does not migrate existing data.

## Build from source or use full Docker

```bash
make web-install
make build       # UI export, registry, release tallyd --features embedded-ui
make run         # foreground binary, localhost:8443, Docker databases
TALLY_DB_MODE=apple make run
make package     # dist/tallyd-<os>-<arch>.tar.gz
make docker-up   # optional image build + Tally/PostgreSQL/ClickHouse
make docker-down
```

Use `TALLY_BINARY` to run a different locally built binary. `make down` stops local database
containers and retains volumes. The Compose variant has no web, collector or nginx container;
`tallyd` performs their application work. Gate upgrades inside the optional full Docker image
have container scope, without access to the host Docker socket.

Before reusing an old full-Compose database volume, put its original database passwords in `.env`.
The old defaults were `TALLY_POSTGRES_PASSWORD=tally` and `TALLY_CLICKHOUSE_PASSWORD=tally-local`;
generating new passwords does not alter users already stored in an existing volume.

## First workflow

1. Register the first administrator, then invite other operators.
2. Configure a connector with the documented read-only permissions and run a sync.
3. Inspect AI Inventory and Findings, then record governance decisions.
4. Configure email delivery and database backups before shared use.

## Upgrade to Gate

Gate and Tally embedded in Gate continue to require Docker. Native Tally and Tally with Apple
container databases can upgrade to Gate on the same host once Docker and Compose are available.
The release includes the migration helpers and `tallyd rekey-for-gate`; no Rust compiler is needed.
See [Upgrade to Gate](upgrade-to-gate.md) for review, backup, port handoff and recovery. The optional
fully containerized Tally deployment runs this upgrade from the host, without mounting a Docker
socket into its application container.
