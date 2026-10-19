# Upgrade standalone Tally to Gödel Gate

**Gate and Tally embedded in Gate require Docker.** Standalone Tally may use native,
Docker, Apple-container or existing databases; the destination Gate deployment always uses
Docker Compose on the same host. Install and start Docker before beginning the upgrade.

Open **Upgrade** (`/upgrade`) from a Tally administrator session. Enter your registration
key, final HTTPS Gate Console URL, and Gate install directory in the form. Select **Review
upgrade**, inspect the installation details, then select **Upgrade to Gate**. The workflow runs
on the Tally host. Registration keys, certificate keys, backups, and receipts stay on that host.
The upgrade requires no AI provider connection. Installation and cutover have separate approvals.

The installed binary and `make dev` / `make run` include the upgrade runtime on the host. The release bundle
includes the migration scripts and `tallyd rekey-for-gate`, so no Cargo build or source checkout
is required. The optional full-Docker Tally deployment uses the host CLI described below.
At cutover, enter absolute **host** paths for a valid TLS full-chain and private key. Tally suggests the files
currently used by Tally when it can find them. The review stage generates its own self-signed certificate.
You can edit the **Final Gate Console URL** in the review stage before entering the production
certificate paths. Point the final hostname to this host and use a certificate that covers it.
The switch approval uses the updated URL; the temporary review URL stays the same.
The host user running Tally must be able to read the private key. Gate also needs a fresh host
install directory.
For the install directory, Tally suggests a sibling of the Tally installation or checkout.
The path is editable and must be empty if it already exists.

## Before starting

The current upgrade transfers Tally's PostgreSQL data. It does not transfer retained AI logs
or estate inventory from standalone Tally's ClickHouse into Gate's ClickHouse. The Tally
ClickHouse data is retained, but those records will need a separate migration to be available
in Gate. Plan that migration before cutover if you need to carry over the existing estate history.

1. If you already have a portal registration key, enter the saved secret in the registration-key field. If you do not have a portal account, select **create an account** below the registration-key field. Tally passes your saved email, first name, and last name to the portal registration page. You can edit your name in **Users** before opening the portal. Verify your email and sign in. Tally referrals are approved after email verification without a support approval step, and the portal creates your first registration key. Confirm the Tally destination to send the new key to the open Tally tab, or use **Open Tally and continue**. A new key expires after seven days. If you have an existing portal account, use its saved key: the upgrade does not rotate it. If you lost the secret, you can choose to rotate it manually in your portal account; doing so invalidates the old secret. Contact support@godel-labs.ai to extend expiry or activate a deactivated key before upgrading.
2. Provide an HTTPS Console hostname with DNS pointed at this host. You will provide a matching full-chain
   certificate and private key readable by Tally only after inspecting Gate on its review port.
3. Ensure the Gate Console images and versioned bundle have been published. The release publisher
   uses a new `GGATE_VERSION` and runs `make push-console-images push-console push-detection-engine-prod`
   in the Gate repository.
   Do not overwrite an already published versioned bundle. `push-console` also updates
   `https://dl.godel-labs.ai/godel-gate/console/latest/install-console.sh` and its checksum
   manifest after the versioned files are uploaded.
4. Ensure the host has Docker Compose, curl, OpenSSL, Python 3, and enough disk space for a complete Tally
   PostgreSQL dump plus a second Gate database. Native and existing PostgreSQL require local
   `psql` and `pg_dump` matching the source server version (use `TALLY_PG_BIN` if outside PATH);
   managed Docker/Apple databases use their own client tools. Tally must be running from its
   installed service, `make dev` or `make run`. Keep its configuration and `TALLY_SECRET_KEY` available so connector credentials can be
   re-encrypted for Gate. If Tally reports `connector_credentials_unsealable`, correct the source
   key or open **Tally Connectors** and re-enter that connector’s credentials before upgrading.
   The edit form loads nonsecret settings even when the old credential cannot be decrypted; saving
   a valid replacement clears the stale credential error. Preparation stops if a secret cannot be
   decrypted. On macOS LibreSSL, Python 3 is needed to check the certificate hostname.

## Prepare and cut over

Enter all three installation details in the form. **Review upgrade** validates the registration
key with the portal, reads the latest release manifest, and shows the exact version and review
URL. Editing any field clears that review. **Upgrade to Gate** then:

1. Downloads the pinned, checksum-verified installer and stages Gate PostgreSQL.
2. Compares PostgreSQL migration versions. A mismatch displays a warning and continues with a
   best-effort transfer instead of stopping preparation.
3. Places Tally in read-only mode, waits for active connector batches, API mutations and scans to finish,
   and saves a checksummed PostgreSQL dump under `$TALLY_UPGRADE_STATE_DIR/gate-upgrade` (by default
   `~/.local/share/godel-tally/upgrade/gate-upgrade` for installed binaries). It restores the dump into
   Gate and re-encrypts connector secrets. A drain timeout fails preparation and resumes Tally.
4. Starts Gate on the first available HTTPS review port from 8443, 9443, 10443, 11443, or 12443 with Gate schedulers paused, imports standalone Tally
   accounts into Gate IAM, and carries an explicit Tally Cursor decision to Gate’s separate Cursor
   coding-agent entry. It then compares key Tally table and user counts, verifies every copied
   provider and model sanction decision, and checks Gate health.
   Tally administrators become Gate super administrators; Tally members retain the member role.
   Account IDs, email addresses, password hashes, active state, and creation times are preserved.
   Tally sign-in and read-only pages remain available, while
   Tally data changes stay blocked so the two copies do not diverge.

Both products must use the October 2026 baseline (or later migrations built on it). Databases
from the historical migration series cannot be restored into this baseline.

When Tally is behind Gate, Gate applies its missing Tally migrations after restoring the full
database backup. When Tally is ahead, the restored Gate copy retains all Tally tables and data,
and moves successful migration ledger entries above Gate's supported version into
`tally_upgrade_newer_migrations`. The original Tally ledger and database stay intact, and supported
ledger entries and checksums are preserved.
As later releases support archived versions, Tally's migrator restores their original ledger
entries and validates their checksums without replaying the already-applied schema.
Gate still validates supported migrations and must pass the existing health, copied-record,
account, and registry checks before the switch is offered.
Actual migration or compatibility failures can still stop preparation; inspect the warning and
review the transferred data in Gate before approving cutover.

Review the receipt on the Upgrade page and open the highlighted Gate Console link in a new window. The review
certificate is self-signed, so the browser may ask you to inspect and accept it. Sign in with your
Tally account and explore the copied data. Then enter valid production certificate paths and select
**Approve switch to Gate**. Tally retires the Tally application, retains its databases,
updates the Gate certificate and final URL, and recreates only Gate's worker, API, and router. Gate's
data services continue running. The Tally data and pre-upgrade dump remain on the host. Sign in to Gate
with the same Tally email address and password. Tally sessions and outstanding invitations are
not Gate sessions or invitations, so users sign in again and unaccepted invitations must be reissued.
Every Tally account must have a password before cutover. For a legacy account without one,
issue a reset link from **Users** and have its owner set a password before retrying preparation.
While Gate is staged, Tally administrator sign-in continues to work, but Tally API mutations return
an upgrade read-only message. The Upgrade page remains available for cutover or cancellation.

Before cutover, **Cancel and resume Tally** stops the staged Gate containers and resumes Tally
writers. A failed attempt offers **Review upgrade** with the prior URL and host paths filled in. The
registration key must be entered again because Tally deletes its temporary copy after each attempt.
The upgrade page shows a bar of verified checkpoints, the latest host activity, a running indicator,
and an actionable failure reason. The bar counts completed checks; it is not a time estimate. If
review finds an unreadable Tally connector credential, it stops before starting another Gate
install and links to Tally Connectors. No source credential is silently discarded.
**Retry upgrade** archives the failed receipt and any partial Gate install,
then starts another reviewed attempt in the same directory. You can choose a different empty
directory. Existing data volumes and the failed receipt are retained.

The switch checks Gate with the production certificate on the review port while Tally remains
available. If Tally owns the final HTTPS port, its public listener pauses during the handoff;
the in-process upgrade helper keeps running. Development pauses the Next.js listener too.
Gate's Docker router takes the released port. Port release and transient Docker bind failures
are retried for up to two minutes. If the handoff fails, the script restores the review configuration
and resumes Tally's public listener, keeping Tally read-only. Failures during Gate activation
require review because Gate may have received new writes.

After Gate's final HTTPS endpoint and active worker are verified, the combined Tally application
exits cleanly. A persistent `retired` marker prevents service or development restarts from resuming
stale Tally writers. Native and existing database servers remain running; source data is retained.
Do not delete that marker to roll back after Gate has accepted writes. Legacy Compose installations
retain their original stop-and-volume-check behavior.
If Gate passes its final checks but Tally shutdown fails, Gate stays running and the interface
shows its verified final URL. Resolve the remaining shutdown issue without resuming Tally writers.

Do not resume Tally writers after Gate has accepted new writes. If preparation fails, the script
attempts to resume Tally writers. If cutover fails, inspect
the redacted log shown on the Upgrade page before selecting a recovery path; the volumes are retained. A
failure during final verification, before service switching begins, offers **Retry cutover** and
**Cancel and resume Tally** in the UI. Failures after switching begins are not retried
automatically. A data-preserving Gate-to-Tally return flow will be added after its mapping and
instructions are defined.

## Full-Docker Tally: run the upgrade on the host

The application container has no Docker socket. Keep Gate installation and service switching on
the host. With the same checkout and user used for `make docker-up`, point `TALLY_BINARY` to a
matching host-platform Tally binary (download a release archive, or use `make build`). The host
and container share the private `.local/docker-state` directory for upgrade markers and receipts.
If Compose uses a custom `TALLY_POSTGRES_URL`, it must reach the same database from the host too;
the helper uses local PostgreSQL clients for that external database.

```bash
export TALLY_BINARY=/absolute/path/to/tallyd
bash scripts/docker-upgrade.sh prepare \
  --console-url https://gate.example.com:9443 \
  --registration-key-file /absolute/private/registration-key \
  --gate-dir /absolute/path/to/new-gate
bash scripts/docker-upgrade.sh status
# Review the staged Gate installation, copied-record receipt and account access first.
bash scripts/docker-upgrade.sh cutover \
  --final-url https://gate.example.com \
  --tls-cert /absolute/path/to/fullchain.pem \
  --tls-key /absolute/path/to/privkey.pem
```

Preparation consumes and removes the temporary registration-key file; create a mode-0600 copy
for this purpose. `cancel`, `reset`, `status` and `cleanup` use the same wrapper. Native installers
can run the packaged `scripts/upgrade-tally-to-gate.sh` with `TALLY_ENV_FILE` set to their `tally.env`
for host-side recovery after the UI has retired.

The Gate installer can also be used without the Tally upgrade workflow:

```bash
curl -fsSL https://dl.godel-labs.ai/godel-gate/console/latest/install-console.sh | sh -s -- \
  --console-url 'https://console.example.com' \
  --tls-cert '/path/to/fullchain.pem' \
  --tls-key '/path/to/privkey.pem'
```

That command creates a fresh Gate installation. Use the Tally upgrade workflow when existing Tally data
must be copied.

For a Gate installation that was cut over before account import was available, run
`bash scripts/upgrade-tally-to-gate.sh import-users` from the Tally checkout on the same host.
It imports missing accounts from the copied `tally_auth_users` table in Gate, keeps any existing
Gate password changes, and records `tally_users` in the upgrade verification receipt. It does not
restart containers or touch the preserved Tally volume.

After cutover reports `gate_live`, the host `cleanup` command checks the final Gate health endpoint before removing
the host-local database dump, copied environment files, installer, logs, and detailed upgrade
receipt. It keeps the Gate installation, Gate data volume, retained Tally data volume, and a minimal
non-secret completion record. Failed, cancelled, staged, or otherwise unfinished upgrades keep their
recovery files.

Registration keys are limited to one per portal user, including expired and deactivated keys. The Tally upgrade does not rotate an existing key. A user who lost the secret may choose Rotate in their portal account; rotation invalidates the old secret for other installations and does not extend expiry. Upgrade preparation and cutover require an active, unexpired key; contact support@godel-labs.ai for activation or extension.
