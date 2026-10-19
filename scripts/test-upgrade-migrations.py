#!/usr/bin/env python3
"""Exercise upgrade migration handling; optionally use a disposable Postgres container."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


source = Path(__file__).with_name("upgrade-tally-to-gate.sh").read_text()
definitions = source.split('\nif [ "$phase" = prepare ]; then', 1)[0]
fixture = r'''
compose_tally() {
    [ "$TEST_CASE" != source-query-failed ] || return 1
    printf '%s\n' "$TEST_SOURCE_HEAD"
}
compose_gate() {
    cat > "$state_dir/ledger.sql"
    [ "$TEST_CASE" != archive-failed ]
}
check_migration_versions
prepare_imported_migration_ledger
'''
postgres_fixture = r'''
compose_tally() { shift 3; docker exec -i "$TEST_POSTGRES_CONTAINER" "$@"; }
compose_gate() { shift 3; docker exec -i "$TEST_POSTGRES_CONTAINER" "$@"; }
check_migration_versions
compose_tally exec -T postgres pg_dump -Fc --no-owner -U tally tally > "$state_dir/backup.dump"
compose_gate exec -T postgres pg_restore -U ggate -d ggate --no-owner --no-acl --exit-on-error < "$state_dir/backup.dump"
prepare_imported_migration_ledger
'''


def run_fixture(root, case, source_head, gate_head, body, **extra_env):
    state = root / case / "gate-upgrade"
    state.mkdir(parents=True)
    gate = root / case / "gate"
    config = gate / "console-config"
    config.mkdir(parents=True)
    if gate_head is not None:
        (config / "tally-schema-head.txt").write_text(gate_head)
    (state / "gate_dir").write_text(str(gate))
    runner = root / "scripts/verify.sh"
    runner.write_text(definitions + body)
    result = subprocess.run(
        ["bash", str(runner), "fixture"], capture_output=True, text=True,
        env={**os.environ, "TALLY_UPGRADE_STATE_DIR": str(state.parent), "TEST_CASE": case,
             "TEST_SOURCE_HEAD": source_head, **extra_env}, timeout=30,
    )
    return result, state


def check_versions():
    cases = [
        ("equal", "18", "18", False, False, True),
        ("older", "16", "18", True, False, True),
        ("newer", "18", "17", True, True, True),
        ("missing-head", "18", None, True, False, True),
        ("invalid-head", "18", "17; DROP TABLE findings", True, False, True),
        ("empty-source-head", "", "18", True, False, True),
        ("source-query-failed", "18", "17", False, False, False),
        ("archive-failed", "18", "17", True, True, False),
    ]
    with tempfile.TemporaryDirectory(prefix="tally-upgrade-migrations-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        for case, tally, gate, warning, archive, success in cases:
            result, state = run_fixture(root, case, tally, gate, fixture)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            assert (state / "migration_warning").exists() == warning, case
            assert (state / "ledger.sql").exists() == archive, case
            if warning:
                assert "best-effort data transfer" in (state / "migration_warning").read_text()
            if archive:
                sql = (state / "ledger.sql").read_text()
                assert "BEGIN;" in sql and "COMMIT;" in sql
                assert f"WHERE version > {gate} AND success RETURNING *" in sql
                assert "INSERT INTO tally_upgrade_newer_migrations SELECT * FROM newer" in sql
            print(f"PASS: {case}")


def check_postgres(container):
    def command(*args, input=None):
        result = subprocess.run(["docker", "exec", "-i", container, *args],
                                input=input, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout.strip()

    def query(db, sql):
        return command("psql", "-U", db, "-d", db, "-At", "-v", "ON_ERROR_STOP=1", input=sql)

    query("postgres", """
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='tally') THEN CREATE ROLE tally LOGIN; END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='ggate') THEN CREATE ROLE ggate LOGIN; END IF;
        END $$;
    """)
    with tempfile.TemporaryDirectory(prefix="tally-upgrade-postgres-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        for case, head in [("newer", "17"), ("equal", "18"), ("older", "19"), ("archive-conflict", "17")]:
            for db in ["tally", "ggate"]:
                command("dropdb", "-U", "postgres", "--if-exists", db)
                command("createdb", "-U", "postgres", "-O", db, db)
            query("tally", """
                CREATE TABLE _sqlx_migrations (
                    version BIGINT PRIMARY KEY, description TEXT NOT NULL,
                    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL,
                    checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL);
                INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time)
                    SELECT n, 'migration ' || n, n < 19, decode(repeat('ab', 48), 'hex'), 0
                    FROM generate_series(0,19) n;
                CREATE TABLE newer_tally_data (id INT PRIMARY KEY, value TEXT);
                INSERT INTO newer_tally_data VALUES (1, 'retain this newer-schema record');
            """)
            if case == "archive-conflict":
                query("tally", """
                    CREATE TABLE tally_upgrade_newer_migrations (LIKE _sqlx_migrations INCLUDING ALL);
                    INSERT INTO tally_upgrade_newer_migrations SELECT * FROM _sqlx_migrations WHERE version=18;
                """)
            snapshot_sql = "SELECT md5(string_agg(row_to_json(m)::text, ',' ORDER BY version)) FROM _sqlx_migrations m;"
            original = query("tally", snapshot_sql)
            result, state = run_fixture(root, case, "18", head, postgres_fixture,
                                        TEST_POSTGRES_CONTAINER=container)
            assert (result.returncode == 0) == (case != "archive-conflict"), result.stdout + result.stderr
            assert query("tally", snapshot_sql) == original, "source ledger changed"
            assert query("ggate", "SELECT value FROM newer_tally_data WHERE id=1;") == "retain this newer-schema record"
            assert query("ggate", "SELECT success FROM _sqlx_migrations WHERE version=19;") == "f", "dirty entry bypassed"
            if case == "newer":
                assert query("ggate", "SELECT max(version) FROM _sqlx_migrations WHERE success;") == "17"
                assert query("ggate", "SELECT version FROM tally_upgrade_newer_migrations;") == "18"
                supported = "SELECT md5(string_agg(row_to_json(m)::text, ',' ORDER BY version)) FROM _sqlx_migrations m WHERE version<=17;"
                assert query("ggate", supported) == query("tally", supported), "supported checksums changed"
            else:
                assert query("ggate", snapshot_sql) == original, "unchanged or rolled-back ledger differs"
            assert (state / "backup.dump").stat().st_size > 0
            print(f"PASS: PostgreSQL {case}: data, checksums, source ledger and dirty entries preserved")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-container", help="an empty disposable PostgreSQL container (test databases are replaced)")
    args = parser.parse_args()
    check_versions()
    if args.postgres_container:
        check_postgres(args.postgres_container)
