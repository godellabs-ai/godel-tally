#!/usr/bin/env python3
"""Run the combined-runtime prepare branch with isolated database/installer fixtures."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

scripts = Path(__file__).resolve().parent
source = (scripts/'upgrade-tally-to-gate.sh').read_text()
definitions, phases = source.split('\nif [ "$phase" = prepare ]; then', 1)
fixture = r'''
docker() { printf 'docker %s\n' "$*" >> "$state_dir/events"; }
stage_certificate() { touch "$state_dir/staging.crt" "$state_dir/staging.key"; }
select_port() { printf '%s' "$1"; }
curl() {
    local output
    while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then output="$2"; break; fi; shift; done
    cp "$TEST_INSTALLER" "$output"
}
tally_query() { printf '1\n'; }
check_migration_versions() { :; }
prepare_imported_migration_ledger() { :; }
pause_combined_writers() {
    [ -f "$maintenance_dir/read-only" ] || exit 1
    [ "$TEST_CASE" != drain-failed ] || fail 'fixture drain timeout'
    printf 'drained\n' >> "$state_dir/events"
}
tally_dump() { grep -q '^drained$' "$state_dir/events" || exit 1; printf 'fixture-backup'; }
compose_gate() {
    printf 'gate %s\n' "$*" >> "$state_dir/events"
    case "$*" in *pg_restore*) cat > "$state_dir/restored" ;; esac
}
import_users() { :; }
reconcile_registry() { :; }
verify_url() { :; }
verify_counts() { [ "$TEST_CASE" != verify-failed ] || fail 'fixture verification failed'; }
'''
installer = '''#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = --dir ]; then gate="$2"; break; fi
    shift
done
mkdir -p "$gate"
printf 'JWT_SECRET=fixture-gate-key\n' > "$gate/.env"
'''

for case in ['success', 'drain-failed', 'rekey-failed', 'verify-failed']:
    with tempfile.TemporaryDirectory(prefix='tally-prepare-fixture-') as temporary:
        root = Path(temporary)
        (root/'scripts').mkdir()
        shutil.copyfile(scripts/'runtime-common.sh', root/'scripts/runtime-common.sh')
        runner = root/'scripts/prepare.sh'
        runner.write_text(definitions + fixture + '\nif [ "$phase" = prepare ]; then' + phases)
        payload = root/'installer.sh'; payload.write_text(installer)
        checksum = hashlib.sha256(installer.encode()).hexdigest()
        binary = root/'tallyd'
        binary.write_text('''#!/bin/bash
set -eu
[ "$1" = rekey-for-gate ]
[ "$TALLY_IMPORT_PG_PORT" = 55432 ]
grep -qx 'TALLY_SECRET_KEY=fixture-source-key' "$TALLY_UPGRADE_SOURCE_ENV"
[ "$TEST_CASE" != rekey-failed ]
''')
        binary.chmod(0o700)
        key = root/'registration-key'; key.write_text('fixture-registration-secret')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('TALLY_', 'TALLY_UPGRADE_'))}
        state = root/'state/gate-upgrade'
        maintenance = root/'maintenance'
        env.update(TALLY_RUNTIME_MODE='combined', TALLY_POSTGRES_MODE='native', TALLY_BINARY=str(binary),
                   TALLY_SECRET_KEY='fixture-source-key', TALLY_UPGRADE_STATE_DIR=str(state.parent),
                   TALLY_MAINTENANCE_DIR=str(maintenance), TEST_INSTALLER=str(payload), TEST_CASE=case)
        result = subprocess.run(['bash', str(runner), 'prepare', '--console-url', 'https://gate.example:9443',
                                 '--registration-key-file', str(key), '--gate-dir', str(root/'gate'),
                                 '--release-version', '1.2.3', '--installer-sha256', checksum],
                                env=env, text=True, capture_output=True, timeout=10)
        output = result.stdout + result.stderr
        assert (result.returncode == 0) == (case == 'success'), output
        assert (state/'mode').read_text() == 'combined', output
        assert (state/'tally.env').stat().st_mode & 0o777 == 0o600
        events = (state/'events').read_text()
        assert 'docker info' in events and 'docker compose version' in events
        assert 'stop postgres' not in events and ' down' not in events
        if case == 'success':
            assert (state/'status').read_text() == 'ready_for_cutover', output
            assert (maintenance/'read-only').exists() and (state/'writers-paused').exists()
            assert (state/'restored').read_bytes() == (state/'tally-before-gate.dump').read_bytes()
        else:
            assert (state/'status').read_text() == 'failed', output
            assert not (maintenance/'read-only').exists() and not (state/'writers-paused').exists()
        print('PASS: combined prepare ' + case)
