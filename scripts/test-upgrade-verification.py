#!/usr/bin/env python3
"""Exercise the upgrade's real verification function with fixture databases."""
import os
from pathlib import Path
import subprocess
import tempfile


script = Path(__file__).resolve().with_name("upgrade-tally-to-gate.sh")
definitions = script.read_text().split('\nif [ "$phase" = prepare ]; then', 1)[0]
fixture = r'''
tally_count() {
    if [ "$1" = tally_auth_users ]; then echo 1; else echo 2; fi
}
gate_count() {
    if [ "$1" = tally_auth_users ]; then echo 1
    elif [ "$TEST_CASE" = fewer-rows ]; then echo 1
    elif [ "$TEST_CASE" = growth ]; then echo 3
    else echo 2; fi
}
compose_tally() {
    if [ "$TEST_CASE" = tally-query-failed ]; then return 1; fi
    printf 'copied-b\ncopied-a\n'
}
compose_gate() {
    case "$TEST_CASE" in
        gate-query-failed) return 1 ;;
        replaced-row) printf 'copied-a\nnew-gate-row\n' ;;
        fewer-rows) printf 'copied-a\n' ;;
        growth) printf 'new-gate-row\ncopied-b\ncopied-a\n' ;;
        *) printf 'copied-a\ncopied-b\n' ;;
    esac
}
verify_users() { echo 'Verified user identities'; }
verify_registry() { echo 'Verified registry decisions'; }
verify_counts
'''


def check_verification():
    cases = [
        ("growth", None),
        ("equal", None),
        ("replaced-row", "installations is missing 1 copied Tally rows in Gate"),
        ("fewer-rows", "installations is missing 1 copied Tally rows in Gate"),
        ("tally-query-failed", "could not read Tally installations primary keys"),
        ("gate-query-failed", "could not read Gate installations primary keys"),
    ]
    with tempfile.TemporaryDirectory(prefix="tally-upgrade-verification-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        runner = root / "scripts/verify.sh"
        runner.write_text(definitions + fixture)
        for case, error in cases:
            state = root / case
            result = subprocess.run(
                ["bash", str(runner), "fixture"], cwd=root, capture_output=True, text=True,
                env={**os.environ, "TALLY_UPGRADE_STATE_DIR": str(state), "TEST_CASE": case},
                timeout=10,
            )
            if error is None:
                assert result.returncode == 0, result.stdout + result.stderr
                assert "Verified audit_log:" in result.stdout, result.stdout
                assert "Verified user identities" in result.stdout
                assert "Verified registry decisions" in result.stdout
            else:
                assert result.returncode != 0, result.stdout + result.stderr
                assert error in result.stderr, result.stderr
            assert not list(state.glob("gate-upgrade/verification-keys.*"))
            print(f"PASS: {case}")


if __name__ == "__main__":
    check_verification()
