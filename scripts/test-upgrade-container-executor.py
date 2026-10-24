#!/usr/bin/env python3
"""Exercise the real detached executor against a disposable local Docker source.

Build the runtime first:
  docker build --target runtime -f deploy/compose/Dockerfile.tallyd -t tally-upgrade-runtime-test .
  python3 scripts/test-upgrade-container-executor.py
This tests lifecycle/mount/group behavior; it does not perform a registered Gate cutover.
"""
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, capture_output=True, text=True)


def main():
    image = os.environ.get("TALLY_TEST_RUNTIME_IMAGE", "tally-upgrade-runtime-test")
    socket = Path(os.environ.get("TALLY_TEST_DOCKER_SOCKET", "/var/run/docker.sock"))
    uid, gid = os.getuid(), os.getgid()
    source = "tally-executor-test-" + secrets.token_hex(6)
    # The tested contract requires the local engine to see this absolute host path.
    with tempfile.TemporaryDirectory(prefix="tally-executor-test-") as directory:
        root = Path(directory)
        fixture = root / "fixture.sh"
        fixture.write_text('''#!/bin/bash
set -euo pipefail
test "$(id -u)" = "$TALLY_TEST_EXPECT_UID"
test -S /var/run/docker.sock
test ! -e "$TALLY_UPGRADE_EXECUTOR_ENV_FILE"
mkdir -p "$TALLY_UPGRADE_STATE_DIR/gate-upgrade"
docker stop --time 1 "$TALLY_UPGRADE_SOURCE_CONTAINER" >/dev/null
printf complete > "$TALLY_UPGRADE_STATE_DIR/gate-upgrade/status"
''')
        fixture.chmod(0o755)
        try:
            docker("run", "-d", "--name", source, "--no-healthcheck",
                   "--user", f"{uid}:{gid}", "--group-add", str(socket.stat().st_gid),
                   "-v", f"{socket}:/var/run/docker.sock", "-v", f"{root}:/data/upgrade",
                   "-v", f"{fixture}:/opt/tally/scripts/upgrade-tally-to-gate.sh:ro",
                   "-e", "TALLY_UPGRADE_CONTAINER_EXECUTION=1",
                   "-e", "TALLY_UPGRADE_STATE_DIR=/data/upgrade",
                   "-e", f"TALLY_TEST_EXPECT_UID={uid}",
                   "--entrypoint", "bash", image, "-c", "sleep infinity")
            result = docker("exec", source, "bash", "/opt/tally/scripts/upgrade-container-executor.sh", "cutover", check=False)
            receipt = root / "gate-upgrade/status"
            for _ in range(50):
                if receipt.exists():
                    break
                time.sleep(0.2)
            assert receipt.exists() and receipt.read_text() == "complete", result.stderr
            assert docker("inspect", "--format", "{{.State.Running}}", source).stdout.strip() == "false"
            assert not list(root.glob("executor-env.*")), "private executor environment file survived"
            print("PASS: detached helper survives source retirement, preserves UID/socket group, and removes its private environment file")
        finally:
            docker("rm", "-f", source, check=False)
            helper = root / "gate-upgrade/executor-container"
            if helper.exists():
                docker("rm", "-f", helper.read_text(), check=False)


if __name__ == "__main__":
    main()
