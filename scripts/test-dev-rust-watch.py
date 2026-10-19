#!/usr/bin/env python3
"""Exercise dev watch pause/resume without compiling or touching the dev stack."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def check_watch():
    helper = Path(__file__).resolve().with_name("dev-rust-watch.sh")
    with tempfile.TemporaryDirectory(prefix="tally-dev-watch-") as directory:
        outer = Path(directory)
        root = outer / "project"
        root.mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="watch_probe"\nversion="0.1.0"\nedition="2021"\n'
        )
        (root / "Cargo.lock").write_text("# fixture\n")
        (root / "rust-toolchain.toml").write_text('[toolchain]\nchannel="stable"\n')
        (root / ".gitignore").write_text("/.local/\n/target/\n")
        (root / "src").mkdir()
        (root / "src/main.rs").write_text("fn main() {}\n")
        for name in ["crates", "apps/tallyd", "apps/tally-collector", "apps/tally-upgrade",
                     "apps/tally-registry", "registry-data", "testdata", ".cargo",
                     ".local", "apps/web"]:
            (root / name).mkdir(parents=True, exist_ok=True)
        watched_files = ["crates/probe.rs", "apps/tally-upgrade/prompt.md", "Cargo.toml",
                         "Cargo.lock", ".cargo/config.toml", "registry-data/probe.json"]
        for name in watched_files:
            path = root / name
            if not path.exists():
                path.write_text("# fixture\n")
        runner = outer / "runner.py"
        runner.write_text('import os,time\nprint("CHILD",os.getpid(),flush=True)\ntime.sleep(120)\n')
        args = subprocess.check_output(
            ["bash", "-c", 'source "$1"; printf "%s\\0" "${TALLY_RUST_WATCH_ARGS[@]}"',
             "watch-test", str(helper)], cwd=root,
            env={**os.environ, "REPO_DIR": str(root)},
        ).decode().rstrip("\0").split("\0")
        log = outer / "watch.log"

        def children():
            return [int(line.split()[1]) for line in log.read_text(errors="replace").splitlines()
                    if line.startswith("CHILD ")]

        def wait_for_count(count):
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                found = children()
                if len(found) >= count:
                    return found[-1]
                if watcher.poll() is not None:
                    break
                time.sleep(0.05)
            raise AssertionError(f"Expected {count} launches:\n{log.read_text()}")

        with log.open("wb") as output:
            watcher = subprocess.Popen(
                ["cargo", "watch", *args, "--", sys.executable, "-u", str(runner)],
                cwd=root, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                child = wait_for_count(1)
                time.sleep(1)
                os.kill(child, signal.SIGSTOP)
                os.kill(watcher.pid, signal.SIGSTOP)
                state = root / ".local/upgrade/gate-upgrade"
                state.mkdir(parents=True)
                for index in range(1000):
                    (state / f"state-{index}").write_text(str(index))
                for path in state.iterdir():
                    path.unlink()
                state.rmdir()
                (root / "apps/web/page.tsx").write_text("fixture\n")
                time.sleep(1)
                os.kill(child, signal.SIGCONT)
                os.kill(watcher.pid, signal.SIGCONT)
                time.sleep(3)
                assert children() == [child], f"Ignored upgrade state restarted worker:\n{log.read_text()}"
                print("PASS: ignored upgrade and web changes preserve the worker across pause/resume.")
                for count, name in enumerate(watched_files, start=2):
                    with (root / name).open("a") as changed:
                        changed.write("\n")
                    wait_for_count(count)
                print("PASS: crate, Upgrade, manifest, lockfile, Cargo config and registry edits restart it.")
            finally:
                if watcher.poll() is None:
                    watcher.send_signal(signal.SIGCONT)
                    watcher.terminate()
                try:
                    watcher.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    watcher.kill()
                    watcher.wait()
                for child in children():
                    try:
                        os.kill(child, signal.SIGCONT)
                        os.kill(child, signal.SIGTERM)
                    except ProcessLookupError:
                        pass


if __name__ == "__main__":
    check_watch()
