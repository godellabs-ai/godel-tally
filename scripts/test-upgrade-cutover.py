#!/usr/bin/env python3
"""Exercise the real cutover branch with isolated host/Compose fixtures."""
import os
from pathlib import Path
import subprocess
import tempfile


source = Path(__file__).with_name("upgrade-tally-to-gate.sh").read_text()
definitions = source.split('\nif [ "$phase" = prepare ]; then', 1)[0]
cutover = source.split('\nelif [ "$phase" = cutover ]; then', 1)[1].split('\nelif [ "$phase" = status ]; then', 1)[0]
fixture = r'''
event() { printf '%s\n' "$*" >> "$state_dir/events"; }
sleep() { event "sleep $*"; }
kill() { event "kill $*"; }
kill_tree() { event "kill-tree $*"; }
validate_final_tls() { event 'certificate-checked'; }
verify_tally_http() { event 'tally-http-restored'; [ "$TEST_CASE" != rollback-router-fails ]; }
verify_counts() { event 'data-checked'; }
port_available() {
    if [ "$1" = 80 ]; then [ "$TEST_CASE" = https-on-80 ]; return; fi
    [ "$TEST_CASE" != unrelated-port ] || return 1
    [ "$1" = 443 ] || return 0
    [ -f "$state_dir/tally-router-paused" ] || [ -f "$maintenance_dir/http-paused" ] || return 1
    [ "$TEST_CASE" != port-never-frees ] || return 1
    if [ "$TEST_CASE" = delayed-port ]; then
        count="$(cat "$state_dir/port-checks" 2>/dev/null || echo 0)"
        count=$((count + 1)); printf '%s' "$count" > "$state_dir/port-checks"
        [ "$count" -gt 2 ] || return 1
    fi
}
docker() {
    case "$1" in
        port) echo '443/tcp -> 127.0.0.1:443' ;;
        inspect)
            if [ "$TEST_CASE" = router-config-fails ]; then echo 'created|nginx configuration invalid'
            else echo 'created|ports are not available: address already in use'; fi ;;
        volume) event 'tally-volume-retained' ;;
        *) echo "Unexpected fixture Docker call: $*" >&2; return 1 ;;
    esac
}
compose_tally() {
    event "tally $*"
    case "$*" in
        'ps -q router') echo tally-router ;;
        'stop router') touch "$state_dir/tally-router-paused" ;;
        'up -d --no-deps --wait --wait-timeout 120 router')
            [ "$TEST_CASE" != rollback-router-fails ] || return 1
            rm -f "$state_dir/tally-router-paused" ;;
        down)
            grep -q '^gate-fully-ready$' "$state_dir/events" || return 1
            [ "$TEST_CASE" != tally-retirement-fails ] || return 1 ;;
        *) echo "Unexpected fixture Tally call: $*" >&2; return 1 ;;
    esac
}
compose_gate() {
    event "gate $*"
    case "$*" in
        'exec -T postgres psql '*) echo fixture-registration-key ;;
        'ps -a -q router') echo gate-router ;;
        'stop router') return 0 ;;
        'up '*worker)
            if grep -q '^GGATE_TALLY_MIGRATION_MODE=0$' "$(read_record gate_dir)/.env"; then
                event 'gate-activation'
                [ "$TEST_CASE" != activation-fails ] || return 1
            fi ;;
        'up '*api)
            if [ "$TEST_CASE" = candidate-api-fails ] && grep -q '^CONSOLE_URL=https://gate.example.test' "$(read_record gate_dir)/.env"; then return 1; fi ;;
        'up '*router)
            if grep -q '^HTTPS_PORT=443$' "$(read_record gate_dir)/.env"; then
                if [ "$TEST_CASE" = router-config-fails ]; then echo 'nginx configuration invalid' >&2; return 1; fi
                if [ "$TEST_CASE" = transient-bind ]; then
                    count="$(cat "$state_dir/router-starts" 2>/dev/null || echo 0)"
                    count=$((count + 1)); printf '%s' "$count" > "$state_dir/router-starts"
                    if [ "$count" -le 2 ]; then echo 'ports are not available: address already in use' >&2; return 1; fi
                fi
            fi ;;
        *) echo "Unexpected fixture Gate call: $*" >&2; return 1 ;;
    esac
}
verify_url() {
    event "verify $1"
    if [ "$1" = https://gate.example.test:8443 ]; then
        [ "$TEST_CASE" != candidate-https-fails ] || return 1
        event 'gate-candidate-ready'
    elif [ "$1" = "$TEST_FINAL_URL" ]; then
        case "$TEST_CASE" in final-https-fails|rollback-router-fails) return 1 ;; esac
    fi
    if [ "$1" = "$TEST_FINAL_URL" ] && grep -q '^GGATE_TALLY_MIGRATION_MODE=0$' "$(read_record gate_dir)/.env"; then
        event 'gate-fully-ready'
    fi
    return 0
}
'''


def check_cutover():
    cases = [
        "shared-port", "different-port", "review-port", "https-on-80", "delayed-port", "transient-bind",
        "unrelated-port", "port-never-frees", "candidate-api-fails",
        "candidate-https-fails", "router-config-fails", "final-https-fails",
        "activation-fails", "rollback-router-fails", "tally-retirement-fails",
    ]
    success = {"shared-port", "different-port", "review-port", "https-on-80", "delayed-port", "transient-bind"}
    cases += ['native/' + case for case in ['shared-port', 'different-port', 'final-https-fails', 'activation-fails', 'rollback-router-fails']]
    cases += ['apple/shared-port', 'existing/shared-port']
    for scenario in cases:
        runtime, case = scenario.split('/', 1) if '/' in scenario else ('legacy', scenario)
        with tempfile.TemporaryDirectory(prefix="tally-cutover-fixture-") as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            runner = scripts / "cutover.sh"
            runner.write_text(definitions + fixture + '\nif [ "$phase" = cutover ]; then\n' + cutover + '\nfi\n')
            (scripts / "validate-gate-registration.py").write_text('print("2099-01-01T00:00:00Z")\n')
            state = root / ".local/upgrade/gate-upgrade"
            state.mkdir(parents=True)
            gate = root / "gate"
            (gate / "certs").mkdir(parents=True)
            original_env = "CONSOLE_URL=https://review.example.test:8443\nHTTPS_PORT=8443\nHTTP_PORT=8880\nGGATE_TALLY_MIGRATION_MODE=1\nGGATE_PUBLISH_HOST=127.0.0.1\n"
            (gate / ".env").write_text(original_env)
            (gate / "certs/console.crt").write_text("review-certificate")
            (gate / "certs/console.key").write_text("review-key")
            (gate / "certs/.self-signed").touch()
            (root / "fullchain.pem").write_text("production-certificate")
            (root / "privkey.pem").write_text("production-key")
            (state.parent / "dev-processes").write_text("API_PID=111\nCOLLECTOR_PID=222\nWEB_PID=333\n")
            maintenance = root / ".local/tally-maintenance/read-only"
            maintenance.parent.mkdir()
            maintenance.touch()
            if runtime != "legacy": (maintenance.parent/"writers-drained").touch()
            for name, value in {
                "status": "ready_for_cutover", "mode": "dev" if runtime == "legacy" else "combined", "writers-paused": "yes",
                "paused-pids": "444\n", "gate_dir": str(gate), "stage_http_port": "8880",
                "temp_url": "https://review.example.test:8443", "staging_cert": "review-certificate",
                "tally_volume": "fixture-tally-volume",
            }.items():
                (state / name).write_text(value)
            port = ":9443" if case in {"different-port", "unrelated-port"} else ":8443" if case == "review-port" else ":80" if case == "https-on-80" else ""
            final = "https://gate.example.test" + port
            result = subprocess.run(
                ["bash", str(runner), "cutover", "--final-url", final, "--tls-cert", str(root / "fullchain.pem"), "--tls-key", str(root / "privkey.pem")],
                env={**os.environ, "TALLY_UPGRADE_STATE_DIR": str(state.parent), "TEST_CASE": case, "TEST_FINAL_URL": final, "TALLY_URL": "https://tally.example.test", "TALLY_HTTP_BIND": "127.0.0.1:443", "TALLY_MAINTENANCE_DIR": str(maintenance.parent)},
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout + result.stderr
            events = (state / "events").read_text().splitlines()
            stopped = [event for event in events if event == "tally down" or event.startswith("kill")]
            if case in success:
                assert result.returncode == 0, output
                assert (state / "status").read_text() == "gate_live", output
                assert (state / "final_url").read_text() == final
                ready = events.index("gate-fully-ready")
                assert all(events.index(event) > ready for event in stopped), events
                assert not (state / "writers-paused").exists()
                if runtime == 'legacy': assert not maintenance.exists()
                else:
                    assert maintenance.exists() and (maintenance.parent/'retired').exists()
                    assert not stopped, events
                assert not (state / "cutover-review-backup").exists()
                if runtime != "legacy": assert "tally stop router" not in events
                elif case in {"different-port", "review-port", "https-on-80"}: assert "tally stop router" not in events
                else: assert events.index("gate-candidate-ready") < events.index("tally stop router")
                if case == "https-on-80": assert "HTTP_PORT=8880\n" in (gate / ".env").read_text()
                if case == "transient-bind":
                    assert (state / "router-starts").read_text() == "3"
                    assert sum("up -d --no-deps --wait --wait-timeout 45 router" in event for event in events) == 2
            else:
                assert result.returncode != 0, output
                if case == "tally-retirement-fails":
                    assert events.index("gate-fully-ready") < events.index("tally down")
                    assert (state / "final_url").read_text() == final
                    assert (state / "cutover_stage").read_text() == "retiring_tally"
                    assert (state / "status").read_text() == "cutover_failed"
                    assert (gate / "certs/console.crt").read_text() == "production-certificate"
                else:
                    assert not stopped, events
                    assert maintenance.exists() and (state / "writers-paused").exists()
                    assert (state / "paused-pids").exists()
                    assert (gate / ".env").read_text() == original_env
                    assert (gate / "certs/console.crt").read_text() == "review-certificate"
                    assert (gate / "certs/console.key").read_text() == "review-key"
                    if case != "unrelated-port":
                        stage = "activation_failed" if case == "activation-fails" else "recovery_failed" if case == "rollback-router-fails" else "preflight"
                        assert (state / "cutover_stage").read_text() == stage, output
                        assert (state / "status").read_text() == "cutover_failed"
                        if case != "rollback-router-fails":
                            assert not (state / "tally-router-paused").exists()
                            assert not (maintenance.parent/"http-paused").exists()
                            assert not (maintenance.parent/"retired").exists()
            print(f"PASS: {scenario}")


if __name__ == "__main__":
    check_cutover()
