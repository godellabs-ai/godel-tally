#!/usr/bin/env python3
"""Exercise persistent local TLS without changing browser or system trust."""
import os
from pathlib import Path
import shutil
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading


def check_make_up():
    """Run the native launcher through real TLS setup with fake databases and binary."""
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="tally-make-up-tls-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        for name in ["Makefile", "prod-run.sh"]:
            shutil.copy(repo / name, root / name)
        for name in ["ensure-tally-tls.sh", "check-tls-host.sh", "runtime-common.sh"]:
            shutil.copy(repo / "scripts" / name, root / "scripts" / name)
        (root / "scripts/data-services.sh").write_text("#!/bin/bash\nexit 0\n")
        binary = root / "tallyd"
        binary.write_text('''#!/usr/bin/env bash
[ "${1:-}" != --check-ui ] || exit 0
if [ "${1:-}" = check-tls-host ]; then
    unset TALLY_BINARY
    exec bash "$TALLY_TLS_FIXTURE_HELPER" "$2" "$3"
fi
[ -r "$TALLY_TLS_CERT_FILE" ] && [ -r "$TALLY_TLS_KEY_FILE" ] || exit 74
printf 'TLS fixture reached native binary.\\n' >&2
exit 73
''')
        binary.chmod(0o755)
        env = {key: value for key, value in os.environ.items() if not key.startswith(("TALLY_", "TALLY_UPGRADE_"))}
        env.update(TALLY_URL="https://localhost:8443", TALLY_BINARY=str(binary),
                   TALLY_TLS_FIXTURE_HELPER=str(root / "scripts/check-tls-host.sh"))
        env.pop("BASH_ENV", None)
        command = ["make", "--no-print-directory", "up"]

        def startup():
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
            assert result.returncode != 0 and "TLS fixture reached native binary." in result.stderr, result.stdout + result.stderr
            return result

        result = startup()
        assert f"Created Tally's local browser certificate in {root.resolve() / '.local/tls'}." in result.stdout, result.stdout
        cert = root / ".local/tls/tally.crt"
        key = root / ".local/tls/tally.key"
        original = (cert.read_bytes(), key.read_bytes())
        startup()
        assert (cert.read_bytes(), key.read_bytes()) == original, "make up rotated valid default TLS"
        print("PASS: native make up generates and reuses TLS before executing tallyd")


def check_tls():
    repo = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="tally-tls-test-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        for name in ["ensure-tally-tls.sh", "check-tls-host.sh"]:
            shutil.copy(repo / "scripts" / name, root / "scripts" / name)
        tools = root / "bin"
        tools.mkdir()
        events = root / "trust-events"
        for name in ["mkcert", "security", "sudo"]:
            (tools / name).write_text('''#!/usr/bin/env bash
printf '%s\\n' "${0##*/}" >> "$TALLY_TLS_TEST_EVENTS"
exit 99
''')
        if os.environ.get("TALLY_TLS_TEST_OPENSSL"):
            (tools / "openssl").write_text(
                "#!/usr/bin/env bash\nexec " + shlex.quote(os.environ["TALLY_TLS_TEST_OPENSSL"]) + ' "$@"\n'
            )
        for tool in tools.iterdir():
            tool.chmod(0o755)
        env = {**os.environ, "TALLY_URL": "https://localhost",
               "PATH": str(tools) + os.pathsep + os.environ["PATH"],
               "TALLY_TLS_TEST_EVENTS": str(events)}
        for key in ["TALLY_TLS_CERT_FILE", "TALLY_TLS_KEY_FILE"]:
            env.pop(key, None)

        def run(*args, success=True):
            result = subprocess.run(args, env=env, capture_output=True, text=True)
            assert (result.returncode == 0) == success, result.stdout + result.stderr
            return result

        def ensure(*args, success=True):
            return run("bash", str(root / "scripts/ensure-tally-tls.sh"), *args, success=success)

        cert = root / ".local/tls/tally.crt"
        key = root / ".local/tls/tally.key"
        result = ensure()
        assert "certificate was created on your computer" in result.stdout
        for host in ["localhost", "127.0.0.1", "::1"]:
            run("bash", str(root / "scripts/check-tls-host.sh"), str(cert), host)
        original = cert.read_bytes()
        inode = cert.stat().st_ino
        ensure()
        assert cert.read_bytes() == original, "startup rotated a valid certificate"
        # Verify a real TLS handshake with the exact leaf as the trust anchor.
        # LibreSSL's CAfile verification expects a CA and rejects CA:FALSE leaves.
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert, key)
        client_context = ssl.create_default_context(cafile=str(cert))
        errors = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)

            def serve():
                try:
                    connection, _ = listener.accept()
                    with server_context.wrap_socket(connection, server_side=True) as tls:
                        assert tls.recv(1) == b"1"
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            with socket.create_connection(listener.getsockname(), timeout=5) as connection:
                with client_context.wrap_socket(connection, server_hostname="localhost") as tls:
                    tls.send(b"1")
            thread.join(timeout=5)
            assert not thread.is_alive() and not errors, errors
        extensions = run("openssl", "x509", "-in", str(cert), "-noout", "-text").stdout
        assert "CA:FALSE" in extensions and "TLS Web Server Authentication" in extensions
        assert key.stat().st_mode & 0o777 == 0o600
        assert cert.stat().st_mode & 0o777 == 0o644
        run("openssl", "x509", "-in", str(cert), "-noout", "-checkend", str(3649 * 86400))
        print("PASS: self-signed server leaf, loopback SANs, permissions and stable reuse")

        key.write_text("invalid private key")
        ensure()
        assert cert.read_bytes() != original
        assert cert.stat().st_ino == inode, "Docker file bind mount lost its certificate inode"
        print("PASS: mismatched key repaired without replacing the mounted inode")

        expired = root / "expired.crt"
        expired_key = root / "expired.key"
        shutil.copy(key, expired_key)
        (root / "index").touch()
        (root / "serial").write_text("01\n")
        config = root / "ca.cnf"
        config.write_text(f"""[ca]
default_ca = fixture
[fixture]
database = {root / 'index'}
serial = {root / 'serial'}
new_certs_dir = {root}
certificate = {cert}
private_key = {key}
default_md = sha256
policy = names
x509_extensions = san
[names]
commonName = supplied
[san]
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
""")
        csr = root / "expired.csr"
        run("openssl", "req", "-new", "-key", str(key), "-subj", "/CN=localhost", "-out", str(csr))
        run("openssl", "ca", "-selfsign", "-batch", "-config", str(config), "-in", str(csr),
            "-startdate", "20200101000000Z", "-enddate", "20200102000000Z", "-out", str(expired))
        cert.write_bytes(expired.read_bytes())
        ensure()
        run("openssl", "x509", "-in", str(cert), "-noout", "-checkend", "86400")
        print("PASS: expired default certificate renewed")

        # Keep an otherwise valid certificate even within a day of expiry.
        near_expiry = root / "near-expiry.crt"
        near_ext = root / "near-expiry.ext"
        near_ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n")
        run("openssl", "req", "-new", "-key", str(key), "-subj", "/CN=localhost", "-out", str(csr))
        run("openssl", "x509", "-req", "-in", str(csr), "-signkey", str(key), "-days", "1",
            "-extfile", str(near_ext), "-out", str(near_expiry))
        cert.write_bytes(near_expiry.read_bytes())
        ensure()
        assert cert.read_bytes() == near_expiry.read_bytes(), "valid near-expiry certificate rotated"
        print("PASS: valid older certificate retained until actual expiry")

        env["TALLY_TLS_CERT_FILE"] = str(cert)
        env["TALLY_TLS_KEY_FILE"] = str(key)
        env["TALLY_URL"] = "https://wrong.example.test"
        assert "does not cover" in run("bash", str(root / "scripts/ensure-tally-tls.sh"), success=False).stderr
        env["TALLY_URL"] = "https://localhost"
        env["TALLY_TLS_CERT_FILE"] = str(expired)
        env["TALLY_TLS_KEY_FILE"] = str(expired_key)
        assert "expired" in run("bash", str(root / "scripts/ensure-tally-tls.sh"), success=False).stderr
        for name in ["TALLY_TLS_CERT_FILE", "TALLY_TLS_KEY_FILE"]:
            env.pop(name)
        print("PASS: invalid custom certificates rejected")

        # Simulate an older default certificate issued by a local CA.
        ca = root / "ca.crt"
        ca_key = root / "ca.key"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            "-subj", "/CN=Fixture CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(ca_key), "-out", str(ca))
        run("openssl", "req", "-new", "-key", str(key), "-subj", "/CN=localhost", "-out", str(csr))
        extensions = root / "server.ext"
        extensions.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
                              "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n")
        issued = root / "issued.crt"
        run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
            "-CAcreateserial", "-days", "30", "-extfile", str(extensions), "-out", str(issued))

        # Operator-provided PEM chain/key files are preserved, including paths with spaces.
        operator_dir = root / "operator certificates"
        operator_dir.mkdir()
        fullchain = operator_dir / "fullchain.pem"
        private_key = operator_dir / "privkey.pem"
        fullchain.write_bytes(issued.read_bytes() + ca.read_bytes())
        shutil.copy(key, private_key)
        supplied = (fullchain.read_bytes(), private_key.read_bytes())
        defaults = (cert.read_bytes(), key.read_bytes())
        env["TALLY_TLS_CERT_FILE"] = str(fullchain)
        env["TALLY_TLS_KEY_FILE"] = str(private_key)
        assert "Using the supplied" in ensure().stdout
        assert (fullchain.read_bytes(), private_key.read_bytes()) == supplied
        assert (cert.read_bytes(), key.read_bytes()) == defaults
        for missing in ["TALLY_TLS_CERT_FILE", "TALLY_TLS_KEY_FILE"]:
            value = env.pop(missing)
            assert "must both be readable" in ensure(success=False).stderr
            env[missing] = value
        env["TALLY_TLS_KEY_FILE"] = str(ca_key)
        assert "do not match" in ensure(success=False).stderr
        for name in ["TALLY_TLS_CERT_FILE", "TALLY_TLS_KEY_FILE"]:
            env.pop(name)
        print("PASS: supplied full chain/key preserved; incomplete and mismatched pairs rejected")

        cert.write_bytes(issued.read_bytes())
        env["CAROOT"] = str(root / "different-user-ca")
        ensure()
        assert cert.read_bytes() == issued.read_bytes(), "existing valid CA-signed certificate rotated"
        assert cert.stat().st_ino == inode
        print("PASS: valid CA-signed certificate reused independently of certificate tools")

        env["TALLY_URL"] = "https://shared.example.test"
        ensure()
        run("bash", str(root / "scripts/check-tls-host.sh"), str(cert), "shared.example.test")
        original = cert.read_bytes()
        env["TALLY_URL"] = "https://localhost"
        ensure()
        assert cert.read_bytes() == original, "switching to a covered hostname rotated certificate"
        env["TALLY_URL"] = "https://127.0.0.1:8443"
        ensure()
        assert cert.read_bytes() == original
        print("PASS: covered hostname/IP/port changes reuse the certificate")

        env["TALLY_TLS_CERT_FILE"] = str(cert)
        env["TALLY_TLS_KEY_FILE"] = str(key)
        original = cert.read_bytes()
        ensure()
        assert cert.read_bytes() == original
        assert not events.exists(), "TLS setup invoked a certificate or trust installer"
        print("PASS: custom TLS is validated without regeneration or trust changes")


if __name__ == "__main__":
    check_make_up()
    check_tls()
