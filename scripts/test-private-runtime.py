#!/usr/bin/env python3
"""Opt-in real-database smoke test, isolated from the user's installed services.

Requires a built tallyd with embedded UI and the pinned database artifacts.
Never uses sudo or changes the user's Tally installation. Optional --launchd
registers a separate temporary service to test automatic recovery, then removes it.
"""
import argparse
import hashlib
import os
import plistlib
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--postgres-archive', type=Path, required=True)
    parser.add_argument('--clickhouse-binary', type=Path, required=True)
    parser.add_argument('--launchd', action='store_true', help='Also test a temporary isolated macOS LaunchAgent, removed afterwards')
    parser.add_argument('--browser-auth', action='store_true', help='Run the native browser authentication test against the disposable installation')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='tally-private-smoke-') as tmp:
        root = Path(tmp)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('TALLY_', 'XDG_'))}
        sockets = [socket.socket() for _ in range(4)]
        for listener in sockets:
            listener.bind(('127.0.0.1', 0))
        pg_port, ch_port, app_port, upgrade_port = [s.getsockname()[1] for s in sockets]
        for listener in sockets:
            listener.close()
        home = root/'home'; home.mkdir()
        env.update(HOME=str(home), TALLY_HOME=str(home/'.godel-tally'),
                   TALLY_POSTGRES_PORT=str(pg_port), TALLY_CLICKHOUSE_PORT=str(ch_port),
                   TALLY_UPGRADE_BIND=f'127.0.0.1:{upgrade_port}')
        tally_home = Path(env['TALLY_HOME']); runtime = tally_home/'runtime'; runtime.mkdir(parents=True)
        config = tally_home/'config'; data = tally_home/'data'
        (runtime/'.tally-runtime').write_text(str(config)+'\n')
        platform = ('darwin' if os.uname().sysname == 'Darwin' else 'linux') + ('-arm64' if os.uname().machine in ('arm64','aarch64') else '-amd64')
        rows = [line.split('|') for line in (ROOT/'scripts/database-assets.tsv').read_text().splitlines() if line and not line.startswith('#')]
        for db, target, version, kind, archive_root, digest, size, urls in rows:
            if target != platform: continue
            destination = runtime/f'{db}-{version}-{platform}'
            if db == 'postgres':
                assert hashlib.sha256(args.postgres_archive.read_bytes()).hexdigest() == digest, 'PostgreSQL fixture checksum mismatch'
                with tarfile.open(args.postgres_archive) as archive:
                    archive.extractall(runtime, filter='data')
                (runtime/archive_root).rename(destination)
            else:
                (destination/'bin').mkdir(parents=True)
                # ClickHouse's official compressed executable expands itself on first run.
                shutil.copy2(args.clickhouse_binary, destination/'bin/clickhouse')
            (destination/'.archive-sha256').write_text(digest+'\n')
        bundle = root/'bundle'; bundle.mkdir()
        shutil.copytree(ROOT/'scripts', bundle/'scripts')
        for file in ('install.sh','uninstall.sh'): shutil.copy2(ROOT/file, bundle/file)
        (bundle/'tallyd').symlink_to(args.binary.resolve())
        result = subprocess.run(['bash',str(bundle/'scripts/install-runtime.sh'),str(bundle),'--no-service','--port',str(app_port)], env=env, text=True, capture_output=True)
        assert result.returncode == 0, result.stdout+result.stderr
        print('PASS: real offline preparation; no service registration or database startup', flush=True)
        pg_bin = Path(next(line.split('=',1)[1] for line in (config/'tally.env').read_text().splitlines() if line.startswith('TALLY_PG_BIN=')))
        pg_password = next(line.split('=',1)[1] for line in (config/'tally.env').read_text().splitlines() if line.startswith('TALLY_POSTGRES_PASSWORD='))
        tls = ssl.create_default_context(cafile=str(data/'tls/tally.crt'))
        process = None
        child_pids = []
        sequence = 0

        def port_closed(port):
            with socket.socket() as sock:
                sock.settimeout(.2)
                return sock.connect_ex(('127.0.0.1',port)) != 0

        def wait_until(predicate, message, seconds=90):
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                if predicate(): return
                time.sleep(.1)
            logs='\n'.join(p.read_text(errors='replace')[-6000:] for p in [root/f'supervisor-{sequence}.log',data/'postgres.log',data/'clickhouse.log'] if p.exists())
            raise AssertionError(message+'\n'+logs)

        def start(ready=True):
            nonlocal process, sequence, child_pids
            sequence += 1
            log = root/f'supervisor-{sequence}.log'
            with log.open('w') as stream:
                process = subprocess.Popen(['bash',str(tally_home/'app/tally.sh')], env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            def healthy():
                if process.poll() is not None: raise AssertionError(log.read_text())
                try:
                    with urllib.request.urlopen(f'https://localhost:{app_port}/api/v1/tally/health/ready',context=tls,timeout=1) as response:
                        return response.status == 200
                except (OSError, urllib.error.URLError): return False
            if ready: wait_until(healthy,'Application did not become ready')
            child_pids = [(name,int(pid)) for name,pid in re.findall(r'started (\w+) \(PID (\d+)\)',log.read_text())]
            return log

        def stopped(expected=0):
            status=process.wait(timeout=90)
            assert (status == 0) == (expected == 0), (status, (root/f'supervisor-{sequence}.log').read_text())
            wait_until(lambda: all(port_closed(p) for p in (pg_port,ch_port,app_port)),'A service port was left open',30)
            for _,pid in child_pids:
                try: os.kill(pid,0)
                except ProcessLookupError: continue
                raise AssertionError(f'Child {pid} was left running')

        def psql(query):
            return subprocess.check_output([str(pg_bin/'psql'),'-h','127.0.0.1','-p',str(pg_port),'-U','tally','-d','tally','-Atc',query],env=dict(env,PGPASSWORD=pg_password),text=True).strip()

        try:
            assert all(port_closed(p) for p in (pg_port,ch_port,app_port))
            log=start()
            assert len(child_pids)==3, log.read_text()
            assert log.read_text().index('private databases are ready') < log.read_text().index('started application')
            if args.browser_auth:
                browser_env=dict(env,TALLY_WEB_URL=f'https://localhost:{app_port}',
                                 TALLY_E2E_NATIVE_AUTH='1',TALLY_E2E_IGNORE_HTTPS_ERRORS='1')
                subprocess.run(['npx','playwright','test','tests/e2e/native-auth.spec.ts','--workers=1'],
                               cwd=ROOT/'apps/web',env=browser_env,check=True)
                print('PASS: native browser registration, HTTP/2 cookies, login, and revocation',flush=True)
            psql('CREATE TABLE private_runtime_smoke (value text); INSERT INTO private_runtime_smoke VALUES (\'preserved\')')
            duplicate=subprocess.run(['bash',str(tally_home/'app/tally.sh')],env=env,capture_output=True,text=True,timeout=10)
            assert duplicate.returncode != 0 and 'already running' in duplicate.stderr, duplicate.stderr
            busy=subprocess.run([str(tally_home/'app/tallyd'),'check-stopped',str(data)],env=env,capture_output=True,text=True)
            assert busy.returncode != 0
            process.terminate();stopped()
            assert 'did not stop in time' not in log.read_text(),log.read_text()
            print('PASS: authenticated readiness, application startup, duplicate guard, orderly stop of all children',flush=True)
            start()
            os.killpg(process.pid,signal.SIGINT)
            stopped()
            print('PASS: terminal Ctrl+C stops Tally and both private databases',flush=True)
            for victim in ('postgres','clickhouse','application'):
                start()
                assert psql('SELECT value FROM private_runtime_smoke') == 'preserved'
                pid=next(pid for name,pid in child_pids if name==victim)
                os.kill(pid,signal.SIGKILL)
                stopped(expected=1)
                print(f'PASS: {victim} crash stops the remaining stack; restart retains data',flush=True)
            start()
            pid=next(pid for name,pid in child_pids if name=='clickhouse')
            os.kill(pid,signal.SIGSTOP)
            stopped(expected=1)
            assert 'failed three health checks' in (root/f'supervisor-{sequence}.log').read_text()
            print('PASS: a hung database is detected by active health checks and the stack stops',flush=True)
            blocker=socket.socket();blocker.bind(('127.0.0.1',pg_port));blocker.listen()
            try:
                start(ready=False)
                assert process.wait(timeout=10) != 0
                assert 'already in use' in (root/f'supervisor-{sequence}.log').read_text()
                assert port_closed(ch_port)
            finally: blocker.close()
            print('PASS: occupied database port fails before starting either database',flush=True)
            start(ready=False)
            wait_until(lambda: 'started postgres' in (root/f'supervisor-{sequence}.log').read_text(),'No PostgreSQL child',10)
            process.terminate();stopped()
            print('PASS: interrupted startup cleans up started databases',flush=True)
            # Bundled verifier covers systems whose OpenSSL lacks hostname checks.
            binary=str(tally_home/'app/tallyd'); certificate=str(data/'tls/tally.crt')
            subprocess.run([binary,'check-tls-host',certificate,'localhost'],check=True)
            invalid=subprocess.run([binary,'check-tls-host',certificate,'wrong.example'],capture_output=True)
            assert invalid.returncode != 0
            print('PASS: bundled TLS hostname verifier accepts matching SAN and rejects mismatch',flush=True)
            if args.launchd:
                assert os.uname().sysname == 'Darwin', '--launchd requires macOS'
                label=f'ai.godel.tally.smoke.{os.getpid()}'
                service=f'gui/{os.getuid()}/{label}'
                service_log=root/'launchd.log'
                plist=root/'smoke.plist'
                with plist.open('wb') as stream:
                    plistlib.dump({
                        'Label':label,'ProgramArguments':['/bin/bash',str(tally_home/'app/tally.sh')],
                        'EnvironmentVariables':{'TALLY_UPGRADE_BIND':env['TALLY_UPGRADE_BIND']},
                        'RunAtLoad':True,'KeepAlive':{'SuccessfulExit':False},'ThrottleInterval':2,
                        'ExitTimeOut':90,'AbandonProcessGroup':False,
                        'StandardOutPath':str(service_log),'StandardErrorPath':str(service_log),
                    },stream)
                def service_ready():
                    try:
                        with urllib.request.urlopen(f'https://localhost:{app_port}/api/v1/tally/health/ready',context=tls,timeout=1) as response:
                            return response.status==200
                    except (OSError,urllib.error.URLError): return False
                try:
                    subprocess.run(['launchctl','bootstrap',f'gui/{os.getuid()}',str(plist)],check=True)
                    wait_until(service_ready,'Temporary LaunchAgent did not start')
                    for victim in ('postgres','supervisor'):
                        previous=service_log.read_text()
                        count=previous.count('started application')
                        if victim=='supervisor':
                            subprocess.run(['launchctl','kill','SIGKILL',service],check=True)
                        else:
                            pid=int(re.findall(r'started postgres \(PID (\d+)\)',previous)[-1])
                            os.kill(pid,signal.SIGKILL)
                        wait_until(lambda: service_log.read_text().count('started application')>count and service_ready(),
                                   f'LaunchAgent did not recover after {victim} crash')
                        print(f'PASS: isolated LaunchAgent restarts whole stack after {victim} crash',flush=True)
                finally:
                    subprocess.run(['launchctl','bootout',service],check=True)
                wait_until(lambda: all(port_closed(p) for p in (pg_port,ch_port,app_port)),'LaunchAgent stop left a port open')
                assert 'did not stop in time' not in service_log.read_text(),service_log.read_text()
                print('PASS: stopping the isolated LaunchAgent stops both databases and Tally',flush=True)
            retained=subprocess.run(['bash',str(tally_home/'app/uninstall.sh')],env=env,capture_output=True,text=True)
            assert retained.returncode==0,retained.stdout+retained.stderr
            assert not (tally_home/'app/tallyd').exists()
            assert runtime.exists() and (data/'postgres/PG_VERSION').exists()
            assert not (data/'supervisor.lock').exists()
            cleanup=subprocess.run(['bash',str(bundle/'uninstall.sh'),'--remove-databases'],env=env,capture_output=True,text=True)
            assert cleanup.returncode == 0,cleanup.stdout+cleanup.stderr
            assert not runtime.exists() and not (data/'postgres').exists() and (config/'tally.env').exists()
            print('PASS: ordinary uninstall retains data; later database cleanup works without the application binary',flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try: process.wait(timeout=90)
                except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL);process.wait()


if __name__ == '__main__': main()
