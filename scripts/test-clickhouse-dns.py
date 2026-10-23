#!/usr/bin/env python3
"""Verify private ClickHouse DNS-cache behavior with an isolated real server.

Uses the installer's generated config via the deployment fixture, then replaces
only test paths, ports, credentials, and logging. No installed services change.
"""
import argparse
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('deployment', Path(__file__).with_name('test-deployment.py'))
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    fixture = module.Deployment()
    fixture.setUp()
    try:
        fixture.install('--no-service')
        source = Path(fixture.env['TALLY_CONFIG_DIR'])/'clickhouse.xml'
        for disabled in (False, True):
            root = fixture.root/('disabled' if disabled else 'enabled')
            root.mkdir()
            config = ET.parse(source)
            tree = config.getroot()
            for name, value in {
                'path': f'{root}/data/', 'tmp_path': f'{root}/tmp/',
                'user_files_path': f'{root}/user_files/', 'logger/level': 'trace',
                'disable_internal_dns_cache': '1' if disabled else '0',
            }.items():
                tree.find(name).text = value
            for name in ('data', 'tmp', 'user_files'):
                (root/name).mkdir()
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            tree.find('http_port').text = str(port)
            ET.SubElement(tree, 'dns_cache_update_period').text = '1'
            user = tree.find('users/tally')
            user.remove(user.find('password_sha256_hex'))
            ET.SubElement(user, 'password').text = ''
            path = root/'config.xml'
            config.write(path)
            log = root/'server.log'
            with log.open('w') as output:
                process = subprocess.Popen([str(args.binary.resolve()), 'server', f'--config-file={path}'], stdout=output, stderr=subprocess.STDOUT)
            try:
                http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                def query(sql):
                    request = urllib.request.Request(f'http://127.0.0.1:{port}/?user=tally', data=sql.encode())
                    return http.open(request, timeout=2).read().decode().strip()
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise AssertionError(log.read_text()[-5000:])
                    try:
                        assert query('SELECT 1') == '1'
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise AssertionError(log.read_text()[-5000:])
                        time.sleep(.1)
                # More than three accelerated update intervals; queries continue to work.
                time.sleep(4)
                assert query('SELECT 42') == '42'
                entries = log.read_text()
                started = 'DNSCacheUpdater: Update period' in entries
                assert started is not disabled, entries[-5000:]
                if disabled:
                    assert 'DNS_ERROR' not in entries, entries[-5000:]
                print(f'PASS: cache disabled={disabled}; updater started={started}; SQL remains healthy', flush=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    finally:
        fixture.tearDown()


if __name__ == '__main__':
    main()
