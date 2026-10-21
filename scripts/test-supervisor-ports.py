#!/usr/bin/env python3
"""Check the built supervisor's port preflight without starting real databases."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


class SupervisorPorts(unittest.TestCase):
    def check_occupied(self, database, host):
        with tempfile.TemporaryDirectory(prefix='tally-port-test-') as tmp, \
                socket.socket() as blocker, socket.socket() as reserve:
            blocker.bind((host, 0))
            blocker.listen()
            blocked_port = blocker.getsockname()[1]
            reserve.bind(('127.0.0.1', 0))
            free_port = reserve.getsockname()[1]
            reserve.close()
            pg, ch = ((blocked_port, free_port) if database == 'PostgreSQL'
                      else (free_port, blocked_port))
            env = {k: v for k, v in os.environ.items() if not k.startswith('TALLY_')}
            env.update(TALLY_DATA_DIR=tmp, TALLY_CONFIG_DIR=tmp,
                       TALLY_POSTGRES_MODE='native', TALLY_CLICKHOUSE_MODE='native',
                       TALLY_PG_BIN=tmp+'/must-not-start',
                       TALLY_CLICKHOUSE_BIN=tmp+'/must-not-start',
                       TALLY_POSTGRES_PASSWORD='isolated-test',
                       TALLY_CLICKHOUSE_PASSWORD='isolated-test',
                       TALLY_POSTGRES_PORT=str(pg), TALLY_CLICKHOUSE_PORT=str(ch))
            result = subprocess.run([str(BINARY), 'supervise'], env=env,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f'port {blocked_port} is already in use', result.stderr)
            self.assertNotIn('started postgres', result.stderr)
            self.assertNotIn('started clickhouse', result.stderr)
            self.assertFalse((Path(tmp)/'postgres.log').exists())
            self.assertFalse((Path(tmp)/'clickhouse.log').exists())
            # The other service still owns its listener after Tally refuses startup.
            with socket.create_connection(('127.0.0.1', blocked_port), timeout=1):
                pass
            with socket.socket() as available:
                available.bind(('127.0.0.1', free_port))

    def test_postgres_loopback(self):
        self.check_occupied('PostgreSQL', '127.0.0.1')

    def test_postgres_all_addresses(self):
        self.check_occupied('PostgreSQL', '0.0.0.0')

    def test_clickhouse_loopback(self):
        self.check_occupied('ClickHouse', '127.0.0.1')

    def test_clickhouse_all_addresses(self):
        self.check_occupied('ClickHouse', '0.0.0.0')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    BINARY = args.binary.resolve()
    unittest.main(argv=[__file__], verbosity=2)
