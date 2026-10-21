#!/usr/bin/env python3
"""Check source database routing and connection privacy without contacting a database."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('source_db', Path(__file__).with_name('tally-source-db.py'))
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class SourceDatabase(unittest.TestCase):
    def test_existing_url_preserves_tls_and_never_puts_credentials_in_argv(self):
        env = dict(os.environ, TALLY_POSTGRES_MODE='existing',
                   TALLY_POSTGRES_URL='postgres://alice:p%40ss%3Aword@db.example:5544/tally?sslmode=verify-full&sslrootcert=/certs/ca.pem',
                   PGSERVICE='unrelated', PGSSLMODE='disable')
        # The test's Python executable stands in for a locally installed client.
        env['PATH'] = str(Path(sys.executable).parent) + ':' + env.get('PATH', '')
        from unittest.mock import patch
        with patch.object(source.shutil, 'which', return_value='/usr/bin/psql'):
            argv, child = source.command(['query', 'SELECT 1'], env)
        self.assertNotIn('p@ss:word', ' '.join(argv))
        self.assertEqual(child['PGPASSWORD'], 'p@ss:word')
        self.assertEqual(child['PGUSER'], 'alice')
        self.assertEqual(child['PGPORT'], '5544')
        self.assertEqual(child['PGSSLMODE'], 'verify-full')
        self.assertEqual(child['PGSSLROOTCERT'], '/certs/ca.pem')
        self.assertNotIn('PGSERVICE', child)

    def test_private_clients_take_precedence_over_system_clients(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            for name,operation in [('psql',['query','SELECT 1']),('pg_dump',['dump'])]:
                client=Path(directory)/name
                client.write_text('#!/bin/sh\nexit 0\n');client.chmod(0o755)
                env=dict(TALLY_POSTGRES_MODE='native',TALLY_PG_BIN=directory,
                         TALLY_POSTGRES_URL='postgres://tally:private-secret@127.0.0.1:5433/tally')
                with patch.object(source.shutil,'which',return_value='/system/older/'+name) as system:
                    argv,child=source.command(operation,env)
                self.assertEqual(argv[0],str(client))
                system.assert_not_called()
                self.assertNotIn('private-secret',' '.join(argv))
                self.assertEqual(child['PGPASSWORD'],'private-secret')

    def test_unsupported_connection_options_fail_before_any_database_command(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported PostgreSQL'):
            source.command(['dump'], dict(TALLY_POSTGRES_URL='postgres://user@db/tally?unknown_option=1'))

    def test_managed_container_clients_and_dump(self):
        for mode, engine in [('docker', 'docker'), ('apple', 'container')]:
            argv, _ = source.command(['dump'], dict(TALLY_POSTGRES_MODE=mode, TALLY_CONTAINER_PREFIX='private-tally'))
            self.assertEqual(argv[:5], [engine, 'exec', '-i', 'private-tally-postgres', 'pg_dump'])
            self.assertIn('-Fc', argv)
            self.assertNotIn('run', argv)

    def test_full_docker_source_stays_on_host_compose(self):
        argv, _ = source.command(['query', 'SELECT 1'], dict(TALLY_RUNTIME_MODE='combined-compose', TALLY_UPGRADE_TALLY_ROOT='/tally'))
        self.assertEqual(argv[:4], ['docker', 'compose', '-f', '/tally/docker-compose.yml'])
        self.assertEqual(argv[4:8], ['exec', '-T', 'postgres', 'psql'])


if __name__ == '__main__': unittest.main()
