#!/usr/bin/env python3
"""Run a PostgreSQL client against standalone Tally without putting secrets in argv."""
import os
from pathlib import Path
import shutil
import sys
from urllib.parse import parse_qsl, unquote, urlsplit


def command(args, env):
    operation, *arguments = args
    if operation not in ('query', 'dump'):
        raise ValueError('expected query SQL or dump')
    client = 'psql' if operation == 'query' else 'pg_dump'
    flags = ['-X', '-v', 'ON_ERROR_STOP=1', '-Atc', *arguments] if operation == 'query' else ['-Fc', '--no-owner']
    mode = env.get('TALLY_POSTGRES_MODE', env.get('TALLY_DB_MODE', 'native'))
    runtime = env.get('TALLY_RUNTIME_MODE', 'combined')
    if runtime == 'combined-compose' and mode != 'existing':
        return ['docker', 'compose', '-f', str(Path(env['TALLY_UPGRADE_TALLY_ROOT'])/'docker-compose.yml'),
                'exec', '-T', 'postgres', client, '-U', 'tally', '-d', 'tally', *flags], env
    if mode in ('docker', 'apple'):
        engine = 'docker' if mode == 'docker' else 'container'
        name = env.get('TALLY_CONTAINER_PREFIX', 'godel-tally-dev') + '-postgres'
        return [engine, 'exec', '-i', name, client, '-U', 'tally', '-d', 'tally', *flags], env
    url = urlsplit(env['TALLY_POSTGRES_URL'])
    if url.scheme not in ('postgres', 'postgresql') or not url.hostname:
        raise ValueError('TALLY_POSTGRES_URL must be a PostgreSQL URL')
    # Do not inherit unrelated libpq credentials or service files.
    child = {k: v for k, v in env.items() if not k.startswith('PG')}
    child.update(PGHOST=url.hostname, PGPORT=str(url.port or 5432),
                 PGUSER=unquote(url.username or ''), PGPASSWORD=unquote(url.password or ''),
                 PGDATABASE=unquote(url.path.lstrip('/')), PGCONNECT_TIMEOUT='10')
    options = {'sslmode': 'PGSSLMODE', 'sslrootcert': 'PGSSLROOTCERT', 'sslcert': 'PGSSLCERT',
               'sslkey': 'PGSSLKEY', 'sslcrl': 'PGSSLCRL', 'sslcrldir': 'PGSSLCRLDIR',
               'connect_timeout': 'PGCONNECT_TIMEOUT', 'application_name': 'PGAPPNAME',
               'options': 'PGOPTIONS', 'channel_binding': 'PGCHANNELBINDING',
               'target_session_attrs': 'PGTARGETSESSIONATTRS', 'sslnegotiation': 'PGSSLNEGOTIATION'}
    for key, value in parse_qsl(url.query):
        if key not in options:
            raise ValueError('Unsupported PostgreSQL connection option: ' + key)
        child[options[key]] = value
    binary = shutil.which(client, path=env.get('PATH'))
    if not binary:
        candidates = [Path(p)/client for p in (
            env.get('TALLY_PG_BIN', ''), '/opt/homebrew/opt/postgresql@18/bin',
            '/usr/local/opt/postgresql@18/bin', '/usr/lib/postgresql/18/bin', '/usr/pgsql-18/bin') if p]
        binary = next((str(p) for p in candidates if p.is_file() and os.access(p, os.X_OK)), None)
    if not binary:
        raise ValueError('Install PostgreSQL client tools matching the source server (psql and pg_dump), or set TALLY_PG_BIN')
    return [binary, *flags], child


if __name__ == '__main__':
    try:
        argv, environment = command(sys.argv[1:], dict(os.environ))
        os.execvpe(argv[0], argv, environment)
    except (ValueError, KeyError, OSError) as error:
        sys.exit('Tally source database: ' + str(error))
