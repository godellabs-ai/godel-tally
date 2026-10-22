#!/usr/bin/env python3
"""Deployment contracts without package installs, containers, or real user services."""
import os
from pathlib import Path
import plistlib
import re
import hashlib
import tarfile
import shutil
import subprocess
import tempfile
import signal
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]

STUB = '''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['FIXTURE'])
with (root/'commands').open('a') as f: f.write(json.dumps([name, *args])+'\\n')
if name == os.environ.get('FAIL_COMMAND'): sys.exit(23)
if name == 'curl' and os.environ.get('FAIL_HTTP_READY') and any('/health/ready' in a for a in args): sys.exit(7)
if name == 'brew' and args[0] == 'install' and os.environ.get('TEST_BREW_PROMPT'):
    if os.environ.get('HOMEBREW_NO_ASK') != '1' or os.environ.get('HOMEBREW_ASK'):
        print('Invalid input. Please press y or n.', file=sys.stderr); sys.exit(2)
if name == 'uname': print(os.environ.get('TEST_OS','Linux') if '-s' in args else os.environ.get('TEST_ARCH','x86_64'))
elif name == 'id': print('1000' if '-u' in args else 'operator')
elif name == 'sw_vers': print(os.environ.get('TEST_MACOS','26.0'))
elif name == 'getconf': print(os.environ.get('TEST_LIBC','glibc 2.36'))
elif name == 'curl' and os.environ.get('BOOTSTRAP_SOURCE'):
    import shutil
    source=pathlib.Path(os.environ['BOOTSTRAP_SOURCE'])
    url=next(a for a in args if a.startswith('https://'))
    if url.endswith('/releases/latest'):
        print(os.environ.get('TEST_RELEASE_URL',url.removesuffix('/latest')+'/tag/v0.1.0'),end='')
    else:
        shutil.copyfile(source/url.rsplit('/',1)[1],args[args.index('-o')+1])
elif name == 'curl' and any('/fixture-' in a for a in args):
    import time
    url=next(a for a in args if a.startswith('https://'))
    asset=url.rsplit('/',1)[1]; db=asset.split('-')[1]
    if os.environ.get('FAIL_DOWNLOAD_HOST') and os.environ['FAIL_DOWNLOAD_HOST'] in url:
        print('curl: (6) Could not resolve host',file=sys.stderr); sys.exit(6)
    if os.environ.get('TEST_PARALLEL'):
        (root/('started-'+asset)).touch()
        deadline=time.monotonic()+5
        while len(list(root.glob('started-*'))) < 2:
            if time.monotonic()>deadline: sys.exit('Downloads did not overlap')
            time.sleep(.02)
    output=pathlib.Path(args[args.index('-o')+1]); data=(root/'assets'/asset).read_bytes()
    offset=output.stat().st_size if '-C' in args and output.exists() else 0
    if offset:
        with (root/'resumed').open('a') as f: f.write(f'{asset} {offset}\\n')
    stop=len(data)
    if os.environ.get('INTERRUPT_DATABASE') == db:
        interrupts=root/('interrupts-'+asset); count=int(interrupts.read_text()) if interrupts.exists() else 0
        if count < int(os.environ.get('INTERRUPT_COUNT','99')):
            interrupts.write_text(str(count+1)); stop=offset+(len(data)-offset)//2
    with output.open('ab' if offset else 'wb') as f:
        if os.environ.get('SLOW_DATABASE') == db:
            middle=offset+(stop-offset)//2; f.write(data[offset:middle]); f.flush()
            (root/'slow-curl').write_text(str(os.getpid())); time.sleep(11); offset=middle
        f.write(data[offset:stop])
    if stop < len(data):
        print('curl: (56) Recv failure: Connection reset by peer',file=sys.stderr); sys.exit(56)
    if os.environ.get('CORRUPT_DATABASE') == db:
        output.write_text('corrupt')
elif name == 'pg_config': print(root/'bin')
elif name == 'brew' and args[0] == '--prefix': print(root/'brew')
elif name in ['brew','dpkg-query','rpm','sudo'] and os.environ.get('TEST_PACKAGES'):
    state=root/'packages';state.mkdir(exist_ok=True)
    if name=='brew':
        package=state/args[-1]
        if args[0]=='list': sys.exit(0 if package.exists() else 1)
        elif args[0]=='install':
            package.touch()
            if os.environ.get('FAIL_PACKAGE_INSTALL'): sys.exit(1)
        elif args[0]=='uninstall': package.unlink(missing_ok=True)
    elif name=='dpkg-query':
        if not (state/args[-1]).exists(): sys.exit(1)
        print('install ok installed',end='')
    elif name=='rpm' and args[0]=='-q': sys.exit(0 if (state/args[-1]).exists() else 1)
    elif name=='sudo':
        if 'install' in args:
            for p in args[args.index('install')+1:]:
                if not p.startswith('-') and '/' not in p: (state/p).touch()
        elif args[0] in ['dpkg','rpm']:
            for p in args[2:]: (state/p).unlink(missing_ok=True)
elif name == 'initdb':
    data=pathlib.Path(args[args.index('-D')+1]); data.mkdir(parents=True,exist_ok=True); (data/'PG_VERSION').write_text('18')
elif name == 'postgres' and '--version' in args: print(os.environ.get('TEST_PG_BANNER','postgres (PostgreSQL) 18.6'))
elif name == 'psql': print('1')
elif name == 'openssl':
    if args[:2] == ['req','-help']: print('' if os.environ.get('TEST_OLD_OPENSSL') else '-addext')
    elif args[:2] == ['x509','-help']: print('-checkhost -checkip')
    elif args[0] == 'rand': print('a'*int(args[-1])*2)
    elif args[0] == 'dgst': print('SHA2-256(stdin)= '+'b'*64)
    elif args[0] == 'req':
        for flag in ['-keyout','-out']: pathlib.Path(args[args.index(flag)+1]).write_text('fixture TLS')
elif name in ['docker','container']:
    state=root/'containers';state.mkdir(exist_ok=True)
    if args[0]=='inspect':
        target=state/args[-1]
        if not target.exists(): sys.exit(1)
        if '--format' in args: print('true' if target.read_text()=='running' else 'false')
        elif name=='container':
            octet={'postgres':2,'clickhouse':3}.get(args[-1].rsplit('-',1)[-1],9)
            print(json.dumps([{'networks':[{'address':f'192.168.64.{octet}/24','gateway':'192.168.64.1'}]}]))
    elif args[0]=='ls':
        if name=='docker': print("unknown shorthand flag: 'q' in -q",file=sys.stderr); sys.exit(125)
        print('\\n'.join(p.name for p in state.iterdir() if p.read_text()=='running'))
    elif args[0] in ['start','stop']:
        target=state/args[1]
        if not target.exists(): sys.exit(1)
        target.write_text('running' if args[0]=='start' else 'stopped')
    elif args[0]=='run':
        cid=args[args.index('--name')+1]; (state/cid).write_text('running'); print(cid)
        if '--env-file' in args:
            envs=root/'container-env'; envs.mkdir(exist_ok=True)
            (envs/cid).write_text(pathlib.Path(args[args.index('--env-file')+1]).read_text())
    elif args[0] in ['rm','delete']: (state/args[1]).unlink(missing_ok=True)
    elif args[0]=='volume':
        volumes=root/'volumes';volumes.mkdir(exist_ok=True)
        volume=volumes/args[-1]
        if args[1]=='inspect': sys.exit(0 if volume.exists() else 1)
        elif args[1]=='create': volume.touch()
        elif args[1]=='rm': volume.unlink(missing_ok=True)
    elif args[0]=='exec' and os.environ.get('FAIL_READY'): sys.exit(1)
elif name == 'sleep': pass
'''

class Deployment(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tally-deployment-')
        self.root = Path(self.temp.name)
        self.bin = self.root/'bin'; self.bin.mkdir()
        for name in ['uname','id','sw_vers','docker','container','systemctl','launchctl','sudo',
                     'apt-get','yum','dnf','brew','pg_config','initdb','postgres','pg_isready',
                     'psql','createdb','clickhouse','curl','sleep','openssl','dpkg-query','rpm','dpkg','getconf']:
            path = self.bin/name; path.write_text(STUB); path.chmod(0o755)
        self.home = self.root/'home with spaces'; self.home.mkdir()
        self.bundle = self.root/'bundle'; self.bundle.mkdir()
        shutil.copytree(ROOT/'scripts', self.bundle/'scripts')
        shutil.copy(ROOT/'uninstall.sh', self.bundle/'uninstall.sh')
        shutil.copy(ROOT/'install.sh', self.bundle/'install.sh')
        (self.bundle/'tallyd').write_text('#!/bin/bash\n[ "$1" = --check-ui ]\n')
        (self.bundle/'tallyd').chmod(0o755)
        for path in [self.root/'brew/bin', self.root/'brew/postgresql@18/bin']:
            path.mkdir(parents=True, exist_ok=True)
        for name in ['initdb','postgres','pg_isready','psql','createdb','clickhouse']:
            (self.root/'brew/bin'/name).symlink_to(self.bin/name)
        assets=self.root/'assets';assets.mkdir()
        manifest=[]
        for platform in ['linux-amd64','linux-arm64','darwin-amd64','darwin-arm64']:
            for db,version in [('postgres','18.6.1'),('clickhouse','26.9.23.15')]:
                archive_root='postgres-runtime' if db=='postgres' else f'clickhouse-common-static-{version}/usr/bin'
                archive=assets/f'fixture-{db}-{platform}.tar.gz'
                with tarfile.open(archive,'w:gz') as package:
                    for binary in (['postgres','initdb','pg_isready','psql','createdb'] if db=='postgres' else ['clickhouse']):
                        entry=f'{archive_root}/bin/{binary}' if db=='postgres' else f'{archive_root}/{binary}'
                        package.add(self.bin/binary,arcname=entry)
                digest=hashlib.sha256(archive.read_bytes()).hexdigest()
                repo='theseus-rs/postgresql-binaries' if db=='postgres' else 'ClickHouse/ClickHouse'
                manifest.append(f'{db}|{platform}|{version}|tar|{archive_root}|{digest}|{archive.stat().st_size}|https://github.com/{repo}/releases/download/test/{archive.name}')
        (self.bundle/'scripts/database-assets.tsv').write_text('\n'.join(manifest)+'\n')
        self.env = {k: v for k,v in os.environ.items() if not k.startswith(('TALLY_','TALLY_UPGRADE_','XDG_'))}
        (self.root/"empty.env").touch()
        (self.root/"os-release").write_text("ID=ubuntu\nVERSION_ID=22.04\nVERSION_CODENAME=jammy\n")
        self.env.update(TALLY_OS_RELEASE_FILE=str(self.root/"os-release"), TALLY_ENV_FILE=str(self.root/"empty.env"), PATH=f'{self.bin}:{os.environ["PATH"]}', HOME=str(self.home), FIXTURE=str(self.root),
                        TALLY_DATA_DIR=str(self.root/'data with spaces'),
                        TALLY_CONFIG_DIR=str(self.root/'config with spaces'),
                        TALLY_INSTALL_DIR=str(self.root/'install with spaces'),
                        TALLY_RUNTIME_DIR=str(self.root/'runtime with spaces'))
    def tearDown(self): self.temp.cleanup()
    def run_script(self, script, *args, ok=True):
        result = subprocess.run(['bash',str(script),*map(str,args)], env=self.env, text=True, capture_output=True)
        if ok: self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        else: self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        return result
    def commands(self):
        import json
        return [json.loads(line) for line in (self.root/'commands').read_text().splitlines()]
    def install(self,*args,ok=True):
        if 'existing' in args:
            self.env.setdefault('TALLY_POSTGRES_URL','postgres://external/tally')
            self.env.setdefault('TALLY_CLICKHOUSE_URL','https://external.example:8443?user=custom&password=encoded%26secret')
        return self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,*args,ok=ok)
    def check_single_root(self, custom=False):
        for key in ['TALLY_INSTALL_DIR','TALLY_CONFIG_DIR','TALLY_DATA_DIR','TALLY_RUNTIME_DIR']:
            self.env.pop(key,None)
        root=self.root/'custom tally home' if custom else self.home/'.godel-tally'
        if custom:
            self.env['TALLY_HOME']=str(root)
            legacy=self.home/'.config/godel-tally';legacy.mkdir(parents=True)
            (legacy/'tally.env').write_text('not a configuration: must not be read\n')
        self.install('--no-service')
        settings=dict(line.split('=',1) for line in (root/'config/tally.env').read_text().splitlines())
        self.assertEqual(settings['TALLY_HOME'],str(root))
        for key in ['TALLY_INSTALL_DIR','TALLY_CONFIG_DIR','TALLY_DATA_DIR','TALLY_RUNTIME_DIR',
                    'TALLY_TLS_DIR','TALLY_MAINTENANCE_DIR','TALLY_UPGRADE_STATE_DIR','TALLY_PG_BIN','TALLY_CLICKHOUSE_BIN']:
            self.assertTrue(Path(settings[key]).is_relative_to(root),(key,settings[key]))
        self.assertTrue((root/'app/tallyd').is_file())
        self.assertTrue((root/'app/scripts/runtime-common.sh').is_file())
        self.assertTrue((root/'data/postgres/PG_VERSION').is_file())
        self.assertTrue((root/'data/clickhouse').is_dir())
        self.assertFalse((self.home/'.local/share/godel-tally').exists())
        self.run_script(ROOT/'uninstall.sh')
        self.assertFalse((root/'app/tallyd').exists())
        self.assertTrue((root/'data/postgres/PG_VERSION').exists())
    def test_fresh_install_uses_one_home_directory(self):
        self.check_single_root()
    def test_custom_home_is_not_overridden_by_legacy_settings(self):
        self.check_single_root(custom=True)

    def test_native_downloads_overlap_and_do_not_use_package_managers(self):
        self.env.update(TEST_OS='Darwin',TEST_PARALLEL='1')
        self.install('--no-start')
        self.assertEqual(len(list(self.root.glob('started-*'))),2)
        self.assertFalse(any(c[0] in ['brew','sudo','apt-get','yum','dnf'] for c in self.commands()))
        self.assertFalse((Path(self.env['TALLY_CONFIG_DIR'])/'installed-packages').exists())
    def test_checksum_failure_explains_recovery_and_preserves_retry_state(self):
        self.env.update(CORRUPT_DATABASE='postgres')
        result=self.install('--no-start',ok=False)
        self.assertIn('Where: Step 5 of 7: Prepare your private databases',result.stderr)
        self.assertIn('postgres download checksum mismatch',result.stderr)
        self.assertIn('Saved settings:',result.stderr)
        self.assertNotIn('Tally is ready!',result.stdout)
        self.assertFalse(any(c[0]=='initdb' for c in self.commands()))
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env'; original=config.read_bytes()
        self.env.pop('CORRUPT_DATABASE')
        self.install('--no-start')
        self.assertTrue(config.read_bytes().startswith(original))
        self.assertFalse(list(Path(self.env['TALLY_RUNTIME_DIR']).glob('.download-*')))
        self.assertFalse(list(Path(self.env['TALLY_RUNTIME_DIR']).glob('.partial-*')))
    def test_pinned_database_manifest_lists_official_sources(self):
        rows=[line.split('|') for line in (ROOT/'scripts/database-assets.tsv').read_text().splitlines() if line and not line.startswith('#')]
        self.assertEqual(len(rows),8)
        for db,platform,version,kind,archive_root,digest,size,urls in rows:
            sources=urls.split(' ')
            self.assertTrue(size.isdigit() and int(size)>0,(db,platform))
            if db=='clickhouse' and platform.startswith('linux-'):
                self.assertEqual([s.split('/')[2] for s in sources],['packages.clickhouse.com','github.com'])
                self.assertEqual(sources[0].rsplit('/',1)[1],sources[1].rsplit('/',1)[1])
            else:
                self.assertEqual([s.split('/')[2] for s in sources],['github.com'],(db,platform))
    def test_database_download_falls_back_to_the_next_official_source(self):
        manifest=self.bundle/'scripts/database-assets.tsv'
        rows=[]
        for line in manifest.read_text().splitlines():
            row=line.split('|')
            if row[0]=='clickhouse': row[7]='https://packages.clickhouse.com/tgz/stable/'+row[7].rsplit('/',1)[1]+' '+row[7]
            rows.append('|'.join(row))
        manifest.write_text('\n'.join(rows)+'\n')
        self.env['FAIL_DOWNLOAD_HOST']='packages.clickhouse.com'
        result=self.install('--no-start')
        urls=[next(a for a in c if a.startswith('https://')) for c in self.commands() if c[0]=='curl' and any('/fixture-clickhouse' in a for a in c)]
        self.assertEqual([u.split('/')[2] for u in urls],['packages.clickhouse.com','github.com'])
        self.assertIn('Trying the next official clickhouse download source',result.stdout)
        self.assertIn('Private clickhouse 26.9.23.15 downloaded and verified',result.stdout)
    def test_database_download_refuses_unlisted_hosts_before_downloading(self):
        manifest=self.bundle/'scripts/database-assets.tsv'
        manifest.write_text(manifest.read_text().replace('https://github.com/ClickHouse/ClickHouse/','https://mirror.example.test/ClickHouse/'))
        result=self.install('--no-start',ok=False)
        self.assertIn('Unexpected database download host',result.stderr)
        self.assertFalse(any(c[0]=='curl' and any('/fixture-' in a for a in c) for c in self.commands()))
    def test_interrupted_database_download_resumes_in_place(self):
        self.env.update(INTERRUPT_DATABASE='postgres',INTERRUPT_COUNT='2')
        result=self.install('--no-start')
        self.assertIn('The postgres download was interrupted. Resuming',result.stdout)
        downloads=[c for c in self.commands() if c[0]=='curl' and any('/fixture-postgres' in a for a in c)]
        self.assertEqual(len(downloads),3)
        self.assertTrue(all(c[c.index('-C')+1]=='-' for c in downloads))
        self.assertEqual(len((self.root/'resumed').read_text().splitlines()),2)
        self.assertFalse(list(Path(self.env['TALLY_RUNTIME_DIR']).glob('.partial-*')))
    def test_failed_database_download_resumes_on_rerun(self):
        self.env['INTERRUPT_DATABASE']='postgres'
        result=self.install('--no-start',ok=False)
        self.assertIn('postgres could not be downloaded',result.stderr)
        self.assertIn('resumes where this download stopped',result.stderr)
        self.assertFalse(any(c[0]=='initdb' for c in self.commands()))
        partial=next(Path(self.env['TALLY_RUNTIME_DIR']).glob('.partial-postgres-*'))
        kept=partial.stat().st_size
        self.assertGreater(kept,0)
        self.env.pop('INTERRUPT_DATABASE')
        result=self.install('--no-start')
        self.assertIn('Resuming private postgres 18.6.1',result.stdout)
        self.assertEqual((self.root/'resumed').read_text().splitlines()[-1].split(' ')[1],str(kept))
        self.assertFalse(partial.exists())
    def test_slow_database_download_reports_received_bytes(self):
        self.env['SLOW_DATABASE']='postgres'
        result=self.install('--no-start')
        self.assertRegex(result.stdout,r'Still preparing private databases \(\d+s elapsed\): postgres \d+\.\d of \d+\.\d MB, \d+\.\d MB/s\.')
    def test_cancelled_database_download_stops_transfers_and_keeps_partial(self):
        self.env['SLOW_DATABASE']='postgres'
        process=subprocess.Popen(['bash',str(self.bundle/'scripts/download-databases.sh')],env=self.env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        deadline=time.monotonic()+10
        while not (self.root/'slow-curl').exists():
            self.assertLess(time.monotonic(),deadline,'download did not start'); time.sleep(.05)
        process.send_signal(signal.SIGINT)
        process.communicate(timeout=10)
        self.assertEqual(process.returncode,130)
        # Background jobs ignore SIGINT; a surviving transfer would race the next run's resume.
        with self.assertRaises(ProcessLookupError): os.kill(int((self.root/'slow-curl').read_text()),0)
        runtime=Path(self.env['TALLY_RUNTIME_DIR'])
        self.assertGreater(next(runtime.glob('.partial-postgres-*')).stat().st_size,0)
        self.assertFalse((runtime/'.download-lock').exists())
    def release_version(self):
        return re.search(r'\[workspace\.package\]\s+version = "([^"]+)"',(ROOT/'Cargo.toml').read_text()).group(1)
    def test_container_deployments_pull_the_release_image(self):
        version=self.release_version()
        compose=(ROOT/'docker-compose.yml').read_text()
        self.assertIn('image: ${TALLY_IMAGE_PREFIX:-quay.io/godellabs-ai}/godel-tally:${TALLY_IMAGE_TAG:-'+version+'}',compose)
        self.assertNotIn('build:',compose)
        self.assertIn('- tally-data:/data',compose)
        build=(ROOT/'docker-compose.build.yml').read_text()
        self.assertIn('dockerfile: deploy/compose/Dockerfile.tallyd',build)
        self.assertIn('- ./.local/docker-state:/data',build)
        apple=(ROOT/'deploy/apple/tally-container.sh').read_text()
        self.assertIn('$(setting TALLY_IMAGE_PREFIX quay.io/godellabs-ai)/godel-tally:$(setting TALLY_IMAGE_TAG '+version+')',apple)
    def test_apple_container_deployment_uses_env_file_and_database_addresses(self):
        self.env.update(TEST_OS='Darwin',TEST_ARCH='arm64')
        work=self.root/'apple deployment';work.mkdir()
        (work/'.env').write_text('TALLY_URL=https://tally.example.test:9443\nTALLY_PUBLISH_BIND=0.0.0.0:9443\n'
            'TALLY_SECRET_KEY=s3cret-key\nTALLY_POSTGRES_PASSWORD=pg-secret\nTALLY_CLICKHOUSE_PASSWORD=ch-secret\n'
            '# comments are ignored\nTALLY_HTTP_BIND=127.0.0.1:1\nEMAIL_FROM=tally@example.test\n')
        script=ROOT/'deploy/apple/tally-container.sh'
        result=subprocess.run(['bash',str(script),'up'],cwd=work,env=self.env,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('Tally is ready at https://tally.example.test:9443',result.stdout)
        commands=[c for c in self.commands() if c[0]=='container']
        runs={c[c.index('--name')+1]:c for c in commands if c[1]=='run'}
        self.assertEqual(sorted(runs),['godel-tally-stack-clickhouse','godel-tally-stack-postgres','godel-tally-stack-tallyd'])
        app=runs['godel-tally-stack-tallyd']
        self.assertEqual(app[-1],'quay.io/godellabs-ai/godel-tally:'+self.release_version())
        for argument in ['0.0.0.0:9443:2357','godel-tally-stack-data:/data',f'{work.resolve()}/tls:/tls']: self.assertIn(argument,app)
        self.assertTrue((work/'tls').is_dir())
        self.assertFalse([c for c in commands if any(s in ' '.join(c) for s in ['s3cret-key','pg-secret','ch-secret'])])
        env=(self.root/'container-env/godel-tally-stack-tallyd').read_text().splitlines()
        for line in ['TALLY_POSTGRES_URL=postgres://tally:pg-secret@192.168.64.2:5432/tally','TALLY_CLICKHOUSE_URL=http://192.168.64.3:8123?user=tally',
                     'TALLY_SECRET_KEY=s3cret-key','EMAIL_FROM=tally@example.test','TALLY_UPGRADE_WEB_ORIGIN=https://tally.example.test:9443']:
            self.assertIn(line,env)
        self.assertEqual([l for l in env if l.startswith('TALLY_HTTP_BIND=')],['TALLY_HTTP_BIND=0.0.0.0:2357'])
        self.assertIn('POSTGRES_PASSWORD=pg-secret',(self.root/'container-env/godel-tally-stack-postgres').read_text())
        self.assertIn('CLICKHOUSE_PASSWORD=ch-secret',(self.root/'container-env/godel-tally-stack-clickhouse').read_text())
        # A rerun keeps the databases and their volumes, and recreates only the application.
        (self.root/'commands').unlink()
        result=subprocess.run(['bash',str(script),'up'],cwd=work,env=self.env,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        commands=[c for c in self.commands() if c[0]=='container']
        self.assertEqual([c[c.index('--name')+1] for c in commands if c[1]=='run'],['godel-tally-stack-tallyd'])
        self.assertIn(['container','delete','godel-tally-stack-tallyd'],commands)
        self.assertFalse(any(c[1:3]==['volume','create'] for c in commands))
    def test_apple_container_deployment_requires_secrets_in_env_file(self):
        self.env.update(TEST_OS='Darwin',TEST_ARCH='arm64')
        work=self.root/'apple';work.mkdir()
        (work/'.env').write_text('TALLY_SECRET_KEY=s3cret-key\n')
        result=subprocess.run(['bash',str(ROOT/'deploy/apple/tally-container.sh'),'up'],cwd=work,env=self.env,text=True,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Set TALLY_POSTGRES_PASSWORD in .env',result.stderr)
        self.assertFalse(any(c[0]=='container' and c[1]=='run' for c in self.commands()))
    def test_old_openssl_fails_before_install(self):
        self.env.update(TEST_OLD_OPENSSL='1')
        result=self.install(ok=False)
        self.assertIn('OpenSSL cannot create',result.stderr)
        self.assertIn('What to do next:',result.stderr)
        self.assertFalse(Path(self.env['TALLY_INSTALL_DIR']).exists())
        self.assertFalse(any(c[0]=='curl' for c in self.commands()))
    def test_supplied_certificates_do_not_require_openssl_generation_support(self):
        self.env.update(TEST_OLD_OPENSSL='1',TALLY_TLS_CERT_FILE=str(self.root/'provided.crt'),
                        TALLY_TLS_KEY_FILE=str(self.root/'provided.key'))
        Path(self.env['TALLY_TLS_CERT_FILE']).write_text('fixture cert')
        Path(self.env['TALLY_TLS_KEY_FILE']).write_text('fixture key')
        self.install('--db','existing','--no-start')
        self.assertFalse(any(c[:2]==['openssl','req'] and '-x509' in c for c in self.commands()))
    def test_download_failure_has_actionable_summary(self):
        self.env['FAIL_COMMAND']='curl'
        result=self.run_script(ROOT/'install.sh',ok=False)
        self.assertIn('Where: Step 2 of 7: Download Tally',result.stderr)
        self.assertIn('exit code 23',result.stderr)
        self.assertIn('internet connection',result.stderr)
        self.assertNotIn('Tally is ready!',result.stdout)
    def test_no_start_and_no_service_do_not_claim_readiness(self):
        for option in ['--no-start','--no-service']:
            result=self.install('--db','existing',option)
            self.assertIn('Startup was skipped',result.stdout)
            self.assertIn('After it starts, open:',result.stdout)
            self.assertNotIn('Tally is ready!',result.stdout)
            self.assertNotIn('\x1b[',result.stdout+result.stderr)
        self.assertFalse(any(c[0]=='curl' and any('/health/ready' in a for a in c) for c in self.commands()))
    def test_ready_and_failed_health_checks_have_distinct_outcomes(self):
        result=self.install('--db','existing')
        self.assertIn('Tally is ready!',result.stdout)
        self.env.update(FAIL_HTTP_READY='1',TEST_OS='Darwin')
        result=self.install('--db','existing',ok=False)
        self.assertNotIn('Tally is ready!',result.stdout)
        self.assertIn('browser console did not become ready',result.stderr)
        self.assertIn('Where: Step 7 of 7',result.stderr)
        self.assertIn('tail -n 50',result.stderr)
        self.assertIn('/server.log',result.stderr)
        self.assertNotIn('journalctl',result.stderr)
    def test_dry_run_does_not_download_or_install(self):
        result=self.run_script(ROOT/'install.sh','--db','docker','--postgres','existing','--no-service','--dry-run')
        self.assertIn('PostgreSQL (settings): existing',result.stdout)
        self.assertIn('ClickHouse (activity): docker',result.stdout)
        self.assertIn('Startup: Manual startup',result.stdout)
        self.assertIn('Nothing was downloaded',result.stdout)
        self.assertTrue(all(c[0]=='uname' for c in self.commands()))
        self.assertFalse(Path(self.env['TALLY_INSTALL_DIR']).exists())
    def test_terminal_colors_and_no_color(self):
        import pty
        master,slave=pty.openpty()
        try:
            for disabled in [False,True]:
                env=dict(self.env,TERM='xterm-256color')
                env.pop('NO_COLOR',None)
                if disabled: env['NO_COLOR']='1'
                result=subprocess.run(['bash',str(ROOT/'install.sh'),'--dry-run'],env=env,
                                      stdout=slave,stderr=slave,timeout=10)
                self.assertEqual(result.returncode,0)
                output=os.read(master,16384)
                self.assertEqual(b'\x1b[' in output,not disabled)
                self.assertIn(b'Preview only',output)
        finally:
            os.close(master);os.close(slave)
    def test_bootstrap_runs_from_stdin_or_bash_c(self):
        source=(ROOT/'install.sh').read_text()
        for command,input_text in [(['bash','-s','--','--dry-run'],source),
                                   (['bash','-c',source,'bash','--dry-run'],None)]:
            result=subprocess.run(command,input=input_text,env=self.env,text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Preview only',result.stdout)
    def test_existing_databases_and_reinstall_preserve_credentials(self):
        self.install('--db','existing','--no-service')
        config = Path(self.env['TALLY_CONFIG_DIR'])/'tally.env'
        first = config.read_text()
        self.assertIn('TALLY_CLICKHOUSE_PASSWORD=\n',first)
        self.assertIn(self.env['TALLY_CLICKHOUSE_URL'],first)
        self.install('--no-service')
        self.assertEqual(first,config.read_text())
        self.assertEqual(config.stat().st_mode & 0o777,0o600)
        self.assertFalse(any(c[0] in ['sudo','docker','container','brew'] for c in self.commands()))
        self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,'--db','docker',ok=False)
    def test_systemd_and_launchd_registration(self):
        for platform in ['Linux','Darwin']:
            self.env['TEST_OS']=platform
            self.install('--db','existing','--no-start')
        unit=(self.home/'.config/systemd/user/tally-server.service').read_text()
        self.assertIn('ExecStart=/bin/bash "',unit)
        self.assertNotIn('User=root',unit)
        with (self.home/'Library/LaunchAgents/ai.godel.tally.server.plist').open('rb') as f: agent=plistlib.load(f)
        self.assertEqual(agent['ProgramArguments'],['/bin/bash',str(Path(self.env['TALLY_INSTALL_DIR'])/'tally.sh')])
        self.assertTrue(agent['KeepAlive'])
        self.assertFalse(any(c[:2] == ['systemctl','enable'] for c in self.commands()))
    def test_native_private_instances_are_idempotent(self):
        self.install('--no-start')
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env';saved=config.read_bytes()
        self.env['FAIL_COMMAND']='curl'  # A cached reinstall must work offline.
        self.install('--no-start')
        commands=self.commands()
        self.assertEqual(sum(c[0]=='initdb' for c in commands),1)
        self.assertEqual(sum(c[0]=='curl' for c in commands),2)
        self.assertFalse(any(c[0] in ['sudo','brew','pg_isready','createdb'] for c in commands))
        self.assertFalse(any(c[0]=='postgres' and '--version' not in c for c in commands))
        self.assertTrue((Path(self.env['TALLY_CONFIG_DIR'])/'clickhouse.xml').is_file())
        self.assertFalse((self.home/'.config/systemd/user/tally-postgres.service').exists())
        self.assertFalse((self.home/'.config/systemd/user/tally-clickhouse.service').exists())
        self.assertEqual(config.read_bytes(),saved)
        self.assertIn('supervise', (Path(self.env['TALLY_INSTALL_DIR'])/'tally.sh').read_text())
    def test_native_manual_install_needs_no_user_service_manager(self):
        self.env['FAIL_COMMAND']='systemctl'
        self.install('--no-service')
        self.assertFalse(any(c[0] in ['systemctl','launchctl'] for c in self.commands()))
        self.assertFalse((self.home/'.config/systemd/user').exists())
    def test_private_runtime_platform_requirements(self):
        for settings,message in [({'TEST_LIBC':'glibc 2.35'},'glibc 2.36+'),({'TEST_OS':'Darwin','TEST_MACOS':'14.6'},'macOS 15+')]:
            self.env.update(settings)
            result=self.install('--no-start',ok=False)
            self.assertIn(message,result.stderr)
        self.assertFalse(any(c[0]=='curl' for c in self.commands()))
    def test_older_data_is_refused_before_application_changes(self):
        pg=Path(self.env['TALLY_DATA_DIR'])/'postgres';pg.mkdir(parents=True)
        (pg/'PG_VERSION').write_text('17')
        result=self.install('--no-start',ok=False)
        self.assertIn('major-version migration',result.stderr)
        self.assertFalse(Path(self.env['TALLY_INSTALL_DIR']).exists())
    def test_postgres_version_parser_accepts_package_labels_and_rejects_unknown_banners(self):
        for banner,expected in [('postgres (PostgreSQL) 18.6 (Homebrew)','18'),
                                ('postgres (PostgreSQL) 15.10 (Ubuntu 15.10-1.pgdg24.04+1)','15'),
                                ('postgres (PostgreSQL) 17.4','17'),('postgres (PostgreSQL) 14.18','14')]:
            result=subprocess.run(['bash','-c','source "$1"; postgres_major_version "$2"','test',str(ROOT/'scripts/runtime-common.sh'),banner],text=True,capture_output=True,check=True)
            self.assertEqual(result.stdout.strip(),expected)
        self.env.update(TEST_PG_BANNER='postgres (PostgreSQL) 14.18 (Homebrew)')
        result=self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,'--no-start',ok=False)
        self.assertIn('must be version 18',result.stderr)
        self.assertFalse(any(c[0]=='initdb' for c in self.commands()))
        self.env['TEST_PG_BANNER']='unexpected banner 18.6'
        result=self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,'--no-start',ok=False)
        self.assertIn('must be version 18',result.stderr)
    def test_uninstall_retains_data_config_and_unknown_files(self):
        self.install('--db','existing','--no-start')
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env'; saved=config.read_bytes()
        data=Path(self.env['TALLY_DATA_DIR'])/'customer-data';data.write_text('keep me')
        install=Path(self.env['TALLY_INSTALL_DIR'])
        custom=install/'scripts/operator-notes';custom.write_text('keep me too')
        self.run_script(ROOT/'uninstall.sh')
        self.assertFalse((install/'tallyd').exists())
        self.assertFalse((install/'uninstall.sh').exists())
        self.assertFalse((self.home/'.config/systemd/user/tally-server.service').exists())
        self.assertEqual(config.read_bytes(),saved)
        self.assertEqual(data.read_text(),'keep me')
        self.assertEqual(custom.read_text(),'keep me too')
        self.run_script(ROOT/'uninstall.sh')
        self.assertFalse(any(c[0] in ['brew','sudo','docker','container'] for c in self.commands()))
    def test_database_cleanup_after_normal_supervised_uninstall(self):
        self.install('--no-service')
        data=Path(self.env['TALLY_DATA_DIR']);(data/'supervisor.lock').touch()
        binary=Path(self.env['TALLY_INSTALL_DIR'])/'tallyd'
        binary.write_text('#!/bin/bash\n[ "$1" = check-stopped ]\n')
        self.run_script(ROOT/'uninstall.sh')
        self.assertFalse(binary.exists())
        self.assertFalse((data/'supervisor.lock').exists())
        self.assertTrue((data/'postgres/PG_VERSION').exists())
        self.run_script(ROOT/'uninstall.sh','--remove-databases')
        self.assertFalse((data/'postgres').exists())
        self.assertFalse(Path(self.env['TALLY_RUNTIME_DIR']).exists())

    def test_uninstall_partial_install_without_registered_services(self):
        # v0.1.0 persisted configuration and copied the binary before the version check.
        self.env.update(TEST_OS='Darwin',TEST_PG_BANNER='unknown version')
        self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,ok=False)
        install=Path(self.env['TALLY_INSTALL_DIR'])
        (install/'uninstall.sh').unlink()  # Older bundles did not include an uninstaller.
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env'; saved=config.read_bytes()
        before=self.commands()
        self.run_script(ROOT/'uninstall.sh')
        self.assertFalse(install.exists())
        self.assertEqual(config.read_bytes(),saved)
        self.assertFalse(any(c[0] in ['systemctl','launchctl','docker','container','brew','sudo']
                             for c in self.commands()[len(before):]))
    def test_uninstall_refuses_unsafe_paths_and_mismatched_installation(self):
        self.install('--db','existing','--no-service')
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env'; saved=config.read_text()
        install=Path(self.env['TALLY_INSTALL_DIR'])
        self.env['TALLY_INSTALL_DIR']=str(self.root/'another-install')
        result=self.run_script(ROOT/'uninstall.sh',ok=False)
        self.assertIn('does not match',result.stderr)
        self.env['TALLY_INSTALL_DIR']=str(install)
        config.write_text(saved.replace(f'TALLY_INSTALL_DIR={install}',f'TALLY_INSTALL_DIR={self.home}'))
        result=self.run_script(ROOT/'uninstall.sh',ok=False)
        self.assertIn('unsafe installation directory',result.stderr)
        config.write_text(saved)
        scripts=install/'scripts'; scripts.rename(install/'saved-scripts')
        scripts.symlink_to(install/'saved-scripts',target_is_directory=True)
        result=self.run_script(ROOT/'uninstall.sh',ok=False)
        self.assertIn('symlinked installation',result.stderr)
        self.assertTrue((install/'tallyd').exists())
    def test_uninstall_dry_run_and_service_ownership(self):
        self.install('--db','existing','--no-start')
        install=Path(self.env['TALLY_INSTALL_DIR'])
        before=self.commands()
        result=self.run_script(ROOT/'uninstall.sh','--dry-run')
        self.assertIn('no changes made',result.stdout)
        self.assertTrue((install/'tallyd').exists())
        self.assertFalse(any(c[0] in ['systemctl','launchctl','docker','container'] for c in self.commands()[len(before):]))
        unit=self.home/'.config/systemd/user/tally-server.service'
        unit.write_text('[Service]\nExecStart=/some/other/installation/tally.sh\n')
        result=self.run_script(ROOT/'uninstall.sh',ok=False)
        self.assertIn('does not belong to this installation',result.stderr)
        self.assertTrue((install/'tallyd').exists())
    def test_uninstall_native_macos_stops_only_private_tally_services(self):
        self.env['TEST_OS']='Darwin'
        self.install('--no-start')
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env';saved=config.read_bytes()
        before=self.commands()
        self.run_script(ROOT/'uninstall.sh')
        commands=self.commands()[len(before):]
        self.assertEqual([c[2] for c in commands if c[:2]==['launchctl','bootout']],
                         ['gui/1000/ai.godel.tally.'+name for name in ['server']])
        self.assertFalse(any(c[0]=='brew' for c in commands))
        self.assertFalse(list((self.home/'Library/LaunchAgents').glob('ai.godel.tally.*.plist')))
        self.assertEqual(config.read_bytes(),saved)
        self.assertTrue((Path(self.env['TALLY_DATA_DIR'])/'postgres/PG_VERSION').exists())
    def test_uninstall_waits_for_macos_service_to_release_supervisor(self):
        # launchctl bootout returns while the supervisor still holds its lock.
        self.env['TEST_OS']='Darwin'
        self.install('--no-start')
        data=Path(self.env['TALLY_DATA_DIR']);(data/'supervisor.lock').touch()
        binary=Path(self.env['TALLY_INSTALL_DIR'])/'tallyd'
        checks=self.root/'stop-checks'
        binary.write_text(f'#!/bin/bash\necho >> "{checks}"\n[ "$(wc -l < "{checks}")" -ge 3 ]\n')
        result=self.run_script(ROOT/'uninstall.sh')
        self.assertIn('Waiting for the Tally service to finish stopping',result.stdout)
        self.assertEqual(len(checks.read_text().splitlines()),4)
        self.assertFalse(binary.exists())
        self.assertFalse((data/'supervisor.lock').exists())
    def test_uninstall_stops_owned_containers_and_keeps_volumes(self):
        for mode,engine in [('docker','docker'),('apple','container')]:
            with self.subTest(mode=mode):
                # A separate config per mode avoids switching an existing installation's DBs.
                self.env.update(TEST_OS='Darwin',TEST_ARCH='arm64',TALLY_CONTAINER_PREFIX='test-'+mode,
                                TALLY_CONFIG_DIR=str(self.root/('config-'+mode)))
                self.install('--db',mode,'--no-start')
                foreign=self.root/'containers/unrelated';foreign.write_text('running')
                before=self.commands()
                self.run_script(ROOT/'uninstall.sh')
                self.run_script(ROOT/'uninstall.sh')
                commands=[c for c in self.commands()[len(before):] if c[0]==engine]
                self.assertEqual(sum(c[1]=='stop' for c in commands),2)
                self.assertFalse(any(c[1] in ['rm','delete','volume','prune'] for c in commands))
                self.assertEqual(foreign.read_text(),'running')
                self.assertTrue((self.root/('config-'+mode)/'tally.env').exists())
    def test_docker_and_apple_create_once_then_reuse_without_deleting_data(self):
        for engine, mode, platform, arch in [('docker','docker','Linux','x86_64'),('container','apple','Darwin','arm64')]:
            self.env.update(TALLY_DB_MODE=mode,TEST_OS=platform,TEST_ARCH=arch,TALLY_CONTAINER_PREFIX=f'test-{mode}')
            for action in ['up','up','stop','up']:
                result=self.run_script(ROOT/'scripts/data-services.sh',action)
                self.assertNotIn('unknown shorthand flag',result.stderr)
            commands=[c for c in self.commands() if c[0]==engine]
            self.assertEqual(sum(c[1]=='run' for c in commands),2)
            self.assertEqual(sum(c[1]=='start' for c in commands),2)
            self.assertFalse(any(c[1] in ['rm','delete','prune'] for c in commands))
            for c in commands:
                if c[1]=='run': self.assertIn('127.0.0.1:',c[c.index('-p')+1])
    def test_mixed_modes_and_unsupported_apple(self):
        self.env.update(TALLY_POSTGRES_MODE='existing',TALLY_CLICKHOUSE_MODE='docker')
        self.run_script(ROOT/'scripts/data-services.sh','up')
        self.assertEqual(sum(c[:2]==['docker','run'] for c in self.commands()),1)
        self.env['TALLY_CLICKHOUSE_MODE']='apple'
        self.run_script(ROOT/'scripts/data-services.sh','up',ok=False)
    def test_mixed_reset_fails_before_touching_any_container(self):
        self.env.update(TALLY_POSTGRES_MODE='docker',TALLY_CLICKHOUSE_MODE='existing')
        self.run_script(ROOT/'scripts/data-services.sh','reset',ok=False)
        self.assertFalse((self.root/'commands').exists())
    def test_refuses_unowned_container_and_readiness_failure(self):
        (self.root/'containers').mkdir();(self.root/'containers/godel-tally-dev-postgres').touch()
        self.run_script(ROOT/'scripts/data-services.sh','up',ok=False)
        (self.root/'containers/godel-tally-dev-postgres').unlink()
        self.env['FAIL_READY']='1'
        self.run_script(ROOT/'scripts/data-services.sh','up',ok=False)
    def test_download_platforms_do_not_install_packages(self):
        for platform,arch in [('Darwin','x86_64'),('Darwin','arm64'),('Linux','x86_64'),('Linux','aarch64')]:
            target=self.root/(platform+arch)
            self.env.update(TEST_OS=platform,TEST_ARCH=arch,TALLY_DATA_DIR=str(target/'data'),
                TALLY_CONFIG_DIR=str(target/'config'),TALLY_INSTALL_DIR=str(self.root/'install with spaces'),TALLY_RUNTIME_DIR=str(target/'runtime'))
            self.install('--no-start')
        self.assertFalse(any(c[0] in ['brew','sudo','apt-get','dnf','yum'] for c in self.commands()))
    def test_legacy_database_units_are_retired_after_preparation(self):
        self.install('--no-start')
        units=self.home/'.config/systemd/user'
        for db in ['postgres','clickhouse']:
            (units/f'tally-{db}.service').write_text(f'[Service]\nExecStart=/bin/bash "{self.env["TALLY_INSTALL_DIR"]}/{db}.sh"\n')
        self.install('--no-start')
        self.assertFalse((units/'tally-postgres.service').exists())
        self.assertFalse((units/'tally-clickhouse.service').exists())
        commands=self.commands()
        self.assertIn(['systemctl','--user','stop','tally-server.service'],commands)
        for db in ['postgres','clickhouse']:
            self.assertIn(['systemctl','--user','disable','--now',f'tally-{db}.service'],commands)
    def test_macos_raw_clickhouse_asset(self):
        self.env.update(TEST_OS='Darwin',TEST_ARCH='arm64')
        asset=self.root/'assets/fixture-clickhouse-darwin-arm64.tar.gz'
        asset.write_text(STUB)
        manifest=self.bundle/'scripts/database-assets.tsv'
        rows=[]
        for line in manifest.read_text().splitlines():
            row=line.split('|')
            if row[:2]==['clickhouse','darwin-arm64']:
                row[3]='binary';row[4]='-';row[5]=hashlib.sha256(asset.read_bytes()).hexdigest();row[6]=str(asset.stat().st_size)
            rows.append('|'.join(row))
        manifest.write_text('\n'.join(rows)+'\n')
        self.install('--no-service')
        binary=Path(self.env['TALLY_RUNTIME_DIR'])/'clickhouse-26.9.23.15-darwin-arm64/bin/clickhouse'
        self.assertEqual(binary.read_text(),STUB)
        self.assertTrue(os.access(binary,os.X_OK))
    def test_native_rejects_external_url_override(self):
        self.env['TALLY_POSTGRES_URL']='postgres://external/tally'
        result=self.install('--no-start',ok=False)
        self.assertIn('choose --postgres existing',result.stderr)
        self.assertFalse(any(c[0]=='curl' for c in self.commands()))
    def test_live_reload_uses_one_rust_watcher_and_no_router(self):
        shutil.copy(ROOT/'dev-run.sh', self.bundle/'dev-run.sh')
        (self.bundle/'apps/web/node_modules').mkdir(parents=True)
        cargo=self.bin/'cargo'
        cargo.write_text('''#!/bin/bash
printf 'cargo %s\\n' "$*" >> "$FIXTURE/dev-events"
if [ "$1" = watch ] && [ "${2:-}" != --version ]; then
    trap 'exit 0' TERM INT
    while true; do /bin/sleep 1; done
fi
''');cargo.chmod(0o755)
        npm=self.bin/'npm'
        npm.write_text('''#!/bin/bash
printf 'npm %s\\n' "$*" >> "$FIXTURE/dev-events"
trap 'exit 0' TERM INT
while true; do /bin/sleep 1; done
''');npm.chmod(0o755)
        self.env.update(TALLY_DB_MODE='existing', TALLY_KEEP_DB='1', TALLY_POSTGRES_URL='postgres://external/tally', TALLY_CLICKHOUSE_URL='http://external:8123')
        with (self.root/'dev.log').open('w') as output:
            process=subprocess.Popen(['bash',str(self.bundle/'dev-run.sh')],cwd=self.bundle,
                env=self.env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and process.poll() is None:
                    if 'Gödel Tally dev stack is up' in (self.root/'dev.log').read_text() and 'npm ' in (self.root/'dev-events').read_text(): break
                    time.sleep(.05)
                self.assertIsNone(process.poll(),(self.root/'dev.log').read_text())
                process.terminate();process.wait(timeout=10)
            finally:
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait()
        events=(self.root/'dev-events').read_text()
        self.assertIn('cargo build -p tallyd --bin tallyd',events)
        self.assertIn('-x run -p tallyd',events)
        self.assertIn('--experimental-https',events)
        self.assertNotIn('run -p tally-upgrade',events)
        self.assertNotIn('tally-collector -- worker',events)
        self.assertNotIn('docker compose',events)
    def test_download_verifies_checksum_before_executing_installer(self):
        release=self.root/'release';release.mkdir()
        installer=self.root/'bootstrap-installer.sh'
        installer.write_text('#!/bin/bash\ntouch "$FIXTURE/installed"\n')
        archive=release/'tallyd-linux-amd64.tar.gz'
        with tarfile.open(archive,'w:gz') as package:
            package.add(installer,arcname='scripts/install-runtime.sh')
        checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
        sums=release/'SHA256SUMS';sums.write_text(f'{checksum}  {archive.name}\n')
        self.env['BOOTSTRAP_SOURCE']=str(release)
        result=self.run_script(ROOT/'install.sh','--db','existing')
        stages=['[1/7] Check your computer','[2/7] Download Tally','Finding the latest release',
                'Downloading v0.1.0','[3/7] Verify the download','Download verified and unpacked']
        offsets=[result.stdout.index(stage) for stage in stages]
        self.assertEqual(offsets,sorted(offsets))
        self.assertTrue((self.root/'installed').exists())
        urls=[next(a for a in c if a.startswith('https://')) for c in self.commands() if c[0]=='curl']
        self.assertEqual(urls,[
            'https://github.com/godellabs-ai/godel-tally/releases/latest',
            'https://github.com/godellabs-ai/godel-tally/releases/download/v0.1.0/'+archive.name,
            'https://github.com/godellabs-ai/godel-tally/releases/download/v0.1.0/SHA256SUMS'])
        (self.root/'installed').unlink()
        sums.write_text(f'{"0"*64}  {archive.name}\n')
        self.run_script(ROOT/'install.sh','--db','existing',ok=False)
        self.assertFalse((self.root/'installed').exists())
    def test_pinned_download_selects_all_four_platforms(self):
        release=self.root/'release';release.mkdir()
        installer=self.root/'bootstrap-installer.sh'
        installer.write_text('#!/bin/bash\nprintf "%s\\n" "$*" > "$FIXTURE/installed"\n')
        self.env.update(BOOTSTRAP_SOURCE=str(release),TALLY_VERSION='v0.1.0')
        for os_name,arch,platform in [('Linux','x86_64','linux-amd64'),('Linux','aarch64','linux-arm64'),
                                      ('Darwin','x86_64','darwin-amd64'),('Darwin','arm64','darwin-arm64')]:
            with self.subTest(platform=platform):
                archive=release/f'tallyd-{platform}.tar.gz'
                with tarfile.open(archive,'w:gz') as package:
                    package.add(installer,arcname='scripts/install-runtime.sh')
                checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
                (release/'SHA256SUMS').write_text(f'{checksum}  {archive.name}\n')
                self.env.update(TEST_OS=os_name,TEST_ARCH=arch)
                self.run_script(ROOT/'install.sh','--db','docker','--no-start','--port','9443')
                self.assertTrue((self.root/'installed').read_text().endswith('--db docker --no-start --port 9443\n'))
        urls=[next(a for a in c if a.startswith('https://')) for c in self.commands() if c[0]=='curl']
        self.assertEqual(len(urls),8)
        self.assertTrue(all('/releases/download/v0.1.0/' in url for url in urls))
    def test_unresolved_latest_release_never_executes_installer(self):
        self.env.update(BOOTSTRAP_SOURCE=str(self.root),TEST_RELEASE_URL='https://github.com/login')
        result=self.run_script(ROOT/'install.sh',ok=False)
        self.assertIn('Could not resolve the latest Tally release',result.stderr)
        self.assertFalse((self.root/'installed').exists())
    def test_release_archive_checks_architecture_and_includes_uninstaller(self):
        import struct
        binary=self.root/'tallyd'
        binary.write_bytes(b'\x7fELF\x02\x01'+b'\0'*12+struct.pack('<H',183))
        if os.uname().sysname == 'Darwin':
            subprocess.run(['/usr/bin/xattr', '-w', 'com.apple.metadata:tally-test',
                            'fixture', str(binary)], check=True)
        output=self.root/'release'
        self.env.update(TEST_OS='Darwin',TEST_ARCH='arm64',TALLY_RELEASE_BINARY=str(binary),
                        TALLY_RELEASE_OUTPUT_DIR=str(output),TALLY_RELEASE_PLATFORM='linux-amd64')
        result=self.run_script(ROOT/'scripts/package-release.sh',ok=False)
        self.assertIn('architecture does not match',result.stderr)
        self.assertFalse(output.exists())
        self.env['TALLY_RELEASE_PLATFORM']='linux-arm64'
        self.run_script(ROOT/'scripts/package-release.sh')
        archive=output/'tallyd-linux-arm64.tar.gz'
        with tarfile.open(archive) as package:
            self.assertEqual(package.extractfile('tallyd').read(),binary.read_bytes())
            self.assertEqual(package.extractfile('uninstall.sh').read(),(ROOT/'uninstall.sh').read_bytes())
            self.assertEqual(package.extractfile('install.sh').read(),(ROOT/'install.sh').read_bytes())
            self.assertIn('scripts/install-runtime.sh',package.getnames())
            self.assertIn('scripts/database-assets.tsv',package.getnames())
            self.assertIn('scripts/download-databases.sh',package.getnames())
            self.assertFalse(any(name.endswith('.env') for name in package.getnames()))
            self.assertFalse(any(part.startswith('._') for name in package.getnames()
                                 for part in Path(name).parts))
        self.assertEqual((output/(archive.name+'.sha256')).read_text().split()[0],
                         hashlib.sha256(archive.read_bytes()).hexdigest())
    def test_port_updates_saved_origin_binding_and_preserves_secrets(self):
        self.env.update(TALLY_URL='https://tally.example.test:8443',TALLY_HTTP_BIND='0.0.0.0:8443')
        self.install('--db','existing','--no-start','--port','9443')
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env'
        first=config.read_text()
        self.assertIn('TALLY_URL=https://tally.example.test:9443\n',first)
        self.assertIn('TALLY_HTTP_BIND=0.0.0.0:9443\n',first)
        self.assertIn('TALLY_UPGRADE_WEB_ORIGIN=https://tally.example.test:9443\n',first)
        self.env.pop('TALLY_URL');self.env.pop('TALLY_HTTP_BIND')
        self.install('--no-start')
        self.assertEqual(first,config.read_text())
        self.install('--port','10443','--no-start')
        self.assertEqual(first.replace(':9443',':10443'),config.read_text())
        self.assertEqual(config.stat().st_mode & 0o777,0o600)
    def test_invalid_ports_fail_before_download_or_install(self):
        for script,args in [(ROOT/'install.sh',[]),(self.bundle/'scripts/install-runtime.sh',[self.bundle])]:
            for value in ['', '443', '65536', '123456789123456789', '-1234', '9443;false', '08443']:
                result=self.run_script(script,*args,'--port',value,ok=False)
                self.assertIn('--port must be between',result.stderr)
        self.assertFalse(Path(self.env['TALLY_INSTALL_DIR']).exists())
        self.assertFalse(any(c[0]=='curl' for c in self.commands()))
        result=self.run_script(ROOT/'install.sh','--port','9443','--dry-run')
        self.assertIn('HTTPS port: 9443',result.stdout)
    def test_remove_native_databases_only_removes_new_packages_and_private_data(self):
        self.env.update(TEST_OS='Darwin',TEST_PACKAGES='1')
        packages=self.root/'packages';packages.mkdir();(packages/'clickhouse').touch()
        self.install('--no-start')
        config=Path(self.env['TALLY_CONFIG_DIR']);data=Path(self.env['TALLY_DATA_DIR'])
        receipt=config/'installed-packages'
        receipt.write_text('brew-formula|postgres|postgresql@18\n')  # A retained legacy receipt.
        (packages/'postgresql@18').touch()
        self.install('--no-start')
        self.assertEqual(len(receipt.read_text().splitlines()),1)
        (data/'backup.sql').write_text('keep')
        before=self.commands()
        self.run_script(ROOT/'uninstall.sh','--remove-databases','--dry-run')
        self.assertTrue((data/'postgres/PG_VERSION').exists())
        self.assertFalse(any('uninstall' in c or c[0] in ['launchctl','sudo'] for c in self.commands()[len(before):]))
        self.run_script(ROOT/'uninstall.sh','--remove-databases')
        self.assertFalse((data/'postgres').exists());self.assertFalse((data/'clickhouse').exists())
        self.assertFalse((packages/'postgresql@18').exists());self.assertTrue((packages/'clickhouse').exists())
        self.assertFalse(receipt.exists())
        self.assertTrue((data/'backup.sql').exists());self.assertTrue((data/'tls/tally.key').exists())
        self.assertTrue((config/'tally.env').exists())
        self.run_script(ROOT/'uninstall.sh','--remove-databases')
    def test_runtime_cleanup_refuses_another_installation(self):
        self.install('--no-start')
        marker=Path(self.env['TALLY_RUNTIME_DIR'])/'.tally-runtime'
        marker.write_text('/another/config\n')
        before=self.commands()
        result=self.run_script(ROOT/'uninstall.sh','--remove-databases',ok=False)
        self.assertIn('belongs to another installation',result.stderr)
        self.assertFalse(any(c[0] in ['systemctl','launchctl'] for c in self.commands()[len(before):]))
    def test_legacy_native_cleanup_preserves_packages_without_receipts(self):
        self.env['TEST_OS']='Darwin'
        self.install('--no-start')
        data=Path(self.env['TALLY_DATA_DIR'])
        before=self.commands()
        result=self.run_script(ROOT/'uninstall.sh','--remove-databases')
        self.assertIn('no package ownership receipt',result.stdout)
        self.assertFalse((data/'postgres').exists());self.assertFalse((data/'clickhouse').exists())
        self.assertFalse(any(c[0] in ['brew','sudo'] for c in self.commands()[len(before):]))
    def test_remove_deb_and_rpm_packages_without_cascading_removal(self):
        for manager in ['apt','yum']:
            self.env.update(TEST_PACKAGES='1',TALLY_CONFIG_DIR=str(self.root/manager/'config'),
                TALLY_INSTALL_DIR=str(self.root/manager/'install'),TALLY_DATA_DIR=str(self.root/manager/'data'),TALLY_RUNTIME_DIR=str(self.root/manager/'runtime'))
            if manager=='yum':
                (self.bin/'apt-get').unlink();(self.bin/'dnf').unlink()
                (self.root/'os-release').write_text('ID=rocky\nVERSION_ID=9.0\n')
            self.install('--no-start')
            packages=['postgresql-18','postgresql-client-18'] if manager=='apt' else ['postgresql18-server','postgresql18']
            state=self.root/'packages';state.mkdir(exist_ok=True)
            for package in packages: (state/package).touch()
            (Path(self.env['TALLY_CONFIG_DIR'])/'installed-packages').write_text(''.join(f'{manager}|postgres|{package}\n' for package in packages))
            self.run_script(ROOT/'uninstall.sh','--remove-databases')
        commands=self.commands()
        self.assertIn(['sudo','dpkg','--remove','postgresql-18','postgresql-client-18'],commands)
        self.assertIn(['sudo','rpm','-e','postgresql18-server','postgresql18'],commands)
        self.assertFalse(any('autoremove' in c or '--force' in c for c in commands))
    def test_remove_containers_and_only_new_volumes_for_both_engines(self):
        for mode,engine in [('docker','docker'),('apple','container')]:
            self.env.update(TEST_OS='Darwin',TEST_ARCH='arm64',TALLY_CONTAINER_PREFIX='test-'+mode,
                            TALLY_CONFIG_DIR=str(self.root/('config-'+mode)))
            volumes=self.root/'volumes';volumes.mkdir(exist_ok=True)
            existing=volumes/('test-'+mode+'-clickhouse');existing.touch()
            self.install('--db',mode,'--no-start')
            self.run_script(ROOT/'uninstall.sh')  # Cleanup also works after a normal uninstall.
            self.run_script(ROOT/'uninstall.sh','--remove-databases')
            self.assertFalse((self.root/'containers'/('test-'+mode+'-postgres')).exists())
            self.assertFalse((volumes/('test-'+mode+'-postgres')).exists())
            self.assertTrue(existing.exists())
            self.run_script(ROOT/'uninstall.sh','--remove-databases')
    def test_cleanup_refuses_unsafe_data_paths_and_receipts_before_stopping(self):
        self.env['TEST_OS']='Darwin'
        self.install('--no-start')
        config=Path(self.env['TALLY_CONFIG_DIR'])/'tally.env';saved=config.read_text()
        data=Path(self.env['TALLY_DATA_DIR']);original=str(data)
        for unsafe in [str(self.home), '/', str(self.root/'alias/data')]:
            if 'alias' in unsafe: (self.root/'alias').symlink_to(data,target_is_directory=True)
            config.write_text(saved.replace('TALLY_DATA_DIR='+original,'TALLY_DATA_DIR='+unsafe))
            before=self.commands()
            self.run_script(ROOT/'uninstall.sh','--remove-databases',ok=False)
            self.assertFalse(any(c[0] in ['launchctl','sudo','brew'] for c in self.commands()[len(before):]))
        config.write_text(saved)
        receipt=config.parent/'installed-packages';receipt.write_text('brew-formula|postgres|unrelated-package\n')
        before=self.commands()
        self.run_script(ROOT/'uninstall.sh','--remove-databases',ok=False)
        self.assertFalse(any(c[0] in ['launchctl','sudo','brew'] for c in self.commands()[len(before):]))
        self.assertTrue((data/'postgres/PG_VERSION').exists())
    def test_cleanup_existing_databases_and_legacy_packages_are_preserved(self):
        self.install('--db','existing','--no-start')
        data=Path(self.env['TALLY_DATA_DIR']);(data/'postgres').mkdir();(data/'postgres/keep').touch()
        before=self.commands()
        result=self.run_script(ROOT/'uninstall.sh','--remove-databases')
        self.assertIn('no package ownership receipt',result.stdout)
        self.assertTrue((data/'postgres/keep').exists())
        self.assertFalse(any(c[0] in ['sudo','brew','docker','container'] for c in self.commands()[len(before):]))
    def test_configuration_is_data_not_shell_code(self):
        payload=f'$(touch {self.root}/injected)'
        config=self.root/'env';config.write_text(f'TALLY_TEST_VALUE={payload}\n')
        result=subprocess.run(['bash','-c','source "$1"; load_env "$2"; printf "%s" "$TALLY_TEST_VALUE"','test',str(ROOT/'scripts/runtime-common.sh'),str(config)],env=self.env,text=True,capture_output=True,check=True)
        self.assertEqual(result.stdout,payload)
        self.assertFalse((self.root/'injected').exists())

if __name__=='__main__': unittest.main()
