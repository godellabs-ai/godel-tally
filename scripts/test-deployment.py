#!/usr/bin/env python3
"""Deployment contracts without package installs, containers, or real user services."""
import os
from pathlib import Path
import plistlib
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
if name == 'uname': print(os.environ.get('TEST_OS','Linux') if '-s' in args else os.environ.get('TEST_ARCH','x86_64'))
elif name == 'id': print('1000' if '-u' in args else 'operator')
elif name == 'sw_vers': print('26.0')
elif name == 'curl' and os.environ.get('BOOTSTRAP_SOURCE'):
    import shutil
    source=pathlib.Path(os.environ['BOOTSTRAP_SOURCE'])
    url=next(a for a in args if a.startswith('https://'))
    if url.endswith('/releases/latest'):
        print(os.environ.get('TEST_RELEASE_URL',url.removesuffix('/latest')+'/tag/v0.1.0'),end='')
    else:
        shutil.copyfile(source/url.rsplit('/',1)[1],args[args.index('-o')+1])
elif name == 'pg_config': print(root/'bin')
elif name == 'brew' and args[0] == '--prefix': print(root/'brew')
elif name == 'initdb':
    data=pathlib.Path(args[args.index('-D')+1]); data.mkdir(parents=True,exist_ok=True); (data/'PG_VERSION').write_text('18')
elif name == 'postgres' and '--version' in args: print(os.environ.get('TEST_PG_BANNER','postgres (PostgreSQL) 18.6'))
elif name == 'psql': print('1')
elif name == 'openssl':
    if args[:2] == ['x509','-help']: print('-checkhost -checkip')
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
    elif args[0]=='ls':
        if name=='docker': print("unknown shorthand flag: 'q' in -q",file=sys.stderr); sys.exit(125)
        print('\\n'.join(p.name for p in state.iterdir() if p.read_text()=='running'))
    elif args[0] in ['start','stop']:
        target=state/args[1]
        if not target.exists(): sys.exit(1)
        target.write_text('running' if args[0]=='start' else 'stopped')
    elif args[0]=='run':
        cid=args[args.index('--name')+1]; (state/cid).write_text('running'); print(cid)
    elif args[:2]==['volume','inspect']: sys.exit(1)
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
                     'psql','createdb','clickhouse','curl','sleep','openssl']:
            path = self.bin/name; path.write_text(STUB); path.chmod(0o755)
        self.home = self.root/'home with spaces'; self.home.mkdir()
        self.bundle = self.root/'bundle'; self.bundle.mkdir()
        shutil.copytree(ROOT/'scripts', self.bundle/'scripts')
        shutil.copy(ROOT/'uninstall.sh', self.bundle/'uninstall.sh')
        (self.bundle/'tallyd').write_text('#!/bin/bash\n[ "$1" = --check-ui ]\n')
        (self.bundle/'tallyd').chmod(0o755)
        for path in [self.root/'brew/bin', self.root/'brew/postgresql@18/bin']:
            path.mkdir(parents=True, exist_ok=True)
        for name in ['initdb','postgres','pg_isready','psql','createdb','clickhouse']:
            (self.root/'brew/bin'/name).symlink_to(self.bin/name)
        self.env = {k: v for k,v in os.environ.items() if not k.startswith(('TALLY_','TALLY_UPGRADE_','XDG_'))}
        (self.root/"empty.env").touch()
        (self.root/"os-release").write_text("ID=ubuntu\nVERSION_ID=22.04\nVERSION_CODENAME=jammy\n")
        self.env.update(TALLY_OS_RELEASE_FILE=str(self.root/"os-release"), TALLY_ENV_FILE=str(self.root/"empty.env"), PATH=f'{self.bin}:{os.environ["PATH"]}', HOME=str(self.home), FIXTURE=str(self.root),
                        TALLY_DATA_DIR=str(self.root/'data with spaces'),
                        TALLY_CONFIG_DIR=str(self.root/'config with spaces'),
                        TALLY_INSTALL_DIR=str(self.root/'install with spaces'),
                        TALLY_POSTGRES_URL='postgres://external/tally',
                        TALLY_CLICKHOUSE_URL='https://external.example:8443?user=custom&password=encoded%26secret')
    def tearDown(self): self.temp.cleanup()
    def run_script(self, script, *args, ok=True):
        result = subprocess.run(['bash',str(script),*map(str,args)], env=self.env, text=True, capture_output=True)
        if ok: self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        else: self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        return result
    def commands(self):
        import json
        return [json.loads(line) for line in (self.root/'commands').read_text().splitlines()]
    def install(self,*args): return self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,*args)
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
        self.env.pop('TALLY_POSTGRES_URL');self.env.pop('TALLY_CLICKHOUSE_URL')
        self.install('--no-start')
        self.install('--no-start')
        commands=self.commands()
        self.assertEqual(sum(c[0]=='initdb' for c in commands),1)
        self.assertEqual(sum(c[0]=='curl' and 'CREATE DATABASE IF NOT EXISTS `tally`' in c for c in commands),2)
        self.assertFalse(list(Path(self.env['TALLY_DATA_DIR']).glob('.clickhouse-headers.*')))
        self.assertTrue(any(c[:4]==['sudo','apt-get','install','-y'] for c in commands))
        self.assertTrue((Path(self.env['TALLY_CONFIG_DIR'])/'clickhouse.xml').is_file())
        self.assertTrue((self.home/'.config/systemd/user/tally-postgres.service').is_file())
        self.assertTrue((self.home/'.config/systemd/user/tally-clickhouse.service').is_file())
    def test_homebrew_postgres_version_with_packager_suffix(self):
        self.env.update(TEST_OS='Darwin',TEST_PG_BANNER='postgres (PostgreSQL) 18.6 (Homebrew)')
        result=self.install('--no-start')
        self.assertIn('Using postgres (PostgreSQL) 18.6 (Homebrew)',result.stdout)
        self.assertIn('Preparing the private PostgreSQL database',result.stdout)
        self.assertNotIn('embedded UI is available',result.stdout)
        self.assertTrue((self.home/'Library/LaunchAgents/ai.godel.tally.postgres.plist').is_file())
    def test_postgres_version_parser_accepts_package_labels_and_rejects_unknown_banners(self):
        for banner,expected in [('postgres (PostgreSQL) 18.6 (Homebrew)','18'),
                                ('postgres (PostgreSQL) 15.10 (Ubuntu 15.10-1.pgdg24.04+1)','15'),
                                ('postgres (PostgreSQL) 17.4','17'),('postgres (PostgreSQL) 14.18','14')]:
            result=subprocess.run(['bash','-c','source "$1"; postgres_major_version "$2"','test',str(ROOT/'scripts/runtime-common.sh'),banner],text=True,capture_output=True,check=True)
            self.assertEqual(result.stdout.strip(),expected)
        self.env.update(TEST_PG_BANNER='postgres (PostgreSQL) 14.18 (Homebrew)')
        result=self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,'--no-start',ok=False)
        self.assertIn('requires PostgreSQL 15 or newer; found:',result.stderr)
        self.assertFalse(any(c[0]=='initdb' for c in self.commands()))
        self.env['TEST_PG_BANNER']='unexpected banner 18.6'
        result=self.run_script(self.bundle/'scripts/install-runtime.sh',self.bundle,'--no-start',ok=False)
        self.assertIn('Cannot read the PostgreSQL version',result.stderr)
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
                         ['gui/1000/ai.godel.tally.'+name for name in ['server','postgres','clickhouse']])
        self.assertFalse(any(c[0]=='brew' for c in commands))
        self.assertFalse(list((self.home/'Library/LaunchAgents').glob('ai.godel.tally.*.plist')))
        self.assertEqual(config.read_bytes(),saved)
        self.assertTrue((Path(self.env['TALLY_DATA_DIR'])/'postgres/PG_VERSION').exists())
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
    def test_brew_and_yum_native_packages(self):
        for platform in ['Darwin', 'Linux']:
            self.env.update(TEST_OS=platform, TALLY_DATA_DIR=str(self.root/platform/'data'),
                TALLY_CONFIG_DIR=str(self.root/platform/'config'), TALLY_INSTALL_DIR=str(self.root/platform/'install'))
            self.env.pop('TALLY_POSTGRES_URL',None);self.env.pop('TALLY_CLICKHOUSE_URL',None)
            if platform == 'Linux':
                (self.bin/'apt-get').unlink();(self.bin/'dnf').unlink()
                (self.root/'os-release').write_text('ID=rocky\nVERSION_ID=9.0\n')
            self.install('--no-start')
        commands=self.commands()
        self.assertTrue(any(c[:3]==['brew','list','postgresql@18'] for c in commands))
        self.assertTrue(any(c[:4]==['sudo','yum','install','-y'] for c in commands))
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
        self.env.update(TALLY_DB_MODE='existing', TALLY_KEEP_DB='1')
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
        stages=['installing for linux/amd64','finding the latest release','downloading v0.1.0',
                'downloading and verifying','checksum verified','preparing the application']
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
                self.run_script(ROOT/'install.sh','--db','docker','--no-start')
                self.assertTrue((self.root/'installed').read_text().endswith('--db docker --no-start\n'))
        urls=[next(a for a in c if a.startswith('https://')) for c in self.commands() if c[0]=='curl']
        self.assertEqual(len(urls),8)
        self.assertTrue(all('/releases/download/v0.1.0/' in url for url in urls))
    def test_unresolved_latest_release_never_executes_installer(self):
        self.env.update(BOOTSTRAP_SOURCE=str(self.root),TEST_RELEASE_URL='https://github.com/login')
        result=self.run_script(ROOT/'install.sh',ok=False)
        self.assertIn('Could not resolve the latest Tally release',result.stderr)
        self.assertFalse((self.root/'installed').exists())
    def test_configuration_is_data_not_shell_code(self):
        payload=f'$(touch {self.root}/injected)'
        config=self.root/'env';config.write_text(f'TALLY_TEST_VALUE={payload}\n')
        result=subprocess.run(['bash','-c','source "$1"; load_env "$2"; printf "%s" "$TALLY_TEST_VALUE"','test',str(ROOT/'scripts/runtime-common.sh'),str(config)],env=self.env,text=True,capture_output=True,check=True)
        self.assertEqual(result.stdout,payload)
        self.assertFalse((self.root/'injected').exists())

if __name__=='__main__': unittest.main()
