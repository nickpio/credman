#!/usr/bin/env python3
"""Build/test Credman with a synthetic home and no host credentials or desktop."""
import argparse
import atexit
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

python_checks = {
    'private_https_probe': {
        'files': ('tests/private_https_probe.py', 'tests/https_fixture.py'),
        'arguments': (),
    },
    'workload_tests': {
        'files': ('tests/test_workload_launcher.py', 'tests/workload_launcher.py'),
        'arguments': ('--synthetic-only',),
    },
}
executable_checks = {
    'agent_program_tests': 'tests/agent_program_regression.py',
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--work-dir', type=Path, help='Dedicated cache directory outside the repository')
parser.add_argument('--revision', help='Read Cargo/source blobs from this commit for baseline comparison')
mode = parser.add_mutually_exclusive_group()
mode.add_argument('--fetch', action='store_true', help='Fetch locked crates only; never build or test')
for name in executable_checks:
    mode.add_argument('--' + name.replace('_', '-'), action='store_true', help='Build and test a verified executable snapshot: ' + name.replace('_', ' '))
for name in python_checks:
    mode.add_argument('--' + name.replace('_', '-'), action='store_true', help='Run declared ' + name.replace('_', ' ') + ' offline')
mode.add_argument('--probe', action='store_true', help='Verify isolation only')
parser.add_argument('cargo_args', nargs=argparse.REMAINDER)
args = parser.parse_args()
python_mode = next((name for name in python_checks if getattr(args, name)), None)
executable_mode = next((name for name in executable_checks if getattr(args, name)), None)
executable_fixture = executable_checks[executable_mode] if executable_mode else None
if args.revision and (executable_mode or python_mode):
    parser.error('Python regression fixtures apply to the current working tree only')
if args.cargo_args and (args.fetch or executable_mode or python_mode or args.probe):
    parser.error('Fixed fetch/probe/executable/Python modes do not accept Cargo arguments')
repo = Path(__file__).resolve().parents[1]
fixtures = (*executable_checks.values(), 'tests/bridge_support.py', 'tests/https_fixture.py', *(relative for check in python_checks.values() for relative in check['files']))
if executable_fixture and not (repo / executable_fixture).is_file():
    parser.error('Declared executable regression fixture is required')
if python_mode and not all((repo / path).is_file() for path in python_checks[python_mode]['files']):
    parser.error('All declared files for this Python check are required')
cache_root = Path(os.environ.get('TMPDIR', str(Path.home() / '.cache')))
work = (args.work_dir or cache_root / 'credman-isolated').resolve()
if work.is_relative_to(repo) or repo.is_relative_to(work):
    parser.error('The dedicated cache must be outside the repository')
work.mkdir(mode=0o700, parents=True, exist_ok=True)
marker = work / '.credman-isolated.json'
if marker.is_symlink():
    parser.error('Cache marker must not be a symlink')
if marker.exists():
    if json.loads(marker.read_text()) != {'version': 1, 'repository': str(repo)}:
        parser.error('Cache belongs to another repository or format')
else:
    if any(work.iterdir()):
        parser.error('Refusing to use an unmarked nonempty cache directory')
    marker.write_text(json.dumps({'version': 1, 'repository': str(repo)}) + '\n')
for name in ['cargo', 'target', 'tmp', 'logs']:
    if (work / name).is_symlink():
        parser.error(f'Cache subdirectory must not be a symlink: {name}')
    (work / name).mkdir(exist_ok=True)
snapshot = tempfile.TemporaryDirectory(prefix='source-', dir=work)
atexit.register(snapshot.cleanup)
source_root = Path(snapshot.name)
rustup = Path.home() / '.cargo/bin/rustup'
toolchain = Path(subprocess.run([str(rustup), 'which', 'rustc'], check=True, capture_output=True, text=True).stdout.strip()).parent.parent
if args.revision:
    tracked = subprocess.run(['git', '-C', str(repo), 'ls-tree', '-r', '--name-only', args.revision, '--', 'Cargo.toml', 'Cargo.lock', 'src'], check=True, capture_output=True, text=True).stdout.splitlines()
else:
    source_dir = repo / 'src'
    assert source_dir.resolve().is_relative_to(repo) and not source_dir.is_symlink()
    tracked = ['Cargo.toml', 'Cargo.lock', *sorted(str(p.relative_to(repo)) for p in source_dir.rglob('*.rs'))]
if not args.revision:
    tracked.extend(relative for relative in fixtures if (repo / relative).is_file())
source_hashes = {}
for relative in tracked:
    source = repo / relative
    assert source.resolve().is_relative_to(repo) and not source.is_symlink(), relative
    assert relative in {'Cargo.toml', 'Cargo.lock', *fixtures} or (relative.startswith('src/') and relative.endswith('.rs')), relative
    if args.revision:
        data = subprocess.run(['git', '-C', str(repo), 'show', f'{args.revision}:{relative}'], check=True, capture_output=True).stdout
    else:
        data = source.read_bytes()
    dest = source_root / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    source_hashes[relative] = hashlib.sha256(data).hexdigest()

if executable_mode == 'two_agent_demo' and source_hashes[executable_fixture] != args.demo_source_sha256:
    parser.error('Demo helper changed after review; refusing to build or execute a different snapshot')


def sandbox(network=False):
    command = ['bwrap', '--die-with-parent', '--new-session', '--unshare-all']
    if network:
        command += ['--share-net']
    command += ['--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/bin', '/sbin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64', '--proc', '/proc', '--dev', '/dev', '--dir', '/etc', '--dir', '/home/tester', '--dir', '/run', '--clearenv', '--ro-bind', str(toolchain), '/opt/rust', '--ro-bind', str(source_root), '/repo', '--bind', str(work / 'cargo'), '/cargo', '--bind', str(work / 'target'), '/target', '--bind', str(work / 'tmp'), '/scratch', '--chdir', '/repo']
    for key, value in {'HOME': '/home/tester', 'CARGO_HOME': '/cargo', 'CARGO_TARGET_DIR': '/target', 'TMPDIR': '/scratch', 'PATH': '/opt/rust/bin:/usr/bin:/bin', 'CARGO_BUILD_JOBS': '2', 'RUST_TEST_THREADS': '2', 'LANG': 'C.UTF-8'}.items():
        command += ['--setenv', key, value]
    if Path('/etc/ld.so.cache').is_file():
        command += ['--ro-bind', '/etc/ld.so.cache', '/etc/ld.so.cache']
    if network:
        command += ['--ro-bind', '/etc/resolv.conf', '/etc/resolv.conf', '--ro-bind', '/etc/hosts', '/etc/hosts']
        cert = Path('/etc/ssl/cert.pem')
        if cert.exists():
            command += ['--ro-bind', str(cert.resolve()), '/etc/ssl/cert.pem', '--setenv', 'CARGO_HTTP_CAINFO', '/etc/ssl/cert.pem', '--setenv', 'SSL_CERT_FILE', '/etc/ssl/cert.pem']
    return command


probe = 'import os,pathlib,socket; assert not pathlib.Path(' + repr(str(Path.home())) + ').exists(); assert not pathlib.Path("/run/user").exists(); assert not os.environ.get("DISPLAY"); assert not os.environ.get("WAYLAND_DISPLAY"); assert not os.environ.get("DBUS_SESSION_BUS_ADDRESS"); assert os.read(0,1)==b""; assert not pathlib.Path("/proc/net/route").read_text().splitlines()[1:]; server=socket.socket(); server.bind(("127.0.0.1",0)); server.listen(1); client=socket.create_connection(server.getsockname(),timeout=2); accepted,_=server.accept(); client.close(); accepted.close(); server.close(); print("ISOLATION_OK: synthetic home; host home/runtime and network hidden; private loopback works")'
subprocess.run([*sandbox(), '/usr/bin/python3', '-c', probe], stdin=subprocess.DEVNULL, check=True, timeout=15)
if args.probe:
    raise SystemExit(0)
if args.fetch:
    commands = [('fetch', True, ['/opt/rust/bin/cargo', 'fetch', '--locked'])]
elif executable_mode:
    commands = [('cli-build', False, ['/opt/rust/bin/cargo', 'build', '--locked', '--offline', '--bin', 'credman', '--message-format=json']), (executable_mode.replace('_', '-'), False, None)]
elif python_mode:
    check = python_checks[python_mode]
    commands = [(python_mode.replace('_', '-'), False, ['/usr/bin/python3', '-B', '/repo/' + check['files'][0], *check['arguments']])]
else:
    cargo_args = args.cargo_args or ['test']
    if cargo_args[0] not in {'test', 'build', 'check', 'clippy', 'fmt'}:
        parser.error('Only test/build/check/clippy/fmt are admitted')
    locked = [] if cargo_args[0] == 'fmt' else ['--locked', '--offline']
    commands = [(cargo_args[0], False, ['/opt/rust/bin/cargo', cargo_args[0], *locked, *cargo_args[1:]])]
cli_artifact = None
for label, network, command in commands:
    if command is None:
        assert executable_fixture is not None
        assert cli_artifact is not None
        executable = source_root / '.verified-bin/credman'
        assert hashlib.sha256(executable.read_bytes()).hexdigest() == cli_artifact['sha256']
        command = ['/usr/bin/python3', '-B', '/repo/' + executable_fixture, '/repo/.verified-bin/credman']
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    started = time.monotonic()
    result = subprocess.run([*sandbox(network), *command], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=900)
    out = work / 'logs' / f'{stamp}-{label}'
    out.with_suffix('.stdout').write_text(result.stdout)
    out.with_suffix('.stderr').write_text(result.stderr)
    if label == 'cli-build' and result.returncode == 0:
        artifacts = []
        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if item.get('reason') == 'compiler-artifact' and item.get('executable') and item['target']['name'] == 'credman' and 'bin' in item['target']['kind'] and not item['profile']['test']:
                artifacts.append(item)
        assert len(artifacts) == 1, 'Expected exactly one native executable from this build'
        artifact = artifacts[0]
        relative = Path(artifact['executable']).relative_to('/target')
        assert '..' not in relative.parts
        built = (work / 'target' / relative).resolve()
        assert built.is_relative_to((work / 'target').resolve()) and built.is_file()
        executable = source_root / '.verified-bin/credman'
        executable.parent.mkdir()
        shutil.copyfile(built, executable)
        executable.chmod(0o500)
        cli_artifact = {'cargo_executable': artifact['executable'], 'executed_snapshot': '/repo/.verified-bin/credman', 'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'profile': artifact['profile']}
    receipt = {'command': command, 'exit_code': result.returncode, 'elapsed_seconds': time.monotonic() - started, 'network': network, 'source_sha256': source_hashes, 'revision': args.revision, 'toolchain': str(toolchain), 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'stdout': str(out.with_suffix('.stdout')), 'stderr': str(out.with_suffix('.stderr')), 'cli_artifact': cli_artifact}
    out.with_suffix('.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if label != 'cli-build':
        print(result.stdout)
    print(result.stderr, file=sys.stderr)
    print(json.dumps({'receipt': str(out.with_suffix('.json')), 'exit_code': result.returncode, 'cli_artifact': cli_artifact, 'test_summaries': re.findall(r'test result:.*', result.stdout)}, indent=2), flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
