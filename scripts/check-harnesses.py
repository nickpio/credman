#!/usr/bin/env python3
"""Probe installed MCP harness clients with synthetic homes and provider egress disabled."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from examples.harness_config import HARNESSES


def stage_file(source, target):
    shutil.copyfile(source, target)
    return hashlib.sha256(target.read_bytes()).hexdigest()


def source_drift(sources, hashes):
    return sorted(key for key, path in sources.items()
                  if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != hashes[key])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--binary-sha256', required=True)
    parser.add_argument('--harness', choices=HARNESSES, action='append',
                        help='Select a harness; repeat to select several (default: full matrix)')
    parser.add_argument('--hermes-source', type=Path, default=Path.home() / '.hermes/hermes-agent',
                        help='Installed Hermes source tree for its native MCP probe')
    args = parser.parse_args()
    selected = list(dict.fromkeys(args.harness or HARNESSES))
    binary = args.binary.resolve(strict=True)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != args.binary_sha256:
        parser.error('Credman artifact digest mismatch')
    controller = Path(__file__).resolve()
    repository = controller.parents[1]
    sources = {'scripts/check-harnesses.py': controller}
    snapshot_hashes = {'scripts/check-harnesses.py': hashlib.sha256(controller.read_bytes()).hexdigest()}
    executables = {'codex': 'codex', 'claude-code': 'claude', 'grok-build': 'grok', 'opencode': 'opencode'}
    paths = {executables[h]: shutil.which(executables[h]) for h in selected if h in executables}
    if 'opencode' in paths and not paths['opencode']:
        paths['opencode'] = str(Path.home() / '.opencode/bin/opencode')
    for name, value in paths.items():
        if not value or not Path(value).is_file():
            parser.error('Installed harness unavailable: ' + name)
        paths[name] = str(Path(value).resolve())
        with Path(paths[name]).open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                parser.error('Expected reviewed standalone ELF harness: ' + name)
    scratch = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix='credman-harness-check-', dir=scratch) as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        runtime = work / 'runtime'
        runtime.mkdir(mode=0o700)
        (runtime / 'work').mkdir(mode=0o700)
        staged = work / 'project'
        for relative in ['tests/bridge_support.py', 'tests/harness_clients.py', 'examples/harness_config.py']:
            target = staged / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            sources[relative] = repository / relative
            snapshot_hashes[relative] = stage_file(sources[relative], target)
        staged_binary = work / 'credman'
        shutil.copyfile(binary, staged_binary)
        staged_binary.chmod(0o500)
        assert hashlib.sha256(staged_binary.read_bytes()).hexdigest() == args.binary_sha256
        staged_paths = {}
        harness_hashes = {}
        for name, original in paths.items():
            target = work / ('client-' + name)
            harness_hashes[name] = stage_file(Path(original), target)
            target.chmod(0o500)
            staged_paths[name] = target
            sources['harness:' + name] = Path(original)
            snapshot_hashes['harness:' + name] = harness_hashes[name]
        hermes = args.hermes_source.resolve()
        if 'hermes' in selected and not (hermes / 'hermes_cli/mcp_config.py').is_file():
            parser.error('Installed Hermes source unavailable; supply --hermes-source')
        hermes_source = work / 'hermes-source'
        hermes_source.mkdir()
        source_files = list(hermes.glob('*.py')) if 'hermes' in selected else []
        for directory in (['hermes_cli', 'hermes_platform', 'pm', 'tools', 'agent', 'gateway', 'utils'] if 'hermes' in selected else []):
            if (hermes / directory).is_dir():
                source_files.extend((hermes / directory).rglob('*.py'))
        hermes_hashes = {}
        for source in source_files:
            relative = source.relative_to(hermes)
            if source.is_symlink() or '__pycache__' in relative.parts or any(part == 'tests' for part in relative.parts):
                continue
            destination = hermes_source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            hermes_hashes[str(relative)] = stage_file(source, destination)
            sources['hermes:' + str(relative)] = source
            snapshot_hashes['hermes:' + str(relative)] = hermes_hashes[str(relative)]
        command = ['bwrap', '--die-with-parent', '--new-session', '--unshare-all',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/bin', '/sbin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64', '--proc', '/proc', '--dev', '/dev',
            '--dir', '/etc', '--dir', '/opt', '--dir', '/home/tester', '--tmpfs', '/tmp',
            '--ro-bind', str(staged), '/repo', '--ro-bind', str(staged_binary), '/opt/credman',
            '--ro-bind', str(hermes_source), '/opt/hermes', '--bind', str(runtime), '/scratch',
            '--clearenv', '--setenv', 'HOME', '/home/tester', '--setenv', 'TMPDIR', '/scratch',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--setenv', 'HERMES_DISABLE_LAZY_INSTALLS', '1',
            '--chdir', '/scratch/work']
        for name, value in staged_paths.items():
            command += ['--ro-bind', str(value), '/opt/' + name]
        # Only the installed Python runtime/dependency environment is mounted, not Hermes homes,
        # auth/config/session stores, Bot workspaces, hooks or private profile histories.
        for prefix in dict.fromkeys([sys.base_prefix, sys.prefix]):
            command += ['--ro-bind', prefix, prefix]
        result = subprocess.run([*command, sys.executable, '-B', '/repo/tests/harness_clients.py',
                                 *[argument for h in selected for argument in ('--harness', h)]],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=270)
        assert hashlib.sha256(staged_binary.read_bytes()).hexdigest() == args.binary_sha256
        try:
            data = json.loads(result.stdout)
        except ValueError:
            data = {'all_connected': False, 'probe_error': 'Probe did not return a complete result',
                    'exit_code': result.returncode, 'diagnostics': 'Harness probe failed before a complete structured result'}
        drift = source_drift(sources, snapshot_hashes)
        data.update({'binary_sha256': args.binary_sha256, 'network': False,
                     'source_drift': drift, 'source_bound': not drift,
                     'scope': 'Synthetic client configuration and native MCP discovery/health, no model/provider operation',
                     'harness_binary_sha256': harness_hashes,
                     'probe_source_sha256': {relative: snapshot_hashes[relative]
                         for relative in ['scripts/check-harnesses.py', 'tests/bridge_support.py', 'tests/harness_clients.py', 'examples/harness_config.py']},
                     'hermes_probe_source_digest': hashlib.sha256(json.dumps(hermes_hashes, sort_keys=True).encode()).hexdigest()})
        print(json.dumps(data, indent=2))
        return 0 if result.returncode == 0 and data.get('all_connected') and not drift else 1


if __name__ == '__main__':
    raise SystemExit(main())
