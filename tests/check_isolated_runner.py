"""Safety checks for the Linux-only isolation runner. No real vault access."""
import json
from pathlib import Path
import subprocess
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / 'scripts/check-isolated.py'


class RunnerGuards(unittest.TestCase):
    def test_opencode_incomplete_does_not_launch_experimental_probe(self):
        import ast
        source = ast.parse((REPO / 'tests/harness_clients.py').read_text())
        function = next(node for node in source.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'opencode_discovery')
        self.assertFalse(any(isinstance(node, ast.Call) for node in ast.walk(function)))
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<incomplete-probe>', 'exec'), namespace)
        result = namespace['opencode_discovery']({}, 'synthetic-marker')
        self.assertIs(result['connected'], False)
        self.assertEqual(result['status'], 'incomplete')
        self.assertNotIn('synthetic-marker', json.dumps(result))

    def test_harness_snapshot_hashes_executed_bytes_and_reports_original_drift(self):
        import hashlib
        probe = runpy.run_path(str(REPO / 'scripts/check-harnesses.py'))
        with tempfile.TemporaryDirectory() as directory:
            source, staged = Path(directory) / 'original', Path(directory) / 'staged'
            source.write_bytes(b'synthetic executed source')
            digest = probe['stage_file'](source, staged)
            source.write_bytes(b'different unexecuted source')
            self.assertEqual(digest, hashlib.sha256(staged.read_bytes()).hexdigest())
            self.assertEqual(probe['source_drift']({'helper': source}, {'helper': digest}), ['helper'])
            self.assertEqual(staged.read_bytes(), b'synthetic executed source')

    def run_probe(self, work, *extra):
        return subprocess.run([sys.executable, str(RUNNER), '--work-dir', str(work),
                               *extra, '--probe'], input='synthetic caller input must stay outside\n', capture_output=True, text=True, timeout=20)

    def test_repository_cannot_be_cache(self):
        result = self.run_probe(REPO)
        self.assertEqual(result.returncode, 2)
        self.assertIn('outside the repository', result.stderr)

    def test_nonempty_unmarked_cache_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            sentinel = work / 'sentinel'
            sentinel.write_text('synthetic preserve marker')
            result = self.run_probe(work)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(sentinel.read_text(), 'synthetic preserve marker')
            self.assertEqual(sorted(p.name for p in work.iterdir()), ['sentinel'])

    def test_wrong_repository_marker_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            marker = work / '.credman-isolated.json'
            before = json.dumps({'version': 1, 'repository': '/synthetic-other-repository'})
            marker.write_text(before)
            result = self.run_probe(work)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(marker.read_text(), before)

    def test_symlinked_logs_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / 'cache'
            work.mkdir()
            (work / '.credman-isolated.json').write_text(json.dumps(
                {'version': 1, 'repository': str(REPO)}))
            destination = root / 'outside'
            destination.mkdir()
            (destination / 'sentinel').write_text('preserve')
            (work / 'logs').symlink_to(destination, target_is_directory=True)
            result = self.run_probe(work)
            self.assertEqual(result.returncode, 2)
            self.assertEqual([p.name for p in destination.iterdir()], ['sentinel'])
            self.assertEqual((destination / 'sentinel').read_text(), 'preserve')

    def test_fresh_cache_probe_hides_home_runtime_and_network(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            result = self.run_probe(work)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('ISOLATION_OK', result.stdout)
            self.assertFalse(list(work.glob('source-*')))
            marker = json.loads((work / '.credman-isolated.json').read_text())
            self.assertEqual(marker, {'version': 1, 'repository': str(REPO)})

    def test_executable_mode_rejects_custom_cargo_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            stale = work / 'target/debug/credman'
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b'synthetic stale artifact; must never execute')
            (work / '.credman-isolated.json').write_text(json.dumps(
                {'version': 1, 'repository': str(REPO)}))
            for mode in ['--agent-program-tests']:
                for arguments in [['check'], ['build', '--release'], ['build', '--target', 'synthetic-target']]:
                    result = subprocess.run([sys.executable, str(RUNNER), '--work-dir',
                                             str(work), mode, *arguments],
                                            stdin=subprocess.DEVNULL, capture_output=True,
                                            text=True, timeout=20)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(stale.read_bytes(), b'synthetic stale artifact; must never execute')
                    self.assertFalse((work / 'logs').exists())



    def test_fetch_only_queues_no_execution(self):
        # Only the Cargo command boundary is stubbed; real Rust/CLI checks run elsewhere.
        observed = []
        real_run = subprocess.run

        def observe(command, *args, **kwargs):
            if '/opt/rust/bin/cargo' in command:
                index = command.index('/opt/rust/bin/cargo')
                observed.append(command[index + 1])
                return subprocess.CompletedProcess(command, 0, '', '')
            return real_run(command, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            argv = [str(RUNNER), '--work-dir', directory, '--fetch']
            with patch.object(sys, 'argv', argv), patch('subprocess.run', side_effect=observe), patch('builtins.print'):
                namespace = runpy.run_path(str(RUNNER), run_name='__main__')
                namespace['snapshot'].cleanup()
        self.assertEqual(observed, ['fetch'])

    def test_current_snapshot_includes_new_source_and_declared_python_fixtures(self):
        real_run = subprocess.run
        observed = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / 'repo'
            (repo / 'scripts').mkdir(parents=True)
            (repo / 'src').mkdir()
            (repo / 'tests').mkdir()
            runner = repo / 'scripts/check-isolated.py'
            runner.write_bytes(RUNNER.read_bytes())
            (repo / 'Cargo.toml').write_text('[package]\nname="snapshot-fixture"\nversion="0.1.0"\nedition="2021"\n')
            (repo / 'Cargo.lock').write_text('version = 3\n')
            (repo / 'src/main.rs').write_text('fn main() {}\n')
            real_run(['git', 'init', '--quiet', str(repo)], check=True)
            real_run(['git', '-C', str(repo), 'add', 'Cargo.toml', 'Cargo.lock', 'src/main.rs'], check=True)
            expected = {
                'src/new_module.rs': b'pub fn newly_written_source() {}\n',
                'tests/bridge_support.py': b'# synthetic declared supervisor helper\n',
                'tests/https_fixture.py': b'# synthetic declared HTTPS oracle\n',
                'tests/private_https_probe.py': b'# synthetic declared TLS seam probe\n',
                'tests/workload_launcher.py': b'# synthetic declared launcher\n',
                'tests/test_workload_launcher.py': b'# synthetic declared boundary check\n',
                'tests/agent_program_regression.py': b'# synthetic declared executable check\n',
            }
            for relative, data in expected.items():
                (repo / relative).write_bytes(data)

            def observe(command, *args, **kwargs):
                if '/opt/rust/bin/cargo' in command:
                    staged = Path(command[command.index('/repo') - 1])
                    for relative, data in expected.items():
                        self.assertTrue((staged / relative).is_file(), relative)
                        self.assertEqual((staged / relative).read_bytes(), data)
                    observed.append('verified_snapshot')
                    return subprocess.CompletedProcess(command, 0, '', '')
                return real_run(command, *args, **kwargs)

            argv = [str(runner), '--work-dir', str(root / 'cache'), '--fetch']
            with patch.object(sys, 'argv', argv), patch('subprocess.run', side_effect=observe), patch('builtins.print'):
                namespace = runpy.run_path(str(runner), run_name='__main__')
                namespace['snapshot'].cleanup()
        self.assertEqual(observed, ['verified_snapshot'])

    def test_python_modes_reject_custom_arguments_and_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for mode in ['--workload-tests']:
                for extra, message in [([mode, 'check'], 'do not accept Cargo arguments'),
                                       (['--revision', 'HEAD', mode], 'current working tree only')]:
                    result = subprocess.run([sys.executable, str(RUNNER), '--work-dir', str(work), *extra],
                                            stdin=subprocess.DEVNULL, capture_output=True,
                                            text=True, timeout=20)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertFalse(list(work.iterdir()))

    def test_workload_mode_requires_explicit_synthetic_opt_in(self):
        observed = []
        real_run = subprocess.run

        def observe(command, *args, **kwargs):
            fixture = '/repo/tests/test_workload_launcher.py'
            if fixture in command:
                observed.append(command[command.index(fixture):])
                return subprocess.CompletedProcess(command, 0, '', '')
            return real_run(command, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            argv = [str(RUNNER), '--work-dir', directory, '--workload-tests']
            with patch.object(sys, 'argv', argv), patch('subprocess.run', side_effect=observe), patch('builtins.print'):
                namespace = runpy.run_path(str(RUNNER), run_name='__main__')
                namespace['snapshot'].cleanup()
        self.assertEqual(observed, [['/repo/tests/test_workload_launcher.py', '--synthetic-only']])

    def test_revision_cannot_use_current_executable_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for mode in ['--agent-program-tests']:
                result = self.run_probe(work, '--revision', 'HEAD', mode)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(list(work.iterdir()))


if __name__ == '__main__':
    unittest.main()
