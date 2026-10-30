"""Actual rootless boundary checks. Run with --synthetic-only in the offline harness.

No skip-on-unavailable behavior: unsupported namespaces are a failing release gate.
All probe targets are task-owned synthetic paths supplied over a private channel.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

LAUNCHER = Path(__file__).with_name('workload_launcher.py').resolve()

WORKER = r'''
import json
import os
from pathlib import Path
import socket

channel = socket.socket(fileno=3)
channel.settimeout(5)
stream = channel.makefile('rwb', buffering=0)
config = json.loads(stream.readline(32768))

def denied_open(path):
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return True
    else:
        os.close(descriptor)
        return False

checks = {}
checks['private_roundtrip'] = config['challenge'] == 'synthetic-private-challenge'
checks['forbidden_files'] = all(denied_open(path) for path in config['forbidden'])
checks['hidden_host_runtime'] = all(not Path(path).exists() for path in ['/run/user', '/tmp', '/home/host-synthetic'])
checks['no_host_proc_root'] = all(denied_open('/proc/' + str(config['host_pid']) + '/root' + path) for path in config['forbidden'])
# Namespace-local PID numbers can collide with the supervisor's outer PID.
# Always attempt the memory open, then distinguish an inner process collision.
memory_denied = denied_open('/proc/' + str(config['host_pid']) + '/mem')
try:
    target_pid_namespace = os.readlink('/proc/' + str(config['host_pid']) + '/ns/pid')
except OSError:
    target_pid_namespace = None
checks['no_host_proc_memory'] = memory_denied or target_pid_namespace != config['namespaces']['pid']
checks['no_pid1_escape'] = all(denied_open('/proc/1/root' + path) for path in config['forbidden'])
checks['namespace_separation'] = all(os.readlink('/proc/self/ns/' + name) != value for name, value in config['namespaces'].items())
open_fds = []
for fd in sorted(int(name) for name in os.listdir('/proc/self/fd')):
    try:
        os.fstat(fd)
    except OSError:
        continue
    open_fds.append(fd)
checks['only_expected_fds'] = open_fds == [0, 1, 2, 3]
checks['stdin_is_null'] = os.read(0, 1) == b''
checks['empty_inherited_environment'] = dict(os.environ) == {'HOME': '/home/worker', 'TMPDIR': '/scratch', 'LANG': 'C.UTF-8'}
checks['synthetic_home'] = Path.home() == Path('/home/worker') and not list(Path.home().iterdir())
checks['empty_network_routes'] = not Path('/proc/net/route').read_text().splitlines()[1:]
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
checks['no_new_privileges'] = status['NoNewPrivs'].strip() == '1'
checks['no_capabilities'] = all(int(status[name].strip(), 16) == 0 for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb'])
connection = socket.socket()
connection.settimeout(0.5)
try:
    connection.connect(('127.0.0.1', config['listener_port']))
except OSError:
    checks['no_supervisor_network'] = True
else:
    checks['no_supervisor_network'] = False
finally:
    connection.close()
checks['program_readonly'] = False
try:
    with open('/program/worker', 'a') as output:
        output.write('unexpected')
except OSError:
    checks['program_readonly'] = True
checks['no_other_scratch'] = not Path('/scratch/worker-private').exists()
Path('/scratch/worker-private').write_text('synthetic scratch')
checks['private_writable_scratch'] = Path('/scratch/worker-private').read_text() == 'synthetic scratch'
stream.write(json.dumps({'checks': checks, 'reply': 'synthetic-private-reply',
    'environment_keys': sorted(os.environ),
    'namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in config['namespaces']}}).encode() + b'\n')
if config.get('hold'):
    assert stream.readline(128) == b'release\n'
stream.close()
channel.close()
'''


class WorkloadLauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Only the trusted offline controller may invoke these tests. Its outer
        # namespace has no /tmp, which Bubblewrap needs before child mounts.
        # Never repair a host directory or change any existing directory.
        if os.environ.get('HOME') != '/home/tester' or os.environ.get('TMPDIR') != '/scratch' or LAUNCHER.parent != Path('/repo/tests'):
            raise RuntimeError('Required synthetic outer harness is absent')
        staging = Path('/tmp')
        if not staging.exists():
            staging.mkdir(mode=0o700)
            cls.addClassCleanup(staging.rmdir)

    def setUp(self):
        parent = Path(os.environ['TMPDIR'])
        self.temporary = tempfile.TemporaryDirectory(prefix='workload-boundaries-', dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.cache = self.root / 'launcher-cache'
        self.cache.mkdir(mode=0o700)
        self.worker = self.root / 'worker.py'
        self.worker.write_text(WORKER)
        self.worker.chmod(0o400)
        self.forbidden = []
        for name in ['vault', 'admin', 'peer', 'host-home', 'host-runtime']:
            directory = self.root / name
            directory.mkdir(mode=0o700)
            sentinel = directory / 'synthetic-sentinel'
            sentinel.write_text('synthetic-' + name + '-marker')
            sentinel.chmod(0o600)
            self.forbidden.append(str(sentinel))
        self.admin = os.open(self.forbidden[1], os.O_RDONLY)
        self.peer_file = os.open(self.forbidden[2], os.O_RDONLY)
        self.addCleanup(os.close, self.admin)
        self.addCleanup(os.close, self.peer_file)
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.addCleanup(self.listener.close)

    def spawn(self, bwrap='/usr/bin/bwrap', worker=None):
        supervisor, worker_channel = socket.socketpair()
        supervisor.settimeout(10)
        environment = dict(os.environ)
        environment.update({'DISPLAY': ':synthetic', 'WAYLAND_DISPLAY': 'synthetic',
                            'DBUS_SESSION_BUS_ADDRESS': 'synthetic',
                            'SYNTHETIC_ADMIN_MARKER': 'must-not-cross'})
        command = [sys.executable, '-I', '-B', str(LAUNCHER),
                   '--channel-fd', str(worker_channel.fileno()),
                   '--worker', str(worker or self.worker),
                   '--scratch-parent', str(self.cache), '--bwrap', bwrap, '--timeout', '12']
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(worker_channel.fileno(), self.admin, self.peer_file, self.listener.fileno()),
                                   close_fds=True, env=environment)
        worker_channel.close()
        self.addCleanup(supervisor.close)
        self.addCleanup(self.stop, process)
        return process, supervisor

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)

    def config(self):
        return {'challenge': 'synthetic-private-challenge', 'forbidden': self.forbidden,
                'host_pid': os.getpid(), 'listener_port': self.listener.getsockname()[1],
                'namespaces': {name: os.readlink('/proc/self/ns/' + name)
                               for name in ['user', 'pid', 'mnt', 'net', 'ipc', 'uts']}}

    def exchange(self, process, channel):
        try:
            channel.sendall(json.dumps(self.config()).encode() + b'\n')
            stream = channel.makefile('rb')
            try:
                response = stream.readline(32768)
            finally:
                stream.close()
        except OSError:
            response = b''
        stdout, stderr = process.communicate(timeout=15)
        self.assertEqual(process.returncode, 0, 'Required rootless sandbox failed: ' + stderr.decode(errors='replace'))
        self.assertEqual(stdout, b'', 'Worker leaked data to stdout')
        self.assertEqual(stderr, b'', 'Unexpected sandbox/worker diagnostics')
        self.assertTrue(response, 'Worker did not return a private response')
        result = json.loads(response)
        self.assertEqual(result['reply'], 'synthetic-private-reply')
        for name, passed in result['checks'].items():
            self.assertIs(passed, True, 'Real boundary attempt failed: ' + name + '; environment keys=' + repr(result['environment_keys']))
        self.assertEqual(set(result['checks']), {
            'private_roundtrip', 'forbidden_files', 'hidden_host_runtime',
            'no_host_proc_root', 'no_host_proc_memory', 'no_pid1_escape',
            'namespace_separation', 'only_expected_fds', 'stdin_is_null',
            'empty_inherited_environment', 'synthetic_home', 'empty_network_routes',
            'no_new_privileges', 'no_capabilities', 'no_supervisor_network',
            'program_readonly', 'private_writable_scratch', 'no_other_scratch'})

    def test_actual_boundaries_private_fd_and_cleanup(self):
        process, channel = self.spawn()
        self.exchange(process, channel)
        self.assertEqual(list(self.cache.iterdir()), [])
        self.assertFalse((self.cache / 'worker-private').exists())
        self.assertEqual(Path(self.forbidden[0]).read_text(), 'synthetic-vault-marker')
        os.lseek(self.admin, 0, os.SEEK_SET)
        self.assertEqual(os.read(self.admin, 128), b'synthetic-admin-marker')

    def test_two_workers_have_independent_namespaces_and_scratch(self):
        first, first_channel = self.spawn()
        second, second_channel = self.spawn()
        responses = []
        for channel in [first_channel, second_channel]:
            config = self.config()
            config['hold'] = True
            channel.sendall(json.dumps(config).encode() + b'\n')
            stream = channel.makefile('rb')
            try:
                response = stream.readline(32768)
            finally:
                stream.close()
            self.assertTrue(response, 'Required concurrent sandbox failed to start')
            responses.append(json.loads(response))
        # Both private scratch files exist concurrently, but neither saw the other.
        for response in responses:
            for name, passed in response['checks'].items():
                self.assertIs(passed, True, 'Concurrent boundary failed: ' + name)
            self.assertEqual(response['reply'], 'synthetic-private-reply')
        for name in ['user', 'pid', 'mnt', 'net', 'ipc', 'uts']:
            self.assertNotEqual(responses[0]['namespaces'][name], responses[1]['namespaces'][name])
        for process, channel in [(first, first_channel), (second, second_channel)]:
            channel.sendall(b'release\n')
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr.decode(errors='replace'))
            self.assertEqual(stdout, b'')
            self.assertEqual(stderr, b'')
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_missing_sandbox_refuses_without_worker_execution(self):
        process, channel = self.spawn(bwrap=str(self.root / 'nonexistent-bwrap'))
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 125)
        self.assertEqual(stdout, b'')
        self.assertEqual(stderr, b'WORKLOAD_REFUSED\n')
        self.assertEqual(channel.recv(1), b'')
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_failing_sandbox_does_not_fall_back_to_unsandboxed_worker(self):
        # A real failing executable, not a mocked subprocess result.
        process, channel = self.spawn(bwrap='/usr/bin/false')
        stdout, _stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(stdout, b'')
        self.assertEqual(channel.recv(1), b'')
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_non_socket_channel_is_refused(self):
        command = [sys.executable, '-I', '-B', str(LAUNCHER),
                   '--channel-fd', str(self.admin), '--worker', str(self.worker),
                   '--scratch-parent', str(self.cache)]
        result = subprocess.run(command, pass_fds=(self.admin,), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 125)
        self.assertEqual(result.stderr, b'WORKLOAD_REFUSED\n')
        self.assertEqual(list(self.cache.iterdir()), [])


if __name__ == '__main__':
    if '--synthetic-only' not in sys.argv or not os.environ.get('TMPDIR', '').startswith('/'):
        raise SystemExit('Use --synthetic-only with an explicit task-owned TMPDIR in the offline harness')
    sys.argv.remove('--synthetic-only')
    unittest.main()
