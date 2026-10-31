"""Synthetic supervisor and MCP clients shared by bridge acceptance checks."""
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import time
import uuid

SEED = ' '.join(['abandon'] * 11 + ['about'])  # Public BIP39 test vector.


def identifier():
    return str(uuid.uuid4())


def framed_call(channel, request):
    payload = json.dumps(request).encode()
    channel.sendall(struct.pack('!I', len(payload)) + payload)

    def exact(size):
        result = bytearray()
        while len(result) < size:
            block = channel.recv(size - len(result))
            if not block:
                raise RuntimeError('Private owner channel disconnected')
            result.extend(block)
        return bytes(result)

    size = struct.unpack('!I', exact(4))[0]
    if not 1 <= size <= 65536:
        raise RuntimeError('Invalid private owner frame')
    return json.loads(exact(size))


def approval(principal, permissions=None, recipients=()):
    fields = ['Label', 'Username', 'Password', 'Notes']
    return {'id': identifier(), 'owner': 'user', 'principal': principal, 'workspace': 'project',
            'service': 'example-service', 'origin': 'https://service.example.invalid',
            'fields': fields,
            'permissions': permissions or ['MetadataRead', 'SecretRead', 'SecretWrite', 'AccessGrant', 'EntryDelete'],
            'destinations': [], 'expires_at': int(time.time()) + 280,
            'share': {'recipients': list(recipients), 'fields': fields,
                      'permissions': ['MetadataRead', 'SecretRead'], 'destinations': [],
                      'expires_at': int(time.time()) + 270} if recipients else None}


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream)


class Owner:
    def __init__(self, binary, root, create=True, vault=None, destinations=None, registry=None):
        if os.environ.get('HOME') != '/home/tester' or os.environ.get('TMPDIR') != '/scratch':
            raise RuntimeError('Use the offline synthetic controller')
        self.binary, self.root = str(binary), Path(root)
        self.vault = Path(vault) if vault else self.root / 'vault'
        self.vault.mkdir(mode=0o700, exist_ok=True)
        self.socket = self.root / ('owner-' + identifier()[:8] + '.sock')
        self.admin, child = socket.socketpair()
        self.admin.settimeout(15)
        handles = []
        config = {'owner': 'user', 'workspace': 'project', 'admin_principal': 'human', 'peers': [],
                  'destinations': list(destinations or [])}
        arguments = [self.binary, 'serve', '--directory', str(self.vault),
                     '--bridge-socket', str(self.socket), '--admin-fd', str(child.fileno())]
        for flag, value in [('--seed-fd', SEED.encode()), ('--config-fd', json.dumps(config).encode())]:
            handle = tempfile.TemporaryFile(dir=self.root)
            handle.write(value)
            handle.seek(0)
            handles.append(handle)
            arguments += [flag, str(handle.fileno())]
        if create:
            arguments.append('--create')
        try:
            self.process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                pass_fds=(child.fileno(), *(h.fileno() for h in handles)))
        finally:
            child.close()
            for handle in handles:
                handle.close()
        self.output = (b'', b'')
        if registry is not None:
            registry.append(self)
        try:
            ready = framed_call(self.admin, {'op': 'status'})
            if ready.get('ok') is not True or ready.get('frozen') is not False or ready.get('clock_frozen') is not False:
                raise RuntimeError('Native owner did not become ready')
        except Exception:
            self.close()
            raise RuntimeError('Native owner startup failed') from None

    def call(self, request):
        return framed_call(self.admin, request)

    def approve(self, value):
        if self.call({'op': 'approve', 'approval': value}) != {'ok': True}:
            raise RuntimeError('Synthetic task approval refused')

    def issue(self, principal, tasks, seconds=240):
        result = self.call({'op': 'issue_session', 'principal': principal,
                            'tasks': tasks, 'expires_at': int(time.time()) + seconds})
        if not result.get('ok'):
            raise RuntimeError('Synthetic session issuance refused')
        session = result['session']
        path = self.root / ('session-' + identifier() + '.json')
        private_json(path, session)
        return path, session

    def close(self):
        if getattr(self, '_closed', False):
            return
        self._closed = True
        process = getattr(self, 'process', None)
        if process is not None and process.poll() is None:
            try:
                self.call({'op': 'shutdown'})
                process.wait(timeout=8)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                process.kill()
        if process is not None:
            self.output = process.communicate(timeout=8)
        self.admin.close()


class MCP:
    def __init__(self, binary, session_file, name='client', initialize=True, registry=None):
        self.process = subprocess.Popen([str(binary), 'mcp', '--session-file', str(session_file)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        self.sequence = 0
        self.pending = bytearray()
        self.output = (b'', b'')
        self.transcript = []
        if registry is not None:
            registry.append(self)
        if initialize:
            try:
                reply = self.rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                    'clientInfo': {'name': name, 'version': 'synthetic-check'}})
                if 'error' in reply or reply['result']['protocolVersion'] not in {'2025-11-25', '2024-11-05'}:
                    raise RuntimeError('MCP negotiation refused')
                self.notify('notifications/initialized')
            except Exception:
                self.close()
                raise

    def send(self, value):
        assert self.process.stdin is not None
        encoded = json.dumps(value).encode()
        self.transcript.append(encoded)
        self.process.stdin.write(encoded + b'\n')
        self.process.stdin.flush()

    def notify(self, method):
        self.send({'jsonrpc': '2.0', 'method': method})

    def receive(self):
        assert self.process.stdout is not None
        deadline = time.monotonic() + 15
        while b'\n' not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError('MCP response deadline exceeded')
            block = os.read(self.process.stdout.fileno(), 65536)
            if not block:
                raise RuntimeError('MCP process disconnected')
            self.pending.extend(block)
            if len(self.pending) > 262144:
                raise RuntimeError('MCP response exceeds check bound')
        line, _, tail = self.pending.partition(b'\n')
        self.pending = bytearray(tail)
        self.transcript.append(bytes(line))
        return json.loads(line)

    def rpc(self, method, parameters=None):
        self.sequence += 1
        request = {'jsonrpc': '2.0', 'id': self.sequence, 'method': method}
        if parameters is not None:
            request['params'] = parameters
        self.send(request)
        reply = self.receive()
        if reply.get('id') != self.sequence:
            raise RuntimeError('MCP response ID mismatch')
        return reply

    def call(self, name, arguments):
        reply = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        if 'error' in reply:
            raise RuntimeError('MCP protocol refused the tool request')
        result = reply['result']
        content = result.get('structuredContent')
        if content is None:
            content = json.loads(result['content'][0]['text'])
        return content

    def close(self):
        if getattr(self, '_closed', False):
            return
        self._closed = True
        if self.process.poll() is None:
            if self.process.stdin is not None:
                self.process.stdin.close()
                self.process.stdin = None
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.output = self.process.communicate(timeout=8)
