"""Synthetic native MCP privacy acceptance. Run only in the offline controller."""
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from typing import cast

from bridge_support import MCP, Owner, SEED, approval, framed_call, identifier
from https_fixture import HTTPSFixture

if os.environ.get('HOME') != '/home/tester' or os.environ.get('TMPDIR') != '/scratch':
    raise SystemExit('Use the isolated agent-program controller')
BINARY = sys.argv.pop(1)


class PrivateAcceptance(unittest.TestCase):
    # Failure diagnostics must never interpolate data received from the native processes.
    def assertEqual(self, first, second, msg=None):
        self.assertTrue(first == second, msg or 'Values differ')

    def assertNotEqual(self, first, second, msg=None):
        self.assertTrue(first != second, msg or 'Values unexpectedly equal')

    def assertIn(self, member, container, msg=None):
        self.assertTrue(member in container, msg or 'Value missing')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='private-acceptance-', dir='/scratch')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.fixture = HTTPSFixture()
        self.addCleanup(self.fixture.close)
        self.other_ca = HTTPSFixture()
        self.addCleanup(self.other_ca.close)
        self.bad_host = HTTPSFixture(san_ip='127.0.0.2')
        self.addCleanup(self.bad_host.close)
        f = self.fixture
        self.destinations = [f.destination('basic', '/basic', 'basic'),
                             f.destination('bearer', '/bearer', 'bearer'),
                             f.destination('header', '/header', {'header': {'name': 'X-API-Key'}},
                                           timeouts={'connect_ms': 1000, 'total_ms': 5000}),
                             f.destination('wrong-ca', '/ca', 'basic', ca_file=self.other_ca.cert),
                             self.bad_host.destination('wrong-host', '/host', 'basic'),
                             f.destination('redirect', '/redirect', 'basic'),
                             f.destination('redirect-target', '/redirect-target', 'basic'),
                             f.destination('drop', '/drop', 'basic')]
        self.owners, self.clients, self.protected, self.audit, self.raw_surfaces = [], [], [], [], []
        self.owner = cast(Owner, None)
        self.addCleanup(self.finish_and_scan)
        self.owner = self.start_owner()

    def start_owner(self, create=True):
        return Owner(BINARY, self.root, create=create, destinations=self.destinations, registry=self.owners)

    def finish_and_scan(self):
        errors = []
        if self.owner is not None and self.owner.process.poll() is None:
            try:
                self.collect_audit()
            except Exception:
                errors.append('audit collection')
        for client in reversed(self.clients):
            try:
                client.close()
            except Exception:
                errors.append('client cleanup')
        for owner in reversed(self.owners):
            try:
                owner.close()
            except Exception:
                errors.append('owner cleanup')
        surfaces = list(self.audit) + self.raw_surfaces
        for client in self.clients:
            surfaces.extend(client.transcript)
            surfaces.extend(client.output)
            surfaces.append(bytes(client.pending))
        for owner in self.owners:
            surfaces.extend(owner.output)
        for value in self.protected:
            for surface in surfaces:
                self.assertTrue(value not in surface, 'Protected value reached a recorded public surface')
        self.assertFalse(errors, 'Process cleanup failed')
        for owner in self.owners:
            self.assertEqual(owner.process.returncode, 0, 'Owner did not shut down cleanly')
        for client in self.clients:
            self.assertIsNotNone(client.process.returncode)

    def task(self, principal, recipients=(), origin=None):
        t = approval(principal, ['MetadataRead', 'SecretRead', 'SecretWrite', 'SecretUse',
                                 'AccessGrant', 'EntryDelete'], recipients)
        t['origin'] = origin or self.fixture.origin
        t['fields'] = ['Label', 'Username', 'Password', 'Notes', 'ApiKey']
        t['destinations'] = [d['id'] for d in self.destinations] + ['unconfigured']
        if recipients:
            t['share']['fields'] = t['fields'][:]
            t['share']['permissions'] = ['MetadataRead', 'SecretRead', 'SecretUse']
            t['share']['destinations'] = t['destinations'][:]
        self.owner.approve(t)
        return t

    def client(self, principal, tasks, seconds=240, initialize=True):
        path, session = self.owner.issue(principal, [t['id'] for t in tasks], seconds)
        client = MCP(BINARY, path, principal, initialize=initialize, registry=self.clients)
        return client, path, session

    def generate(self, client, task, kind='Login'):
        args = {'task': task['id'], 'request': identifier(), 'kind': kind}
        if kind == 'Login':
            args['username'] = 'synthetic-user'
        result = client.call('credman_generate', args)
        self.assertTrue(result.get('ok'))
        return result['receipt'], args

    def read_private(self, task, record, fields):
        result = self.owner.call({'op': 'read_secret', 'task': task['id'],
                                  'record': record['record'], 'fields': fields})
        self.assertTrue(result.get('ok'))
        self.assertEqual(result.get('permission'), 'secret.read')
        return result['fields']

    def protect(self, secret, username=None):
        encoded = secret.encode()
        self.protected.append(encoded)
        self.assertTrue(len(encoded) == 32 and all(33 <= c <= 126 for c in encoded))
        self.protected.append(('Bearer ' + secret).encode())
        if username is not None:
            self.protected.append(base64.b64encode((username + ':' + secret).encode()))
            self.protected.append(b'Basic ' + self.protected[-1])

    def share(self, client, task, record, fields, destinations):
        grant = {'recipient': 'agent-b', 'fields': fields, 'permissions': ['SecretUse'],
                 'destinations': destinations, 'expires_at': int(time.time()) + 200, 'follow_active': False}
        r = client.call('credman_mutate', {'task': task['id'], 'request': identifier(), 'mutation': {
            'Share': {'record': record['record'], 'expected': record['revision'], 'grant': grant}}})
        self.assertTrue(r.get('ok'))
        return r['receipt']

    def use(self, client, task, record, fields, destination, action='Use', request=None):
        args = {'task': task['id'], 'usage': {'request': request or identifier(),
                'record': record['record'], 'fields': fields, 'destination': destination, 'action': action}}
        return client.call('credman_use', args), args

    def denied(self, result):
        self.assertTrue(result == {'ok': False, 'error': 'access denied'}, 'Expected exact owner denial')

    def collect_audit(self):
        offset = 0
        all_events = []
        while True:
            r = self.owner.call({'op': 'audit', 'offset': offset})
            self.audit.append(json.dumps(r).encode())
            self.assertTrue(r.get('ok'))
            events = r['events']
            all_events.extend(events)
            if not r.get('has_more'):
                self.assertEqual(len(all_events), r['total'], 'Audit stream is incomplete')
                break
            self.assertTrue(events)
            offset += len(events)
        return all_events

    def test_private_generation_delegation_retry_and_revocation(self):
        ta, tb, tc = self.task('agent-a', ['agent-b']), self.task('agent-b'), self.task('agent-c')
        a, _, _ = self.client('agent-a', [ta])
        b, _, _ = self.client('agent-b', [tb])
        c, _, _ = self.client('agent-c', [tc])
        tools = a.rpc('tools/list')['result']['tools']
        self.assertEqual({t['name'] for t in tools}, {'credman_generate', 'credman_mutate', 'credman_metadata', 'credman_use'})
        login, generate = self.generate(a, ta)
        api, _ = self.generate(a, ta, 'ApiKey')
        password = self.read_private(ta, login, ['Password'])['Password']
        self.protect(password, 'synthetic-user')
        key = self.read_private(ta, api, ['ApiKey'])['ApiKey']
        self.protect(key)
        self.fixture.expect('/basic', 'Basic ' + base64.b64encode(('synthetic-user:' + password).encode()).decode())
        self.fixture.expect('/bearer', 'Bearer ' + key)
        self.denied(self.use(b, tb, login, ['Username', 'Password'], 'basic')[0])
        self.denied(self.use(c, tc, login, ['Username', 'Password'], 'basic')[0])
        shared = self.share(a, ta, login, ['Username', 'Password'], ['basic'])
        self.share(a, ta, api, ['ApiKey'], ['bearer'])
        used, use_args = self.use(b, tb, login, ['Username', 'Password'], 'basic')
        self.assertTrue(used.get('ok'))
        self.assertEqual(used['receipt']['status'], 'Accepted')
        self.assertTrue(used['receipt']['attempt'])
        bearer, _ = self.use(b, tb, api, ['ApiKey'], 'bearer')
        self.assertTrue(bearer.get('ok'))
        self.assertEqual(bearer['receipt']['status'], 'Accepted')
        self.assertEqual(self.fixture.snapshot(), [('/basic', True, True), ('/bearer', True, True)])
        self.denied(self.use(c, tc, login, ['Username', 'Password'], 'basic')[0])
        self.assertEqual(a.call('credman_generate', generate), {'ok': True, 'receipt': login})
        changed = dict(generate, username='different-user')
        self.assertFalse(a.call('credman_generate', changed).get('ok'))
        before = self.fixture.snapshot()
        revoked = a.call('credman_mutate', {'task': ta['id'], 'request': identifier(), 'mutation': {
            'Revoke': {'record': login['record'], 'expected': shared['revision'], 'grant': shared['grant']}}})
        self.assertTrue(revoked.get('ok'))
        self.denied(b.call('credman_use', use_args))
        self.denied(self.use(b, tb, login, ['Username', 'Password'], 'basic')[0])
        self.assertEqual(self.fixture.snapshot(), before)
        self.collect_audit()
        a.close(); b.close(); c.close(); self.owner.close()
        self.owner = self.start_owner(create=False)
        renewed, _, _ = self.client('agent-a', [ta])
        self.assertEqual(renewed.call('credman_generate', generate), {'ok': True, 'receipt': login})
        self.assertFalse(renewed.call('credman_generate', changed).get('ok'))
        self.assertTrue(self.owner.call({'op': 'revoke_task', 'task': ta['id']}).get('ok'))
        self.denied(renewed.call('credman_generate', generate))
        self.collect_audit()

    def test_custom_header_api_key_reaches_only_the_configured_header(self):
        ta = self.task('agent-a')
        a, _, _ = self.client('agent-a', [ta])
        api, _ = self.generate(a, ta, 'ApiKey')
        key = self.read_private(ta, api, ['ApiKey'])['ApiKey']
        self.protect(key)
        self.fixture.expect('/header', key, header='X-API-Key')
        used, _ = self.use(a, ta, api, ['ApiKey'], 'header')
        self.assertTrue(used.get('ok'))
        self.assertEqual(used['receipt']['status'], 'Accepted')
        self.assertEqual(self.fixture.snapshot(), [('/header', True, True)])
        self.assertEqual(self.fixture.present[-1] & {'authorization', 'x-api-key'}, {'x-api-key'})
        self.collect_audit()

    def test_authority_import_unsupported_and_session_boundaries(self):
        ta, tb, other = self.task('agent-a', ['agent-b']), self.task('agent-b'), self.task('agent-a')
        a, path, _ = self.client('agent-a', [ta])
        b, _, _ = self.client('agent-b', [tb])
        record, _ = self.generate(a, ta)
        secret = self.read_private(ta, record, ['Password'])['Password']
        self.protect(secret, 'synthetic-user')
        self.fixture.expect('/basic', 'Basic ' + base64.b64encode(('synthetic-user:' + secret).encode()).decode())
        shared = self.share(a, ta, record, ['Username', 'Password'], ['basic'])
        before = self.fixture.snapshot()
        self.denied(self.use(a, other, record, ['Username', 'Password'], 'basic')[0])
        self.denied(self.use(b, tb, record, ['Password'], 'basic')[0])
        self.denied(self.use(b, tb, record, ['Username', 'Password'], 'bearer')[0])
        state_before = (self.owner.vault / 'state.v2').read_bytes()
        self.collect_audit()
        for action in ['Login', 'Register']:
            result, _ = self.use(b, tb, record, ['Username', 'Password'], 'basic', action)
            self.assertTrue(not result.get('ok') or result.get('receipt', {}).get('status') == 'HumanRequired')
        result, _ = self.use(a, ta, record, ['Username', 'Password'], 'unconfigured')
        self.assertFalse(result.get('ok'))
        self.assertEqual(self.fixture.snapshot(), before)
        self.collect_audit()
        self.assertEqual((self.owner.vault / 'state.v2').read_bytes(), state_before,
                         'Unsupported call changed durable state')
        read = a.rpc('tools/call', {'name': 'credman_read', 'arguments': {'task': ta['id'], 'record': record['record'], 'fields': ['Password']}})
        self.assertTrue('error' in read or read.get('result', {}).get('isError'))
        forged = a.rpc('tools/call', {'name': 'credman_metadata', 'arguments': {'task': ta['id'], 'record': record['record'], 'fields': ['Username'], 'admin': True, 'principal': 'human'}})
        self.assertTrue('error' in forged or forged.get('result', {}).get('isError'))
        marker = 'MODEL-INPUT-ATTACK-MARKER'
        self.assertNotEqual(marker, secret)
        for mutation in [{'Create': {'kind': 'Login', 'values': {'Username': 'attacker', 'Password': marker}}},
                         {'Patch': {'record': record['record'], 'expected': shared['revision'], 'values': {'Password': marker}}}]:
            result = a.rpc('tools/call', {'name': 'credman_mutate', 'arguments': {'task': ta['id'], 'request': identifier(), 'mutation': mutation}})
            self.assertTrue('error' in result or result.get('result', {}).get('isError') or not result.get('result', {}).get('structuredContent', {}).get('ok'))
        _, raw_session = self.owner.issue('agent-a', [ta['id']])
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(15)
            channel.connect(raw_session['socket'])
            self.assertEqual(framed_call(channel, {'op': 'attach', 'token': raw_session['token']}), {'ok': True},
                             'Raw session attachment failed')

            class RecordedChannel:
                def __init__(self, channel, surfaces):
                    self.channel = channel
                    self.sent, self.received = bytearray(), bytearray()
                    surfaces.extend([self.sent, self.received])

                def sendall(self, data):
                    self.sent.extend(data)
                    self.channel.sendall(data)

                def recv(self, size):
                    data = self.channel.recv(size)
                    self.received.extend(data)
                    return data

            raw_state = (self.owner.vault / 'state.v2').read_bytes()
            raw_requests = [
                {'op': 'read', 'task': ta['id'], 'record': record['record'], 'fields': ['Password']},
                {'op': 'mutate', 'task': ta['id'], 'request': identifier(), 'mutation':
                 {'Create': {'kind': 'Login', 'values': {'Username': 'attacker', 'Password': marker}}}},
                {'op': 'mutate', 'task': ta['id'], 'request': identifier(), 'mutation':
                 {'Patch': {'record': record['record'], 'expected': shared['revision'], 'values': {'Password': marker}}}},
                {'op': 'import_secret', 'task': ta['id'], 'request': identifier(), 'kind': 'ApiKey', 'values': {'ApiKey': marker}},
                {'op': 'read_secret', 'task': ta['id'], 'record': record['record'], 'fields': ['Password']},
            ]
            for index, request in enumerate(raw_requests):
                try:
                    result = framed_call(RecordedChannel(channel, self.raw_surfaces), request)
                except Exception:
                    raise AssertionError('Raw owner request failed at transport') from None
                self.assertFalse(result.get('ok'), 'Raw owner request unexpectedly succeeded')
                self.assertTrue('fields' not in result, 'Raw owner response disclosed fields')
                if index == 0:
                    self.assertEqual(result, {'ok': False, 'error': 'invalid request'})
                elif index < 3:
                    self.denied(result)
            self.assertEqual((self.owner.vault / 'state.v2').read_bytes(), raw_state,
                             'Raw owner request changed durable state')
            self.assertEqual(self.owner.call({'op': 'status'}), {'ok': True}, 'Owner did not remain healthy')
        canary = 'synthetic-import-canary-not-generated'
        self.protected.extend([canary.encode(), ('Bearer ' + canary).encode()])
        imported = self.owner.call({'op': 'import_secret', 'task': ta['id'], 'request': identifier(), 'kind': 'ApiKey', 'values': {'ApiKey': canary}})
        self.assertTrue(imported.get('ok'))
        readback = self.read_private(ta, imported['receipt'], ['ApiKey'])
        self.assertTrue(readback['ApiKey'] == canary)
        agent_import = a.rpc('tools/call', {'name': 'credman_import_secret', 'arguments': {'task': ta['id'], 'request': identifier(), 'kind': 'ApiKey', 'values': {'ApiKey': marker}}})
        self.assertTrue('error' in agent_import or agent_import.get('result', {}).get('isError'))
        replay = MCP(BINARY, path, initialize=False); self.clients.append(replay)
        with self.assertRaises((RuntimeError, OSError)):
            replay.rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'replay', 'version': '1'}})
        unsafe_path, _ = self.owner.issue('agent-a', [ta['id']]); unsafe_path.chmod(0o644)
        unsafe = MCP(BINARY, unsafe_path, initialize=False); self.clients.append(unsafe)
        with self.assertRaises((RuntimeError, OSError)):
            unsafe.rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'unsafe', 'version': '1'}})
        active, _, _ = self.client('agent-a', [ta], seconds=2)
        args = {'task': ta['id'], 'record': record['record'], 'fields': ['Username']}
        self.assertTrue(active.call('credman_metadata', args).get('ok'))
        time.sleep(2.1)
        try:
            reply = active.rpc('tools/call', {'name': 'credman_metadata', 'arguments': args})
        except (RuntimeError, OSError):
            pass
        else:
            value = reply.get('error') or reply.get('result', {}).get('structuredContent', {})
            self.assertNotEqual(value, {'ok': False, 'error': 'access denied'})
            self.assertFalse(value.get('ok'))
            text = json.dumps(value).lower()
            self.assertTrue('transport' in text or 'unknown' in text, 'Disconnect must differ from denial')
        self.collect_audit()

    def test_tls_verification_redirect_and_unknown_no_retry(self):
        ta = self.task('agent-a')
        a, _, _ = self.client('agent-a', [ta])
        record, _ = self.generate(a, ta)
        password = self.read_private(ta, record, ['Password'])['Password']
        self.protect(password, 'synthetic-user')
        auth = 'Basic ' + base64.b64encode(('synthetic-user:' + password).encode()).decode()
        for path in ['/ca', '/host', '/redirect', '/drop']:
            self.fixture.expect(path, auth)
        for dest in ['wrong-ca']:
            before = self.fixture.snapshot()
            tls_before = self.fixture.tls_failures
            result, _ = self.use(a, ta, record, ['Username', 'Password'], dest)
            self.assertNotEqual(result, {'ok': False, 'error': 'access denied'})
            self.assertTrue(result.get('ok'))
            self.assertEqual(result['receipt']['status'], 'Unknown')
            self.assertEqual(self.fixture.snapshot(), before)
            self.assertTrue(self.fixture.wait_tls_failure(tls_before))
        host_task = self.task('host-agent', origin=self.bad_host.origin)
        host_client, _, _ = self.client('host-agent', [host_task])
        host_record, _ = self.generate(host_client, host_task)
        host_secret = self.read_private(host_task, host_record, ['Password'])['Password']
        self.protect(host_secret, 'synthetic-user')
        self.bad_host.expect('/host', 'Basic ' + base64.b64encode(('synthetic-user:' + host_secret).encode()).decode())
        host_tls_before = self.bad_host.tls_failures
        host_result, _ = self.use(host_client, host_task, host_record, ['Username', 'Password'], 'wrong-host')
        self.assertTrue(host_result.get('ok'))
        self.assertEqual(host_result['receipt']['status'], 'Unknown')
        self.assertEqual(self.bad_host.snapshot(), [])
        self.assertTrue(self.bad_host.wait_tls_failure(host_tls_before))
        result, _ = self.use(a, ta, record, ['Username', 'Password'], 'redirect')
        self.assertTrue(result.get('ok'))
        self.assertIn(result['receipt']['status'], ['Rejected', 'HumanRequired', 'Unknown'])
        self.assertEqual(self.fixture.snapshot(), [('/redirect', True, True)])
        result, args = self.use(a, ta, record, ['Username', 'Password'], 'drop')
        self.assertTrue(result.get('ok'))
        self.assertEqual(result['receipt']['status'], 'Unknown')
        before = self.fixture.snapshot()
        self.assertEqual(before[-1], ('/drop', True, True))
        self.assertEqual(a.call('credman_use', args), result)
        self.assertEqual(self.fixture.snapshot(), before)
        self.collect_audit()

    def test_offline_backup_restore_and_human_reauthorization(self):
        task = self.task('a')
        a, _, _ = self.client('a', [task])
        record, _ = self.generate(a, task)
        original = self.read_private(task, record, ['Username', 'Password'])
        self.protect(original['Password'], original['Username'])
        self.collect_audit()
        a.close()
        self.owner.close()

        def offline(directory, operation, secret, backup=None):
            with ExitStack() as stack:
                def descriptor(value):
                    handle = stack.enter_context(tempfile.TemporaryFile(dir=self.root))
                    handle.write(value)
                    handle.seek(0)
                    return handle

                seed = descriptor(SEED.encode())
                identity = descriptor(json.dumps({'owner': 'user', 'principal': 'human',
                                                  'workspace': 'project'}).encode())
                key = descriptor(secret)
                payload = descriptor(backup or b'')
                handles = [seed, identity, key, payload]
                command = [BINARY, 'admin', '--directory', str(directory),
                           '--seed-fd', str(seed.fileno()), '--identity-fd', str(identity.fileno()),
                           operation, '--secret-fd', str(key.fileno()), '--passphrase',
                           '--output-fd' if operation == 'backup' else '--backup-fd', str(payload.fileno())]
                result = subprocess.run(command, pass_fds=[h.fileno() for h in handles],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
                self.raw_surfaces.extend([result.stdout, result.stderr])
                self.assertEqual(result.returncode, 0, 'Offline administration failed')
                self.assertEqual(result.stdout, b'')
                payload.seek(0)
                return payload.read()

        secret = b'synthetic offline backup passphrase'
        backup = offline(self.owner.vault, 'backup', secret)
        self.assertTrue(backup.startswith(b'CMABAK02'))
        self.assertTrue(original['Password'].encode() not in backup)
        target = self.root / 'restored'
        target.mkdir(mode=0o700)
        offline(target, 'restore', secret, backup)
        self.owner = Owner(BINARY, self.root, create=False, vault=target,
                           destinations=self.destinations, registry=self.owners)
        # Restore revokes old approvals, even for private human reads.
        denied = self.owner.call({'op': 'read_secret', 'task': task['id'],
                                  'record': record['record'], 'fields': ['Password']})
        self.assertFalse(denied.get('ok'))
        human = self.task('human')
        renewed = self.task('a')
        grant = {'recipient': 'a', 'fields': ['Username', 'Password'],
                 'permissions': ['SecretRead'], 'destinations': [],
                 'expires_at': int(time.time()) + 200, 'follow_active': False}
        shared = self.owner.call({'op': 'mutate', 'task': human['id'], 'request': identifier(),
                                  'mutation': {'Share': {'record': record['record'],
                                                        'expected': record['revision'], 'grant': grant}}})
        self.assertTrue(shared.get('ok'), 'Human could not reauthorize restored credentials')
        self.assertEqual(self.read_private(renewed, record, ['Username', 'Password']), original)


class OfflineDescriptorAcceptance(unittest.TestCase):
    def test_admin_closes_unlisted_descriptors_before_reading_seed(self):
        with tempfile.TemporaryDirectory(dir='/scratch') as directory, ExitStack() as stack:
            root = Path(directory)
            root.chmod(0o700)

            def descriptor(value):
                handle = stack.enter_context(tempfile.TemporaryFile(dir=root))
                handle.write(value)
                handle.seek(0)
                return handle

            identity = descriptor(json.dumps({'owner': 'user', 'principal': 'human',
                                              'workspace': 'project'}).encode())
            secret = descriptor(b'synthetic backup passphrase')
            output = descriptor(b'')
            seed_read, seed_write = os.pipe()
            extra_read, extra_write = os.pipe()
            process = None
            try:
                command = [BINARY, 'admin', '--directory', str(root),
                           '--seed-fd', str(seed_read), '--identity-fd', str(identity.fileno()),
                           'backup', '--passphrase', '--secret-fd', str(secret.fileno()),
                           '--output-fd', str(output.fileno())]
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           pass_fds=[seed_read, extra_write, identity.fileno(),
                                                     secret.fileno(), output.fileno()])
                os.close(extra_write)
                extra_write = None
                # EOF proves the live child released its inherited pipe writer.
                ready = select.select([extra_read], [], [], 3)[0]
                closed = bool(ready) and os.read(extra_read, 1) == b''
                still_waiting_for_seed = process.poll() is None
                os.write(seed_write, SEED.encode())
                os.close(seed_write)
                seed_write = None
                stdout, stderr = process.communicate(timeout=15)
                self.assertTrue(closed and still_waiting_for_seed,
                                'Unlisted descriptor remained open while waiting for seed')
                self.assertEqual(stdout, b'')
                self.assertNotIn(SEED.encode(), stderr)
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)
                for fd in [seed_read, seed_write, extra_read, extra_write]:
                    if fd is not None:
                        os.close(fd)


if __name__ == '__main__':
    unittest.main()
