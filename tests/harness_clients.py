"""Installed-harness connection probes, run only inside check-harnesses.py's namespace."""
import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time

from bridge_support import Owner, approval

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from examples.harness_config import HARNESSES, configuration

if os.environ.get('HOME') != '/home/tester' or os.environ.get('TMPDIR') != '/scratch':
    raise SystemExit('Use scripts/check-harnesses.py')


def codex_discovery(environment):
    process = subprocess.Popen(['/opt/codex', 'app-server'], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    pending = bytearray()

    def rpc(number, method, params):
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(json.dumps({'id': number, 'method': method, 'params': params}).encode() + b'\n')
        process.stdin.flush()
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if b'\n' not in pending:
                if not select.select([process.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
                    break
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                pending.extend(block)
                if len(pending) > 1024 * 1024:
                    raise RuntimeError('Codex RPC response exceeds probe bound')
            while b'\n' in pending:
                line, _, tail = pending.partition(b'\n')
                pending[:] = tail
                value = json.loads(line)
                if value.get('id') == number:
                    return value
        raise RuntimeError('Codex MCP discovery deadline/disconnection')

    try:
        initialized = rpc(1, 'initialize', {'clientInfo': {'name': 'credman_probe', 'version': '1'},
                                           'capabilities': {'experimentalApi': True}})
        if 'error' in initialized:
            return {'connected': False, 'stage': 'app-server initialize', 'reply': initialized}
        assert process.stdin is not None
        process.stdin.write(b'{"method":"initialized"}\n')
        process.stdin.flush()
        reply = rpc(2, 'mcpServerStatus/list', {'serverName': 'credman', 'detail': 'toolsAndAuthOnly'})
        names = {'credman_generate', 'credman_mutate', 'credman_metadata', 'credman_use'}
        servers = [s for s in reply.get('result', {}).get('data', []) if s.get('name') == 'credman']
        connected = len(servers) == 1 and set(servers[0].get('tools', {})) == names and not servers[0].get('toolsError')
        return {'connected': 'error' not in reply and connected,
                'stage': 'native app-server MCP tool discovery', 'reply': reply}
    finally:
        process.kill()
        process.communicate(timeout=5)


def opencode_discovery(environment, token):
    """OpenCode credential use is unsupported; report the capability without launching a client."""
    return {'connected': False, 'status': 'incomplete',
            'stage': 'OpenCode compatibility incomplete',
            'reason': 'Native MCP connection, exact tool discovery and invocation are unverified.'}


def run(selected):
    with tempfile.TemporaryDirectory(prefix='harness-bridge-', dir='/scratch') as directory:
        root = Path(directory)
        root.chmod(0o700)
        owner = Owner('/opt/credman', root)
        results = []
        try:
            for harness in selected:
                home = Path('/home/tester') / harness
                home.mkdir(mode=0o700)
                task = approval('probe-' + harness, ['MetadataRead'])
                owner.approve(task)
                session_file, session = owner.issue('probe-' + harness, [task['id']])
                fragment = configuration(harness, '/opt/credman', session_file)
                environment = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                    XDG_CACHE_HOME=str(home / '.cache'), XDG_DATA_HOME=str(home / '.local/share'),
                    XDG_STATE_HOME=str(home / '.local/state'),
                    NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
                entry = {'harness': harness, 'provider_egress': False, 'model_call': False,
                         'configured': False, 'connected': False}
                try:
                    if harness == 'opencode':
                        entry.update(opencode_discovery(environment, session['token']))
                        results.append(entry)
                        continue
                    if harness != 'hermes':
                        executable = {'codex': 'codex', 'claude-code': 'claude',
                                      'grok-build': 'grok', 'opencode': 'opencode'}[harness]
                        version = subprocess.run(['/opt/' + executable, '--version'], env=environment,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
                        entry['version'] = version.stdout.strip() if version.returncode == 0 else 'unavailable'
                    if harness == 'codex':
                        target = home / '.codex/config.toml'
                        target.parent.mkdir(mode=0o700, exist_ok=True)
                        target.write_text(fragment)
                        environment['CODEX_HOME'] = str(target.parent)
                        entry['configured'] = True
                        entry.update(codex_discovery(environment))
                        results.append(entry)
                        continue
                    if harness == 'claude-code':
                        config = json.loads(fragment)['mcpServers']['credman']
                        added = subprocess.run(['/opt/claude', 'mcp', 'add-json', '--scope', 'user',
                            'credman', json.dumps(config)], env=environment, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=35)
                        if added.returncode != 0:
                            entry.update({'stage': 'native config registration', 'exit_code': added.returncode,
                                          'diagnostics': added.stderr[-3000:]})
                            results.append(entry)
                            continue
                        command = ['/opt/claude', 'mcp', 'get', 'credman']
                    elif harness == 'grok-build':
                        target = home / '.grok/config.toml'
                        target.parent.mkdir(mode=0o700, exist_ok=True)
                        target.write_text(fragment)
                        environment['GROK_HOME'] = str(target.parent)
                        command = ['/opt/grok', 'mcp', 'doctor', 'credman', '--json']
                    else:
                        target = home / '.hermes/config.yaml'
                        target.parent.mkdir(mode=0o700, exist_ok=True)
                        target.write_text(fragment)
                        environment['HERMES_HOME'] = str(target.parent)
                        environment['HERMES_CONFIG_PATH'] = str(target)
                        environment['PYTHONPATH'] = '/opt/hermes'
                        command = [sys.executable, '-B', '-c',
                            'from argparse import Namespace; from hermes_cli.mcp_config import cmd_mcp_test; '
                            'raise SystemExit(cmd_mcp_test(Namespace(name="credman")))']
                    entry['configured'] = True
                    result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                        capture_output=True, text=True, timeout=45)
                    output = result.stdout + result.stderr
                    if session['token'] in output:
                        entry.update({'stage': 'secret-output check', 'error': 'Attachment credential echoed'})
                    else:
                        if harness == 'claude-code':
                            connected = any(line.strip() in {'Status: ✔ Connected', 'Status: ✓ Connected', 'Status: Connected'}
                                            for line in output.splitlines())
                        elif harness == 'grok-build':
                            health = json.loads(result.stdout)
                            servers = [s for s in health.get('servers', []) if s.get('name') == 'credman']
                            connected = health.get('healthy_count') == 1 and health.get('failing_count') == 0 and len(servers) == 1
                            connected = connected and servers[0].get('healthy') is True and any(
                                c.get('label') == '4 tools discovered' and c.get('passed') is True
                                for c in servers[0].get('checks', []))
                        else:
                            connected = 'Connected' in output and 'Tools discovered: 4' in output
                        entry.update({'stage': 'native MCP connection diagnostic' if harness != 'hermes' else 'installed Hermes native MCP probe function',
                                      'exit_code': result.returncode, 'connected': result.returncode == 0 and connected,
                                      'output': output[-8000:]})
                except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
                    entry['error'] = type(error).__name__
                if session['token'] in json.dumps(entry):
                    entry = {'harness': harness, 'connected': False, 'error': 'Attachment credential echoed'}
                results.append(entry)
        finally:
            owner.close()
        return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--harness', choices=HARNESSES, action='append')
    selected = list(dict.fromkeys(parser.parse_args().harness or HARNESSES))
    results = run(selected)
    if len(results) != len(selected) or {r['harness'] for r in results} != set(selected):
        raise SystemExit('Incomplete harness matrix')
    print(json.dumps({'harnesses': results, 'all_connected': all(r['connected'] for r in results)}, indent=2))
