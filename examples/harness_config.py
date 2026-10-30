#!/usr/bin/env python3
"""Print an inert harness MCP configuration. Never edits live harness settings."""
import argparse
import json
from pathlib import Path

HARNESSES = {
    'codex': {'format': 'toml', 'source': 'https://developers.openai.com/codex/mcp'},
    'claude-code': {'format': 'json', 'source': 'https://code.claude.com/docs/en/mcp'},
    'hermes': {'format': 'yaml', 'source': 'https://hermes-agent.nousresearch.com/docs/reference/mcp-config-reference'},
    'grok-build': {'format': 'toml', 'source': 'https://docs.x.ai/build/features/mcp-servers'},
    'opencode': {'format': 'json', 'source': 'https://opencode.ai/docs/mcp-servers/'},
}


def configuration(harness, binary, session_file):
    for path in [binary, session_file]:
        if not Path(path).is_absolute() or any(c in str(path) for c in ['\x00', '\n', '\r']):
            raise ValueError('Use absolute executable and session-file paths without control separators')
    command, arguments = str(binary), ['mcp', '--session-file', str(session_file)]
    if harness in {'codex', 'grok-build'}:
        return '[mcp_servers.credman]\ncommand = ' + json.dumps(command) + '\nargs = ' + json.dumps(arguments) + '\n'
    if harness == 'claude-code':
        return json.dumps({'mcpServers': {'credman': {'type': 'stdio', 'command': command, 'args': arguments}}}, indent=2) + '\n'
    if harness == 'hermes':
        return ('mcp_servers:\n  credman:\n    command: ' + json.dumps(command) +
                '\n    args: ' + json.dumps(arguments) + '\n    sampling:\n      enabled: false\n')
    if harness == 'opencode':
        return json.dumps({'mcp': {'servers': {'credman': {'type': 'local', 'command': [command, *arguments], 'disabled': False, 'protocol': 'legacy'}}}}, indent=2) + '\n'
    raise ValueError('Unsupported harness')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('harness', choices=HARNESSES)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--session-file', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = configuration(args.harness, args.binary, args.session_file)
    except ValueError as error:
        parser.error(str(error))
    print(result, end='')


if __name__ == '__main__':
    main()
