#!/usr/bin/env python3
"""Synthetic curl/TLS seam probe. Run only through check-isolated.py."""
import base64
import json
from pathlib import Path
import re
import ssl
import subprocess
import time

from https_fixture import HTTPSFixture


def fixed_arguments():
    source = Path('/repo/src/agent_https.rs').read_text()
    launch = source.split('let mut command = Command::new("/usr/bin/curl");', 1)[1]
    launch = launch.split('.env_clear()', 1)[0]
    arrays = re.findall(r'\.args\(\[(.*?)\]\)', launch, re.S)
    assert len(arrays) == 2, 'Fixed curl argument layout changed'
    arguments = [json.loads(value) for array in arrays
                 for value in re.findall(r'"(?:[^"\\]|\\.)*"', array)]
    assert arguments[:3] == ['-q', '--config', '-'], 'Private stdin config required'
    return arguments


def classify(stderr):
    # Never return raw diagnostics, auth, response bodies, or filesystem paths.
    lowered = stderr.lower()
    categories = [name for marker, name in [
        (b'option', 'option'), (b'config', 'config'), (b'openssl', 'openssl'),
        (b'certificate', 'certificate'), (b'ca cert', 'ca_certificate'),
        (b'failed to connect', 'connect'), (b'could not resolve', 'resolve'),
        (b'initializ', 'initialization'), (b'libcrypto', 'libcrypto'),
        (b'error setting', 'setting'), (b'no such file', 'missing_file'),
        (b'timed out', 'timeout'), (b'unknown', 'unknown'),
        (b'unexpected eof', 'unexpected_tls_eof'), (b'ssl_read', 'ssl_read'),
        (b'certificate verify failed', 'certificate_verification_failed'),
    ] if marker in lowered]
    return categories or (['unclassified'] if stderr else ['none'])


def observe_accept_errors(fixture):
    errors = []
    original = fixture.server.get_request

    def observed():
        try:
            return original()
        except OSError as error:
            errors.append('ssl_error' if isinstance(error, ssl.SSLError)
                          else 'connection_reset' if isinstance(error, ConnectionResetError)
                          else 'other_os_error')
            raise

    fixture.server.get_request = observed
    return errors


def request(fixture, ca, arguments, accept_errors):
    config = ('url = ' + json.dumps(fixture.origin + '/probe') + '\n'
              'cacert = ' + json.dumps(str(ca)) + '\n'
              'user = "synthetic-user:synthetic-password"\n')
    before = len(fixture.snapshot())
    errors_before = len(accept_errors)
    tls_before = fixture.tls_failures
    result = subprocess.run(['/usr/bin/curl', *arguments, '--show-error'],
                            input=config.encode(), env={}, capture_output=True,
                            timeout=5, close_fds=True)
    if result.returncode == 60:
        deadline = time.monotonic() + 1
        while len(accept_errors) == errors_before and time.monotonic() < deadline:
            time.sleep(0.01)
    return {'exit_code': result.returncode,
            'accept_errors': accept_errors[errors_before:],
            'http_status': int(result.stdout) if re.fullmatch(rb'[0-9]{3}', result.stdout) else None,
            'http_events': len(fixture.snapshot()) - before,
            'tls_failures': fixture.tls_failures - tls_before,
            'diagnostic_classes': classify(result.stderr)}


def main():
    arguments = fixed_arguments()
    fixture = HTTPSFixture()
    wrong_ca = None
    try:
        authorization = 'Basic ' + base64.b64encode(b'synthetic-user:synthetic-password').decode()
        fixture.expect('/probe', authorization)
        accept_errors = observe_accept_errors(fixture)
        trusted = request(fixture, fixture.cert, arguments, accept_errors)
        print(json.dumps({'production_options_trusted_ca': trusted}), flush=True)
        trusted_ok = (trusted['exit_code'] == 0 and trusted['http_status'] == 200
                      and trusted['http_events'] == 1
                      and fixture.snapshot() == [('/probe', True, True)])
        if not trusted_ok:
            control = request(fixture, fixture.cert, [
                '-q', '--config', '-', '--silent', '--proxy', '', '--noproxy', '*',
                '--no-insecure', '--max-time', '2.5', '--basic',
                '--output', '/dev/null', '--write-out', '%{http_code}'], accept_errors)
            print(json.dumps({'minimal_verified_tls_control': control}), flush=True)
            # Diagnostic A/B only. Do not change the imported fixture or production TLS.
            handler = fixture.server.RequestHandlerClass
            original_end_headers = handler.end_headers

            def framed_end_headers(self):
                self.send_header('Content-Length', str(len(self.headers.get('Authorization', '').encode())))
                original_end_headers(self)

            handler.end_headers = framed_end_headers
            try:
                framed = request(fixture, fixture.cert, arguments, accept_errors)
                print(json.dumps({'content_length_only_control': framed}), flush=True)
            finally:
                handler.end_headers = original_end_headers
        wrong_ca = HTTPSFixture()
        rejected = request(fixture, wrong_ca.cert, arguments, accept_errors)
        print(json.dumps({'production_options_wrong_ca': rejected}), flush=True)
        assert rejected['exit_code'] == 60 and rejected['http_events'] == 0, 'Wrong CA was not rejected'
        assert rejected['tls_failures'] > 0, 'Wrong CA did not reach TLS verification'
        assert trusted_ok, 'Production-shaped authenticated TLS request failed'
        print('PRIVATE_HTTPS_PROBE_OK: authenticated TLS succeeds; wrong CA rejected')
    finally:
        if wrong_ca is not None:
            wrong_ca.close()
        fixture.close()


if __name__ == '__main__':
    main()
