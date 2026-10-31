"""Loopback-only HTTPS test oracle. Never logs request headers or credentials."""
import http.server
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading


class HTTPSFixture:
    def __init__(self, san_ip='127.0.0.1'):
        self.temp = tempfile.TemporaryDirectory(prefix='credman-tls-', dir='/scratch')
        root = Path(self.temp.name)
        root.chmod(0o700)
        self.cert, self.key = root / 'cert.pem', root / 'key.pem'
        config = root / 'openssl.cnf'
        config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                          '[dn]\nCN=fixture\n[ext]\nsubjectAltName=IP:' + san_ip + '\n'
                          'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
        config.chmod(0o600)
        try:
            run = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                                  '-nodes', '-days', '1', '-config', str(config), '-keyout', str(self.key),
                                  '-out', str(self.cert)], env={'OPENSSL_CONF': str(config)},
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=20, check=False, umask=0o077)
            if run.returncode:
                raise RuntimeError('Synthetic certificate generation failed')
            self.key.chmod(0o600)
            self.expected = {}
            self.events = []
            self.present = []
            self.tls_failures = 0
            self.lock = threading.Lock()
            self.tls_condition = threading.Condition(self.lock)
            fixture = self

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, format, *args):
                    pass

                def handle_one_request(self):
                    try:
                        super().handle_one_request()
                    except (ssl.SSLError, ConnectionResetError, BrokenPipeError) as error:
                        # A pre-request disconnect is an abort, not proof of its cause.
                        reason = getattr(error, 'reason', None)
                        if not hasattr(self, 'raw_requestline') and (
                            isinstance(error, (ConnectionResetError, BrokenPipeError)) or reason in (
                                'TLSV1_ALERT_UNKNOWN_CA', 'SSLV3_ALERT_BAD_CERTIFICATE',
                                'SSLV3_ALERT_CERTIFICATE_UNKNOWN',
                            )
                        ):
                            with fixture.tls_condition:
                                fixture.tls_failures += 1
                                fixture.tls_condition.notify_all()
                        raise

                def do_GET(self):
                    auth = self.headers.get('Authorization', '')
                    with fixture.lock:
                        spec = fixture.expected.get(self.path)
                        if spec is None:
                            header_name, wanted = 'Authorization', None
                        else:
                            header_name, wanted = spec
                        presented = self.headers.get(header_name, '')
                        valid = wanted is not None and presented == wanted
                        fixture.events.append((self.path, bool(presented), valid))
                        fixture.present.append({name.lower() for name in self.headers.keys()})
                    if self.path == '/drop':
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    if self.path == '/redirect':
                        self.send_response(302)
                        self.send_header('Location', fixture.redirect)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    body = auth.encode()
                    self.send_response(200 if valid else 401)
                    self.send_header('X-Reflected-Authorization', auth)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            class Server(http.server.ThreadingHTTPServer):
                def handle_error(self, request, client_address):
                    pass

                def get_request(self):
                    try:
                        return super().get_request()
                    except ssl.SSLError:
                        with fixture.tls_condition:
                            fixture.tls_failures += 1
                            fixture.tls_condition.notify_all()
                        raise

            self.server = Server(('127.0.0.1', 0), Handler)
            self.server.daemon_threads = True
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(self.cert), str(self.key))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            self.redirect = self.origin + '/redirect-target'
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        except BaseException:
            self.temp.cleanup()
            raise

    @property
    def origin(self):
        return 'https://127.0.0.1:' + str(self.server.server_port)

    def destination(self, name, path, auth, origin=None, ca_file=None, timeouts=None):
        value = {'id': name, 'service': 'example-service', 'origin': origin or self.origin,
                 'path': path, 'auth': auth, 'ca_file': str(ca_file or self.cert)}
        if timeouts is not None:
            value['timeouts'] = timeouts
        return value

    def expect(self, path, authorization, header='Authorization'):
        with self.lock:
            self.expected[path] = (header, authorization)

    def snapshot(self):
        with self.lock:
            return list(self.events)

    def wait_tls_failure(self, previous, timeout=1):
        with self.tls_condition:
            return self.tls_condition.wait_for(lambda: self.tls_failures > previous, timeout)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError('HTTPS fixture did not stop')
        self.temp.cleanup()
