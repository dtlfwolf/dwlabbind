"""Real verified TLS ingress into the authenticated local-only BIND backend."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import ssl
import subprocess
from threading import Thread

import pytest
import yaml

from dwlabbind.api import BindApiContext, BindHttpServer


class TlsIngress:
    """Isolated test gateway; not a production HTTP implementation."""

    def __init__(self, root: Path) -> None:
        self.certificate = root / "server.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(root / "server.key"), "-out", str(self.certificate)],
                       check=True, capture_output=True)
        state = root / "dns.yaml"
        state.write_text(yaml.safe_dump({"schema_version": "dwlabbind/v1", "server": {"name": "test"},
                                        "zones": [], "views": [], "tsig_keys": [], "response_policies": []}))
        self.backend = BindHttpServer(("127.0.0.1", 0), BindApiContext("test-token", state={"desired_state_path": str(state)}))
        owner = self

        class Gateway(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.client_address[0] != "127.0.0.1":
                    self.send_response(403)
                    self.end_headers()
                    return
                connection = http.client.HTTPConnection("127.0.0.1", owner.backend.server_port)
                try:
                    headers = {"Authorization": self.headers["Authorization"]} if self.headers.get("Authorization") else {}
                    connection.request("GET", self.path, headers=headers)
                    response = connection.getresponse()
                    body = response.read()
                    self.send_response(response.status)
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    connection.close()

            def log_message(self, *args):
                pass

        self.gateway = HTTPServer(("127.0.0.1", 0), Gateway)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certificate, root / "server.key")
        self.gateway.socket = context.wrap_socket(self.gateway.socket, server_side=True)

    @contextmanager
    def running(self):
        threads = [Thread(target=server.serve_forever, daemon=True) for server in (self.backend, self.gateway)]
        for thread in threads:
            thread.start()
        try:
            yield self
        finally:
            for server in (self.backend, self.gateway):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=5)

    def request(self, token=None, source="127.0.0.1", trusted=True):
        context = ssl.create_default_context(cafile=str(self.certificate)) if trusted else ssl.create_default_context()
        connection = http.client.HTTPSConnection("127.0.0.1", self.gateway.server_port,
                                                context=context, source_address=(source, 0))
        try:
            headers = {"X-Forwarded-User": "root", "X-Forwarded-For": "127.0.0.1"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            connection.request("GET", "/v1/server/listener", headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()


def test_verified_tls_ingress_preserves_authentication_and_source_restrictions(tmp_path):
    with TlsIngress(tmp_path).running() as ingress:
        status, body = ingress.request("test-token")
        assert status == 200
        assert json.loads(body)["listener_policy"] is None
        assert ingress.request()[0] == 401
        assert ingress.request("wrong")[0] == 401
        assert ingress.request("test-token", source="127.0.0.2")[0] == 403
        with pytest.raises(ssl.SSLCertVerificationError):
            ingress.request("test-token", trusted=False)
