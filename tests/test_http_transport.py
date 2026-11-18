"""BIND's actual adapter must inherit the bounded transport and retain auth."""
import http.client
import socket
from threading import Thread

import pytest
from dwlabbasicpy.http_transport import HttpTransportLimits
from dwlabbind.api import BindApiContext, BindHttpServer


@pytest.fixture
def server(tmp_path):
    state = tmp_path / "dns.yaml"
    state.write_text("schema_version: dwlabbind/v1\nserver:\n  name: test-dns\nzones: []\nviews: []\ntsig_keys: []\nresponse_policies: []\n")
    instance = BindHttpServer(("127.0.0.1", 0), BindApiContext("token", state={"desired_state_path": str(state)}),
                              transport_limits=HttpTransportLimits(body_timeout=0.3, header_timeout=0.3))
    thread = Thread(target=instance.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()
    thread.join(timeout=3)


@pytest.mark.parametrize("header,status", [(b"Content-Length: -1", 400),
                                          (b"Content-Length: 65537", 413),
                                          (b"Content-Length: 2\r\nContent-Length: 2", 400),
                                          (b"Transfer-Encoding: chunked", 400)])
def test_adapter_rejects_bad_framing(server, header, status):
    peer = socket.create_connection(server.server_address, timeout=2)
    peer.sendall(b"POST /v1/zones HTTP/1.0\r\nAuthorization: Bearer token\r\n" + header + b"\r\n\r\n")
    response = http.client.HTTPResponse(peer)
    response.begin()
    assert response.status == status
    response.read()
    peer.close()
    assert server.context.state["server"] is None


def test_slow_upload_does_not_block_authorized_inspection(server):
    peer = socket.create_connection(server.server_address, timeout=2)
    peer.sendall(b"POST /v1/zones HTTP/1.0\r\nAuthorization: Bearer token\r\nContent-Length: 8\r\n\r\nx")
    connection = http.client.HTTPConnection(*server.server_address, timeout=2)
    connection.request("GET", "/v1/server/listener", headers={"Authorization": "Bearer token"})
    response = connection.getresponse()
    assert response.status == 200
    response.read()
    connection.close()
    response = http.client.HTTPResponse(peer)
    response.begin()
    assert response.status == 408
    response.read()
    peer.close()
