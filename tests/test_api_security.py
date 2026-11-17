"""Fail-closed authorization independent of route and other server instances."""

from contextlib import contextmanager
import http.client
import json
from threading import Thread

import pytest

from dwlabbind.api import BindApiContext, BindHttpServer


class ApiHost:
    def __init__(self, token="test-token") -> None:
        self.context = BindApiContext(token)
        self.server = BindHttpServer(("127.0.0.1", 0), self.context)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    @contextmanager
    def running(self):
        self.thread.start()
        try:
            yield self
        finally:
            self.server.shutdown()
            self.thread.join(timeout=5)
            self.server.server_close()

    def request(self, method, path, token=None, payload=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            connection.request(method, path, body="NOT_JSON" if payload is None else json.dumps(payload), headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()


@pytest.mark.parametrize("method,path", [
    ("GET", "/v1/installation"), ("GET", "/v1/installation/validate/additive"),
    ("GET", "/v1/rpz/policies"), ("GET", "/v1/rpz/policies/test/rules"),
    ("GET", "/v1/server/listener"), ("POST", "/backup"), ("POST", "/restore"),
    ("POST", "/import"), ("POST", "/initialize"), ("POST", "/v1/zones"),
    ("POST", "/fixed-host-add"), ("POST", "/fixed-host-delete"),
    ("PATCH", "/v1/rpz/policies/test/rules/host"),
    ("PUT", "/v1/server/listener"), ("DELETE", "/v1/server/listener"),
    ("DELETE", "/v1/zones/test"), ("DELETE", "/v1/rpz/policies/test/rules/host"),
])
@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_every_route_rejects_before_body_or_filesystem_access(method, path, token):
    with ApiHost().running() as host:
        status, body = host.request(method, path, token)
        assert status == 401
        assert body["code"] == "UNAUTHORIZED"
        assert host.context.state["server"] is None


@pytest.mark.parametrize("token", [None, "", "bad token", "bad\ntoken"])
def test_missing_or_invalid_policy_rejected_before_binding(token):
    with pytest.raises(ValueError, match="--api-token is required"):
        BindApiContext(token)


def test_servers_have_independent_state_and_credentials():
    with ApiHost("first-token").running() as first:
        with ApiHost("second-token").running() as second:
            first.context.state["named_main"] = "/first/named.conf"
            assert second.context.state["named_main"] == "/etc/bind/named.conf"
            assert first.request("GET", "/unknown", "first-token")[0] == 404
            assert second.request("GET", "/unknown", "first-token")[0] == 401
            assert second.request("GET", "/unknown", "second-token")[0] == 404


@pytest.mark.parametrize("field", ["named_conf", "named_etc", "named_var", "allow_legacy"])
def test_restore_http_cannot_override_server_owned_roots(field):
    with ApiHost().running() as host:
        status, body = host.request("POST", "/restore", "test-token", {field: "/etc/cron.d", "archive": "/missing"})
        assert status == 400
        assert body["code"] == "RESTORE_SCOPE_OVERRIDE"
