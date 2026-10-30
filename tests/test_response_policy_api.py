from __future__ import annotations

import http.client
import json
from pathlib import Path
import threading
from unittest.mock import Mock, patch

import pytest
import yaml
from http.server import HTTPServer

from dwlabbind import api


def _write_state(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "dwlabbind/v1",
                "server": {"name": "dns-01", "resolver_policy": {"allow_query": ["any"]}},
                "tsig_keys": [],
                "zones": [],
                "views": [],
                "response_policies": [
                    {"name": "internal-host-overrides", "zone_name": "rpz.internal.dw-lab", "enabled": True, "rules": []}
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _request(
    port: int,
    method: str,
    path: str,
    payload: dict | None = None,
    token: str | None = None,
) -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    result = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, result


def test_rpz_http_lifecycle_uses_only_the_server_configured_state_file(tmp_path: Path) -> None:
    state = tmp_path / "state.yaml"
    _write_state(state)
    api._API_STATE["desired_state_path"] = str(state)
    server = HTTPServer(("127.0.0.1", 0), api.BindApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, listed = _request(server.server_port, "GET", "/v1/rpz/policies")
        assert status == 200
        assert listed["response_policies"][0]["rules"] == []

        status, created = _request(
            server.server_port,
            "POST",
            "/v1/rpz/policies/internal-host-overrides/rules",
            {"query_name": "t-com.dw-lab.com", "action": "answer", "records": [{"type": "A", "value": "192.168.2.31"}]},
        )
        assert status == 201
        assert created["response_policies"][0]["rules"][0]["query_name"] == "t-com.dw-lab.com"

        status, updated = _request(
            server.server_port,
            "PATCH",
            "/v1/rpz/policies/internal-host-overrides/rules/t-com.dw-lab.com",
            {"action": "nxdomain", "records": []},
        )
        assert status == 200
        assert updated["response_policies"][0]["rules"][0]["action"] == "nxdomain"

        status, deleted = _request(
            server.server_port,
            "DELETE",
            "/v1/rpz/policies/internal-host-overrides/rules/t-com.dw-lab.com",
        )
        assert status == 200
        assert deleted["response_policies"][0]["rules"] == []
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
        api._API_STATE["desired_state_path"] = None


def test_rpz_http_policy_create_and_fixed_host_add_use_domain_convention(tmp_path: Path) -> None:
    state = tmp_path / "state.yaml"
    _write_state(state)
    document = yaml.safe_load(state.read_text(encoding="utf-8"))
    document["response_policies"] = []
    state.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    previous_state = dict(api._API_STATE)
    api._API_STATE.update({"desired_state_path": str(state), "api_token": "test-token"})
    server = HTTPServer(("127.0.0.1", 0), api.BindApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, created = _request(
            server.server_port,
            "POST",
            "/v1/rpz/policies",
            {"domain_name": "dw-lab.com"},
            token="test-token",
        )
        assert status == 201
        assert created["response_policies"][0]["zone_name"] == "rpz.dw-lab.com-overrides"

        status, updated = _request(
            server.server_port,
            "POST",
            "/v1/rpz/policies/dw-lab.com-overrides/fixed-hosts",
            {"hostname": "cmkdev", "ip_address": "192.168.2.31"},
            token="test-token",
        )
        assert status == 201
        assert updated["response_policies"][0]["rules"][0]["query_name"] == "cmkdev.dw-lab.com"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
        api._API_STATE.clear()
        api._API_STATE.update(previous_state)


def test_listener_policy_http_lifecycle_uses_the_desired_state_file(tmp_path: Path) -> None:
    state = tmp_path / "state.yaml"
    _write_state(state)
    previous_state = dict(api._API_STATE)
    api._API_STATE.update({"desired_state_path": str(state), "api_token": "test-token"})
    server = HTTPServer(("127.0.0.1", 0), api.BindApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, initial = _request(server.server_port, "GET", "/v1/server/listener")
        assert status == 200
        assert initial["listener_policy"] is None

        status, updated = _request(
            server.server_port,
            "PUT",
            "/v1/server/listener",
            {"ipv4": {"addresses": ["127.0.0.1", "192.168.2.30"]}, "ipv6": {"addresses": []}},
            token="test-token",
        )
        assert status == 200
        assert updated["listener_policy"]["ipv4"]["addresses"] == ["127.0.0.1", "192.168.2.30"]

        status, cleared = _request(server.server_port, "DELETE", "/v1/server/listener", token="test-token")
        assert status == 200
        assert cleared["listener_policy"] is None
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
        api._API_STATE.clear()
        api._API_STATE.update(previous_state)


def test_fixed_host_http_routes_use_the_renamed_contract() -> None:
    bind_server = Mock()
    bind_server.add_fixed_host.return_value = {"fqdn": "host.example.test", "ip": "192.0.2.10"}
    bind_server.delete_fixed_host.return_value = {"fqdn": "host.example.test", "ip": "192.0.2.10"}
    previous_server = api._API_STATE.get("server")
    previous_named_conf = api._API_STATE.get("named_conf")
    api._API_STATE["server"] = bind_server
    api._API_STATE["named_conf"] = "/etc/bind/named.conf"
    server = HTTPServer(("127.0.0.1", 0), api.BindApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch.object(api.BindApiHandler, "_sync_xml_from_server", return_value="<BindServer />"):
            status, created = _request(
                server.server_port,
                "POST",
                "/fixed-host-add",
                {"fqdn": "host.example.test", "ip": "192.0.2.10"},
            )
            assert status == 200
            assert created["fqdn"] == "host.example.test"

            status, deleted = _request(
                server.server_port,
                "POST",
                "/fixed-host-delete",
                {"fqdn": "host.example.test", "ip": "192.0.2.10"},
            )
            assert status == 200
            assert deleted["fqdn"] == "host.example.test"

            status, error = _request(
                server.server_port,
                "POST",
                "/add-fixed-host",
                {"fqdn": "host.example.test", "ip": "192.0.2.10"},
            )
            assert status == 404
            assert error["error"] == "not found"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
        api._API_STATE["server"] = previous_server
        api._API_STATE["named_conf"] = previous_named_conf


def test_active_zone_http_resource_uses_transactional_runtime_service_and_token(tmp_path: Path) -> None:
    previous_state = dict(api._API_STATE)
    state_file = tmp_path / "state.yaml"
    _write_state(state_file)
    api._API_STATE.update(
        {
            "api_token": "test-token",
            "desired_state_path": str(state_file),
            "releases_root": "/managed/releases",
            "runtime_root": "/managed/current",
            "named_options": "/managed/named.conf.options",
            "named_local": "/managed/named.conf.local",
            "named_main": "/managed/named.conf",
            "key_directory": "/managed/keys",
            "named_service": "bind9",
        }
    )
    server = HTTPServer(("127.0.0.1", 0), api.BindApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with patch.object(
            api.BindRuntimeService,
            "ensure_ovpn_zone",
            return_value={
                "reverse_zone": "4.8.10.in-addr.arpa",
                "dns_server_ip": "10.8.4.1",
                "key_file": "/managed/keys/ovpn.example.test.key",
            },
        ) as ensure_zone, patch.object(api.BindRuntimeService, "remove_ovpn_zone") as remove_zone:
            status, denied = _request(
                server.server_port,
                "POST",
                "/v1/zones",
                {"domain_name": "ovpn.example.test", "dns_server_cidr": "10.8.4.1/24", "base_hostname": "central"},
            )
            assert status == 401
            assert denied["code"] == "UNAUTHORIZED"

            status, created = _request(
                server.server_port,
                "POST",
                "/v1/zones",
                {"domain_name": "ovpn.example.test", "dns_server_cidr": "10.8.4.1/24", "base_hostname": "central"},
                token="test-token",
            )
            assert status == 201
            assert created["dns_server_ip"] == "10.8.4.1"
            runtime_configuration, domain_name, cidr, hostname = ensure_zone.call_args.args
            assert runtime_configuration.state_path == state_file
            assert runtime_configuration.releases_root == Path("/managed/releases")
            assert runtime_configuration.key_directory == Path("/managed/keys")
            assert (domain_name, cidr, hostname) == ("ovpn.example.test", "10.8.4.1/24", "central")

            status, deleted = _request(
                server.server_port,
                "DELETE",
                "/v1/zones/ovpn.example.test",
                token="test-token",
            )
            assert status == 200
            assert deleted["status"] == "deleted"
            runtime_configuration, domain_name = remove_zone.call_args.args
            assert runtime_configuration.state_path == state_file
            assert domain_name == "ovpn.example.test"
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
        api._API_STATE.clear()
        api._API_STATE.update(previous_state)


def test_installation_http_endpoints_are_read_only_and_validate_modes(tmp_path: Path) -> None:
    previous_state = dict(api._API_STATE)
    named_conf = tmp_path / "named.conf"
    named_conf.write_text("options {};\n", encoding="utf-8")
    api._API_STATE["named_main"] = str(named_conf)
    with patch.object(api, "_MANAGER") as manager:
        manager.list_zones_from_conf.return_value = [
            {
                "zone_name": ".",
                "zone_type": "hint",
                "file_path": "/usr/share/dns/root.hints",
                "management_state": "package-managed",
            },
            {"zone_name": "customer.example", "zone_type": "master", "file_path": "/var/lib/bind/customer.zone"},
        ]
        server = HTTPServer(("127.0.0.1", 0), api.BindApiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, inspected = _request(server.server_port, "GET", "/v1/installation")
            assert status == 200
            assert inspected["non_default_zone_count"] == 1
            assert inspected["zones"][1]["name"] == "customer.example"

            status, approved = _request(server.server_port, "GET", "/v1/installation/validate/additive")
            assert status == 200
            assert approved["status"] == "approved"

            status, rejected = _request(server.server_port, "GET", "/v1/installation/validate/new-server")
            assert status == 409
            assert rejected["code"] == "INSTALLATION_MODE_REJECTED"
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()
            api._API_STATE.clear()
            api._API_STATE.update(previous_state)


def test_serve_api_rejects_remote_listener_without_token() -> None:
    with pytest.raises(ValueError, match="--api-token is required"):
        api.serve(host="0.0.0.0")
