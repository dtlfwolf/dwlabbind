from __future__ import annotations

import http.client
import json
from pathlib import Path
import threading

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


def _request(port: int, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
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
