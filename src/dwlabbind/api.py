"""Minimal REST API for bindconf operations."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Tuple

from .bind_conf import backup_named_conf, import_named_conf


class BindApiHandler(BaseHTTPRequestHandler):
    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path == "/backup":
            data = self._read_json()
            named_conf = data.get("named_conf", "/etc/bind/named.conf")
            output = data.get("output")
            if not output:
                self._send_json(400, {"error": "output is required"})
                return
            path = backup_named_conf(named_conf, output)
            self._send_json(200, {"archive": path})
            return
        if self.path == "/import":
            data = self._read_json()
            named_conf = data.get("named_conf", "/etc/bind/named.conf")
            path = import_named_conf(named_conf)
            self._send_json(200, {"xml": path})
            return
        self._send_json(404, {"error": "not found"})


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), BindApiHandler)
    server.serve_forever()
