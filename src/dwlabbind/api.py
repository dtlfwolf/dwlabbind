"""REST API server for bind configuration management."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .models import BindServer, BindZone
from .importers import import_server_config
from .xml_store import XmlConfigStore


class BindApiHandler(BaseHTTPRequestHandler):
    store: XmlConfigStore

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return None
        try:
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _load_server(self) -> Optional[BindServer]:
        return self.store.load()

    def _save_server(self, server: BindServer) -> None:
        self.store.save(server)

    def do_GET(self) -> None:
        if self.path == "/server":
            server = self._load_server()
            if server is None:
                self._send_json({"error": "config not found"}, status=404)
                return
            self._send_json(server.to_dict())
            return
        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        if self.path == "/server":
            data = self._read_json()
            if data is None:
                self._send_json({"error": "invalid json"}, status=400)
                return
            server = BindServer.from_dict(data)
            self._save_server(server)
            self._send_json({"status": "saved"})
            return
        if self.path == "/import":
            data = self._read_json()
            if data is None:
                self._send_json({"error": "invalid json"}, status=400)
                return
            try:
                server = import_server_config(
                    server_type=data.get("server_type", "bind9"),
                    config_path=data.get("config_path", ""),
                    name=data.get("name", "imported"),
                    ip=data.get("ip", ""),
                    port=int(data.get("port", 53)),
                    role=data.get("role", "master"),
                    version=data.get("version", ""),
                )
            except (ValueError, FileNotFoundError) as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            self._save_server(server)
            self._send_json({"status": "imported", "server": server.to_dict()})
            return
        if self.path == "/zones":
            data = self._read_json()
            if data is None:
                self._send_json({"error": "invalid json"}, status=400)
                return
            server = self._load_server()
            if server is None:
                self._send_json({"error": "config not found"}, status=404)
                return
            zone = BindZone.from_dict(data)
            server.add_zone(zone)
            self._save_server(server)
            self._send_json({"status": "zone added"})
            return
        self._send_json({"error": "not found"}, status=404)

    def do_DELETE(self) -> None:
        if self.path.startswith("/zones/"):
            zone_name = self.path.split("/", 2)[2]
            server = self._load_server()
            if server is None:
                self._send_json({"error": "config not found"}, status=404)
                return
            server.remove_zone(zone_name)
            self._save_server(server)
            self._send_json({"status": "zone removed"})
            return
        self._send_json({"error": "not found"}, status=404)

    def log_message(self, format: str, *args: object) -> None:
        return


class BindApiServer:
    def __init__(self, store: XmlConfigStore, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.store = store
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None

    def start(self) -> None:
        handler = self._build_handler()
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._httpd.serve_forever()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()

    def _build_handler(self):
        store = self.store

        class _Handler(BindApiHandler):
            pass

        _Handler.store = store
        return _Handler
