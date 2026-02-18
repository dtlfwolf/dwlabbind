"""Minimal REST API for bindconf operations."""

from __future__ import annotations

import json
import os
import tempfile
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer

from .bind_conf import (
    BindOperationError,
    BindServer,
    _write_server_xml,
    backup_named_conf,
    import_named_conf,
    initialize_named_conf,
)

_API_STATE: dict[str, object] = {
    "server": None,
    "named_conf": None,
    "xml_root": None,
}


class BindApiHandler(BaseHTTPRequestHandler):
    def _normalize_zone_name(self, value: str) -> str:
        text = (value or "").strip()
        if text.startswith('"') and text.endswith('"') and len(text) >= 2:
            text = text[1:-1]
        return text.strip().rstrip(".").lower()

    def _zone_name_from_element(self, zone_element: ET.Element) -> str:
        value_el = zone_element.find("value")
        if value_el is None or not (value_el.text or "").strip():
            raise BindOperationError(
                "INVALID_ZONE_XML",
                "Zone XML must contain <value>...</value> with zone name.",
                "Example: <zone><value>\"example.com\"</value><statements>...</statements></zone>",
                status=400,
            )
        return self._normalize_zone_name(value_el.text or "")

    def _ensure_xml_root(self) -> ET.Element:
        root = _API_STATE.get("xml_root")
        if isinstance(root, ET.Element):
            return root
        raise BindOperationError(
            "STATE_NOT_INITIALIZED",
            "No XML configuration loaded in API memory.",
            "Call /import, /initialize, or /xml/load first.",
            status=409,
        )

    def _load_xml_text_into_state(self, xml_text: str) -> ET.Element:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise BindOperationError(
                "INVALID_XML",
                f"XML parse error: {exc}",
                status=400,
            )
        _API_STATE["xml_root"] = root
        return root

    def _zones_container(self, root: ET.Element, create_if_missing: bool = False) -> ET.Element | None:
        zones = root.find("zones")
        if zones is None and create_if_missing:
            zones = ET.SubElement(root, "zones")
        return zones

    def _find_zone_element(self, root: ET.Element, zone_name: str) -> ET.Element | None:
        zones = self._zones_container(root, create_if_missing=False)
        if zones is None:
            return None
        wanted = self._normalize_zone_name(zone_name)
        for zone in zones.findall("zone"):
            try:
                current = self._zone_name_from_element(zone)
            except BindOperationError:
                continue
            if current == wanted:
                return zone
        return None

    def _parse_zone_xml(self, zone_xml: str) -> ET.Element:
        try:
            element = ET.fromstring(zone_xml)
        except ET.ParseError as exc:
            raise BindOperationError("INVALID_ZONE_XML", f"Zone XML parse error: {exc}", status=400)
        if element.tag != "zone":
            raise BindOperationError(
                "INVALID_ZONE_XML",
                "Zone XML must have <zone> as root element.",
                status=400,
            )
        self._zone_name_from_element(element)
        return element

    def _xml_to_text(self, root: ET.Element) -> str:
        return ET.tostring(root, encoding="unicode")

    def _sync_xml_from_server(self, server: BindServer) -> str:
        fd, tmp_path = tempfile.mkstemp(prefix="dwlabbind-api-", suffix=".xml")
        os.close(fd)
        try:
            _write_server_xml(server, tmp_path)
            xml_tree = ET.parse(tmp_path)
            root = xml_tree.getroot()
            _API_STATE["xml_root"] = root
            return self._xml_to_text(root)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

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

    def _send_error(self, status: int, code: str, message: str, hint: str | None = None) -> None:
        payload = {
            "status": status,
            "code": code,
            "error": message,
            "type": f"urn:dwlabbind:error:{code.lower().replace('_', '-')}",
        }
        if hint:
            payload["hint"] = hint
        self._send_json(status, payload)

    def _map_runtime_error(self, message: str) -> tuple[int, str, str | None]:
        text = (message or "").strip()
        if "named.conf.working-on already exists" in text:
            return (
                409,
                "LOCK_EXISTS",
                "If this lock is stale, retry /initialize with {\"force\": true}.",
            )
        if "named.conf missing" in text:
            return (409, "CONFIG_NOT_FOUND", None)
        if text.startswith("named-checkconf failed"):
            return (422, "VALIDATION_FAILED", None)
        if text.startswith("named-checkzone failed"):
            return (422, "ZONE_VALIDATION_FAILED", None)
        if "not found" in text:
            return (404, "NOT_FOUND", None)
        return (400, "OPERATION_FAILED", None)

    def do_POST(self) -> None:
        try:
            if self.path == "/backup":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                output = data.get("output")
                if not output:
                    self._send_error(400, "MISSING_REQUIRED_FIELD", "output is required")
                    return
                path = backup_named_conf(named_conf, output)
                self._send_json(200, {"archive": path})
                return
            if self.path == "/import":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                path = import_named_conf(named_conf)
                _API_STATE["server"] = BindServer.fromConfFile(named_conf)
                _API_STATE["named_conf"] = named_conf
                try:
                    xml_tree = ET.parse(path)
                    _API_STATE["xml_root"] = xml_tree.getroot()
                except Exception:
                    _API_STATE["xml_root"] = None
                self._send_json(200, {"xml": path})
                return
            if self.path == "/initialize":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                output = data.get("output")
                named_etc = data.get("named_etc")
                named_var = data.get("named_var")
                force = bool(data.get("force", False))
                cleanup = bool(data.get("cleanup", True))
                result = initialize_named_conf(
                    named_conf=named_conf,
                    backup_output=output,
                    named_etc=named_etc,
                    named_var=named_var,
                    force=force,
                    cleanup=cleanup,
                )
                loaded_conf = result.get("conf") or named_conf
                _API_STATE["server"] = BindServer.fromConfFile(str(loaded_conf))
                _API_STATE["named_conf"] = str(loaded_conf)
                xml_path = result.get("xml")
                if xml_path:
                    try:
                        xml_tree = ET.parse(str(xml_path))
                        _API_STATE["xml_root"] = xml_tree.getroot()
                    except Exception:
                        _API_STATE["xml_root"] = None
                self._send_json(200, result)
                return
            if self.path == "/xml/load":
                data = self._read_json()
                xml_text = data.get("xml")
                if not xml_text:
                    self._send_error(400, "MISSING_REQUIRED_FIELD", "xml is required")
                    return
                root = self._load_xml_text_into_state(str(xml_text))
                self._send_json(200, {"status": "ok", "root": root.tag})
                return
            if self.path == "/add-fixed-host":
                data = self._read_json()
                named_conf = data.get("named_conf")
                fqdn = data.get("fqdn")
                ip_address = data.get("ip")
                ttl = data.get("ttl")
                force = bool(data.get("force", False))
                if not fqdn or not ip_address:
                    self._send_error(
                        400,
                        "MISSING_REQUIRED_FIELD",
                        "fqdn and ip are required",
                    )
                    return
                server = _API_STATE.get("server")
                current_named_conf = _API_STATE.get("named_conf")
                if named_conf and (server is None or current_named_conf != named_conf):
                    server = BindServer.fromConfFile(named_conf)
                    _API_STATE["server"] = server
                    _API_STATE["named_conf"] = named_conf
                if server is None:
                    self._send_error(
                        409,
                        "STATE_NOT_INITIALIZED",
                        "No in-memory configuration loaded in API mode.",
                        "Call /import first (or provide named_conf once in /add-fixed-host).",
                    )
                    return
                result = server.add_fixed_host(
                    fqdn=fqdn,
                    ip_address=ip_address,
                    ttl=ttl,
                    force=force,
                    persist=False,
                )
                xml_text = self._sync_xml_from_server(server)
                self._send_json(
                    200,
                    {
                        **result,
                        "mode": "in-memory",
                        "named_conf": _API_STATE.get("named_conf"),
                        "xml": xml_text,
                    },
                )
                return
            if self.path == "/zone/create-minimal":
                data = self._read_json()
                named_conf = data.get("named_conf")
                domain_name = data.get("domain_name")
                dns_server = data.get("dns_server")
                base_hostname = data.get("base_hostname")
                force = bool(data.get("force", False))
                enable_allow_recursion = bool(data.get("allow_recursion", True))
                enable_allow_update = bool(data.get("allow_update", True))
                if not domain_name or not dns_server or not base_hostname:
                    self._send_error(
                        400,
                        "MISSING_REQUIRED_FIELD",
                        "domain_name, dns_server, and base_hostname are required",
                    )
                    return
                server = _API_STATE.get("server")
                current_named_conf = _API_STATE.get("named_conf")
                if named_conf and (server is None or current_named_conf != named_conf):
                    server = BindServer.fromConfFile(named_conf)
                    _API_STATE["server"] = server
                    _API_STATE["named_conf"] = named_conf
                if server is None:
                    self._send_error(
                        409,
                        "STATE_NOT_INITIALIZED",
                        "No in-memory configuration loaded in API mode.",
                        "Call /import first (or provide named_conf once in /zone/create-minimal).",
                    )
                    return
                result = server.create_zone_minimal(
                    domain_name=str(domain_name),
                    dns_server_cidr=str(dns_server),
                    base_hostname=str(base_hostname),
                    force=force,
                    enable_allow_recursion=enable_allow_recursion,
                    enable_allow_update=enable_allow_update,
                )
                xml_text = self._sync_xml_from_server(server)
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "action": "create-minimal",
                        "mode": "in-memory",
                        "named_conf": _API_STATE.get("named_conf"),
                        "xml": xml_text,
                        **result,
                    },
                )
                return
            if self.path == "/zone/create":
                data = self._read_json()
                root = self._ensure_xml_root()
                zone_xml = data.get("zone_xml")
                if not zone_xml:
                    self._send_error(400, "MISSING_REQUIRED_FIELD", "zone_xml is required")
                    return
                zone_element = self._parse_zone_xml(str(zone_xml))
                zone_name = self._zone_name_from_element(zone_element)
                existing = self._find_zone_element(root, zone_name)
                if existing is not None:
                    raise BindOperationError(
                        "ZONE_ALREADY_EXISTS",
                        f"Zone '{zone_name}' already exists.",
                        status=409,
                    )
                zones = self._zones_container(root, create_if_missing=True)
                assert zones is not None
                zones.append(zone_element)
                self._send_json(200, {"status": "ok", "action": "create", "zone": zone_name, "xml": self._xml_to_text(root)})
                return
            if self.path == "/zone/update":
                data = self._read_json()
                root = self._ensure_xml_root()
                zone_xml = data.get("zone_xml")
                if not zone_xml:
                    self._send_error(400, "MISSING_REQUIRED_FIELD", "zone_xml is required")
                    return
                zone_element = self._parse_zone_xml(str(zone_xml))
                zone_name = self._zone_name_from_element(zone_element)
                zones = self._zones_container(root, create_if_missing=False)
                if zones is None:
                    raise BindOperationError("ZONE_NOT_FOUND", f"Zone '{zone_name}' not found.", status=404)
                existing = self._find_zone_element(root, zone_name)
                if existing is None:
                    raise BindOperationError("ZONE_NOT_FOUND", f"Zone '{zone_name}' not found.", status=404)
                zone_list = zones.findall("zone")
                replace_idx = None
                for idx, item in enumerate(zone_list):
                    if item is existing:
                        replace_idx = idx
                        break
                if replace_idx is None:
                    raise BindOperationError("ZONE_NOT_FOUND", f"Zone '{zone_name}' not found.", status=404)
                zones.remove(existing)
                zones.insert(replace_idx, zone_element)
                self._send_json(200, {"status": "ok", "action": "update", "zone": zone_name, "xml": self._xml_to_text(root)})
                return
            if self.path == "/zone/delete":
                data = self._read_json()
                root = self._ensure_xml_root()
                zone_name = data.get("zone_name")
                zone_xml = data.get("zone_xml")
                if not zone_name and not zone_xml:
                    self._send_error(400, "MISSING_REQUIRED_FIELD", "zone_name or zone_xml is required")
                    return
                if not zone_name and zone_xml:
                    zone_name = self._zone_name_from_element(self._parse_zone_xml(str(zone_xml)))
                zone_name_norm = self._normalize_zone_name(str(zone_name))
                zones = self._zones_container(root, create_if_missing=False)
                if zones is None:
                    raise BindOperationError("ZONE_NOT_FOUND", f"Zone '{zone_name_norm}' not found.", status=404)
                existing = self._find_zone_element(root, zone_name_norm)
                if existing is None:
                    raise BindOperationError("ZONE_NOT_FOUND", f"Zone '{zone_name_norm}' not found.", status=404)
                zones.remove(existing)
                self._send_json(200, {"status": "ok", "action": "delete", "zone": zone_name_norm, "xml": self._xml_to_text(root)})
                return
            self._send_error(404, "NOT_FOUND", "not found")
        except json.JSONDecodeError:
            self._send_error(400, "INVALID_JSON", "invalid JSON body")
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
        except RuntimeError as exc:
            message = str(exc)
            status, code, hint = self._map_runtime_error(message)
            self._send_error(status, code, message, hint)
        except Exception as exc:
            self._send_error(500, "INTERNAL_ERROR", f"internal error: {exc}")


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), BindApiHandler)
    server.serve_forever()
