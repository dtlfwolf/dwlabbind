"""Minimal REST API for bindconf operations."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlparse

from .bind_conf import (
    BindServerXmlSerializer,
    BindConfigurationManager,
    BindOperationError,
    BindServer,
)
from .application import BindReconciliationService
from .desired_state import BindDesiredState, DesiredStateValidationError
from .desired_state import ResponsePolicyRecord, ResponsePolicyRule
from .desired_state_io import DesiredStateFileError, YamlDesiredStateRepository
from .response_policy import ResponsePolicyAlreadyExistsError, ResponsePolicyNotFoundError, ResponsePolicyService
from .listener_policy import ListenerPolicyService
from .bind_adapters import SystemdBindServiceController
from .installation import BindInstallationError, BindInstallationInspector, BindInstallationMode
from .runtime import BindRuntimeConfiguration, BindRuntimeService

_API_STATE: dict[str, object] = {
    "server": None,
    "named_conf": None,
    "xml_root": None,
    "desired_state_path": None,
    "api_token": None,
    "releases_root": "/etc/bind/dwlab/releases",
    "runtime_root": "/etc/bind/dwlab/current",
    "named_options": "/etc/bind/named.conf.options",
    "named_local": "/etc/bind/named.conf.local",
    "named_main": "/etc/bind/named.conf",
    "key_directory": "/etc/bind/dwlab/keys",
    "named_service": "bind9",
}
_MANAGER = BindConfigurationManager()
_XML_SERIALIZER = BindServerXmlSerializer()


class BindApiHandler(BaseHTTPRequestHandler):
    def _require_mutation_authorization(self) -> None:
        token = _API_STATE.get("api_token")
        if not isinstance(token, str) or not token:
            return
        if self.headers.get("Authorization") != f"Bearer {token}":
            raise BindOperationError(
                "UNAUTHORIZED",
                "A valid bearer token is required for BIND mutations.",
                status=401,
            )

    def _create_managed_zone(self, data: dict) -> dict:
        domain_name = str(data.get("domain_name") or "").strip()
        dns_server_cidr = str(data.get("dns_server_cidr") or "").strip()
        base_hostname = str(data.get("base_hostname") or "").strip()
        if not domain_name or not dns_server_cidr or not base_hostname:
            raise BindOperationError(
                "MISSING_REQUIRED_FIELD",
                "domain_name, dns_server_cidr, and base_hostname are required",
                status=400,
            )
        return self._runtime_service().ensure_ovpn_zone(self._runtime_configuration(), domain_name, dns_server_cidr, base_hostname)

    def _delete_managed_zone(self, zone_name: str) -> dict:
        if not zone_name:
            raise BindOperationError("MISSING_REQUIRED_FIELD", "zone_name is required", status=400)
        self._runtime_service().remove_ovpn_zone(self._runtime_configuration(), zone_name)
        return {"zone_name": zone_name}

    def _runtime_service(self) -> BindRuntimeService:
        return BindRuntimeService(SystemdBindServiceController(str(_API_STATE["named_service"])))

    def _runtime_configuration(self) -> BindRuntimeConfiguration:
        return BindRuntimeConfiguration(
            state_path=Path(self._desired_state_path()),
            releases_root=Path(str(_API_STATE["releases_root"])),
            runtime_root=Path(str(_API_STATE["runtime_root"])),
            named_options=Path(str(_API_STATE["named_options"])),
            named_local=Path(str(_API_STATE["named_local"])),
            named_main=Path(str(_API_STATE["named_main"])),
            key_directory=Path(str(_API_STATE["key_directory"])),
        )

    def _installation_inspector(self) -> BindInstallationInspector:
        """Create the read-only first-install inspection service."""

        return BindInstallationInspector(_MANAGER)

    def _desired_state_path(self) -> str:
        path = _API_STATE.get("desired_state_path")
        if not isinstance(path, str) or not path:
            raise BindOperationError(
                "DESIRED_STATE_NOT_CONFIGURED",
                "Desired-state API requires a desired-state file configured when the server starts.",
                "Start with dwlabbind serve-api --desired-state /etc/dwlab/dns.yaml.",
                status=409,
            )
        return path

    @staticmethod
    def _response_policy_payload(state: BindDesiredState) -> dict:
        return {"response_policies": [policy.to_mapping() for policy in state.response_policies]}

    @staticmethod
    def _listener_policy_payload(state: BindDesiredState) -> dict:
        policy = ListenerPolicyService.get_policy(state)
        return {"listener_policy": policy.to_mapping() if policy is not None else None}

    @staticmethod
    def _listener_policy_from_payload(state: BindDesiredState, payload: dict) -> BindDesiredState:
        if not isinstance(payload, dict):
            raise DesiredStateValidationError("listener policy payload must be a mapping")
        document = state.to_mapping()
        server = document["server"]
        assert isinstance(server, dict)
        server["listener_policy"] = payload
        return BindDesiredState.from_mapping(document)

    @staticmethod
    def _rule_from_payload(data: dict) -> ResponsePolicyRule:
        records = data.get("records", [])
        if not isinstance(records, list):
            raise DesiredStateValidationError("records must be a list")
        if not all(isinstance(record, dict) for record in records):
            raise DesiredStateValidationError("records must be a list of mappings")
        return ResponsePolicyRule(
            query_name=str(data.get("query_name", "")),
            action=str(data.get("action", "answer")),
            records=tuple(
                ResponsePolicyRecord(
                    record_type=str(record.get("type", "")),
                    value=str(record.get("value", "")),
                    ttl=record.get("ttl"),
                )
                for record in records
            ),
        )

    def _load_desired_state(self) -> BindDesiredState:
        return YamlDesiredStateRepository().load(self._desired_state_path())

    def _save_desired_state(self, state: BindDesiredState) -> None:
        YamlDesiredStateRepository().save(state, self._desired_state_path())

    @staticmethod
    def _rpz_path_parts(path: str) -> list[str]:
        return [unquote(item) for item in path.strip("/").split("/") if item]

    def do_GET(self) -> None:
        try:
            parts = self._rpz_path_parts(urlparse(self.path).path)
            if parts == ["v1", "installation"]:
                inspection = self._installation_inspector().inspect(str(_API_STATE["named_main"]))
                self._send_json(200, inspection.to_mapping())
                return
            if len(parts) == 4 and parts[:3] == ["v1", "installation", "validate"]:
                inspection = self._installation_inspector().inspect(str(_API_STATE["named_main"]))
                mode = BindInstallationMode(parts[3])
                self._installation_inspector().validate_mode(mode, inspection)
                self._send_json(200, {**inspection.to_mapping(), "installation_mode": mode.value, "status": "approved"})
                return
            if parts == ["v1", "rpz", "policies"]:
                self._send_json(200, self._response_policy_payload(self._load_desired_state()))
                return
            if parts == ["v1", "server", "listener"]:
                self._send_json(200, self._listener_policy_payload(self._load_desired_state()))
                return
            if len(parts) == 5 and parts[:3] == ["v1", "rpz", "policies"] and parts[4] == "rules":
                policy = ResponsePolicyService().get_policy(self._load_desired_state(), parts[3])
                self._send_json(200, {"policy": policy.name, "rules": [rule.to_mapping() for rule in policy.rules]})
                return
            self._send_error(404, "NOT_FOUND", "not found")
        except DesiredStateFileError as exc:
            self._send_error(422, "INVALID_DESIRED_STATE_FILE", str(exc))
        except ResponsePolicyNotFoundError as exc:
            self._send_error(404, "RPZ_NOT_FOUND", str(exc))
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
        except BindInstallationError as exc:
            self._send_error(409, "INSTALLATION_MODE_REJECTED", str(exc))
        except ValueError as exc:
            self._send_error(400, "INVALID_INSTALLATION_MODE", str(exc))
        except Exception as exc:
            self._send_error(500, "INTERNAL_ERROR", f"internal error: {exc}")

    def do_PATCH(self) -> None:
        try:
            self._require_mutation_authorization()
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
            return
        self._handle_rpz_mutation("update")

    def do_PUT(self) -> None:
        try:
            self._require_mutation_authorization()
            if self._rpz_path_parts(urlparse(self.path).path) != ["v1", "server", "listener"]:
                self._send_error(404, "NOT_FOUND", "not found")
                return
            state = self._load_desired_state()
            parsed = self._listener_policy_from_payload(state, self._read_json())
            assert parsed.listener_policy is not None
            updated = ListenerPolicyService().update_policy(state, parsed.listener_policy)
            self._save_desired_state(updated)
            self._send_json(200, {"status": "ok", **self._listener_policy_payload(updated)})
        except DesiredStateValidationError as exc:
            self._send_error(400, "INVALID_LISTENER_POLICY", str(exc))
        except DesiredStateFileError as exc:
            self._send_error(422, "INVALID_DESIRED_STATE_FILE", str(exc))
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
        except Exception as exc:
            self._send_error(500, "INTERNAL_ERROR", f"internal error: {exc}")

    def do_DELETE(self) -> None:
        try:
            self._require_mutation_authorization()
            parts = self._rpz_path_parts(urlparse(self.path).path)
            if parts == ["v1", "server", "listener"]:
                updated = ListenerPolicyService().clear_policy(self._load_desired_state())
                self._save_desired_state(updated)
                self._send_json(200, {"status": "ok", **self._listener_policy_payload(updated)})
                return
            if len(parts) == 4 and parts[:3] == ["v1", "rpz", "policies"]:
                updated = ResponsePolicyService().delete_policy(self._load_desired_state(), parts[3])
                self._save_desired_state(updated)
                self._send_json(200, {"status": "deleted", **self._response_policy_payload(updated)})
                return
            if len(parts) == 3 and parts[:2] == ["v1", "zones"]:
                self._send_json(200, {"status": "deleted", **self._delete_managed_zone(parts[2])})
                return
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
            return
        self._handle_rpz_mutation("delete")

    def _handle_rpz_mutation(self, operation: str) -> None:
        try:
            parts = self._rpz_path_parts(urlparse(self.path).path)
            if len(parts) != 6 or parts[:3] != ["v1", "rpz", "policies"] or parts[4] != "rules":
                self._send_error(404, "NOT_FOUND", "not found")
                return
            state = self._load_desired_state()
            service = ResponsePolicyService()
            if operation == "delete":
                updated = service.delete_rule(state, parts[3], parts[5])
            else:
                data = self._read_json()
                data["query_name"] = parts[5]
                updated = service.update_rule(state, parts[3], self._rule_from_payload(data))
            self._save_desired_state(updated)
            self._send_json(200, {"status": "ok", **self._response_policy_payload(updated)})
        except DesiredStateValidationError as exc:
            self._send_error(400, "INVALID_RPZ_RULE", str(exc))
        except DesiredStateFileError as exc:
            self._send_error(422, "INVALID_DESIRED_STATE_FILE", str(exc))
        except ResponsePolicyNotFoundError as exc:
            self._send_error(404, "RPZ_NOT_FOUND", str(exc))
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
        except Exception as exc:
            self._send_error(500, "INTERNAL_ERROR", f"internal error: {exc}")

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
            _XML_SERIALIZER.write_server_xml(server, tmp_path)
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

    @staticmethod
    def _plan_payload(desired_state: BindDesiredState) -> dict:
        plan = BindReconciliationService(renderer=None, validator=None).plan(desired_state)  # type: ignore[arg-type]
        return {
            "can_apply": plan.can_apply,
            "issues": [
                {"code": issue.code, "message": issue.message, "severity": issue.severity}
                for issue in plan.issues
            ],
        }

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
            self._require_mutation_authorization()
            if self.path == "/v1/zones":
                self._send_json(201, {"status": "created", **self._create_managed_zone(self._read_json())})
                return
            if self.path == "/v1/rpz/policies":
                data = self._read_json()
                updated = ResponsePolicyService().create_policy(
                    self._load_desired_state(), str(data.get("domain_name", ""))
                )
                self._save_desired_state(updated)
                self._send_json(201, {"status": "created", **self._response_policy_payload(updated)})
                return
            if self.path.startswith("/v1/rpz/policies/") and self.path.endswith("/fixed-hosts"):
                parts = self._rpz_path_parts(urlparse(self.path).path)
                if len(parts) != 5 or parts[:3] != ["v1", "rpz", "policies"] or parts[4] != "fixed-hosts":
                    self._send_error(404, "NOT_FOUND", "not found")
                    return
                data = self._read_json()
                updated = ResponsePolicyService().add_fixed_host(
                    self._load_desired_state(),
                    parts[3],
                    str(data.get("hostname", "")),
                    str(data.get("ip_address", "")),
                )
                self._save_desired_state(updated)
                self._send_json(201, {"status": "created", **self._response_policy_payload(updated)})
                return
            if self.path.startswith("/v1/rpz/policies/") and self.path.endswith("/rules"):
                parts = self._rpz_path_parts(urlparse(self.path).path)
                if len(parts) != 5 or parts[:3] != ["v1", "rpz", "policies"] or parts[4] != "rules":
                    self._send_error(404, "NOT_FOUND", "not found")
                    return
                state = self._load_desired_state()
                updated = ResponsePolicyService().add_rule(state, parts[3], self._rule_from_payload(self._read_json()))
                self._save_desired_state(updated)
                self._send_json(201, {"status": "created", **self._response_policy_payload(updated)})
                return
            if self.path == "/desired-state/plan":
                data = self._read_json()
                self._send_json(200, self._plan_payload(BindDesiredState.from_mapping(data)))
                return
            if self.path == "/backup":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                output = data.get("output")
                if not output:
                    self._send_error(400, "MISSING_REQUIRED_FIELD", "output is required")
                    return
                path = _MANAGER.backup_named_conf(named_conf, output)
                self._send_json(200, {"archive": path})
                return
            if self.path == "/import":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                path = _MANAGER.import_named_conf(named_conf)
                _API_STATE["server"] = BindServer.fromConfFile(named_conf)
                _API_STATE["named_conf"] = named_conf
                try:
                    xml_tree = ET.parse(path)
                    _API_STATE["xml_root"] = xml_tree.getroot()
                except Exception:
                    _API_STATE["xml_root"] = None
                self._send_json(200, {"xml": path})
                return
            if self.path == "/restore":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                archive_path = data.get("archive")
                named_etc = data.get("named_etc")
                named_var = data.get("named_var")
                force = bool(data.get("force", False))
                result = _MANAGER.restore_named_conf(
                    named_conf=named_conf,
                    archive_path=archive_path,
                    force=force,
                    named_etc=named_etc,
                    named_var=named_var,
                )
                restored_named_conf = str(result.get("named_conf") or named_conf)
                _API_STATE["server"] = BindServer.fromConfFile(restored_named_conf)
                _API_STATE["named_conf"] = restored_named_conf
                xml_path = result.get("xml")
                if xml_path:
                    try:
                        xml_tree = ET.parse(str(xml_path))
                        _API_STATE["xml_root"] = xml_tree.getroot()
                    except Exception:
                        _API_STATE["xml_root"] = None
                self._send_json(200, result)
                return
            if self.path == "/initialize":
                data = self._read_json()
                named_conf = data.get("named_conf", "/etc/bind/named.conf")
                xml_input = data.get("xml_input")
                output = data.get("output")
                named_etc = data.get("named_etc")
                named_var = data.get("named_var")
                force = bool(data.get("force", False))
                cleanup = bool(data.get("cleanup", True))
                keep_stage_on_error = bool(data.get("keep_stage_on_error", False))
                result = _MANAGER.initialize_named_conf(
                    named_conf=named_conf,
                    xml_input=xml_input,
                    backup_output=output,
                    named_etc=named_etc,
                    named_var=named_var,
                    force=force,
                    cleanup=cleanup,
                    keep_stage_on_error=keep_stage_on_error,
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
            if self.path == "/fixed-host-add":
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
                        "Call /import first (or provide named_conf once in /fixed-host-add).",
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
            if self.path == "/fixed-host-delete":
                data = self._read_json()
                named_conf = data.get("named_conf")
                fqdn = data.get("fqdn")
                ip_address = data.get("ip")
                force = bool(data.get("force", False))
                if not fqdn:
                    self._send_error(
                        400,
                        "MISSING_REQUIRED_FIELD",
                        "fqdn is required",
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
                        "Call /import first (or provide named_conf once in /fixed-host-delete).",
                    )
                    return
                result = server.delete_fixed_host(
                    fqdn=fqdn,
                    ip_address=ip_address,
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
        except DesiredStateValidationError as exc:
            self._send_error(400, "INVALID_DESIRED_STATE", str(exc))
        except DesiredStateFileError as exc:
            self._send_error(422, "INVALID_DESIRED_STATE_FILE", str(exc))
        except ResponsePolicyAlreadyExistsError as exc:
            self._send_error(409, "RPZ_RULE_EXISTS", str(exc))
        except ResponsePolicyNotFoundError as exc:
            self._send_error(404, "RPZ_NOT_FOUND", str(exc))
        except BindOperationError as exc:
            self._send_error(exc.status, exc.code, str(exc), exc.hint)
        except RuntimeError as exc:
            message = str(exc)
            status, code, hint = self._map_runtime_error(message)
            self._send_error(status, code, message, hint)
        except Exception as exc:
            self._send_error(500, "INTERNAL_ERROR", f"internal error: {exc}")


def serve(
    host: str = "127.0.0.1",
    port: int = 8080,
    desired_state_path: str | None = None,
    *,
    api_token: str | None = None,
    releases_root: str = "/etc/bind/dwlab/releases",
    runtime_root: str = "/etc/bind/dwlab/current",
    named_options: str = "/etc/bind/named.conf.options",
    named_local: str = "/etc/bind/named.conf.local",
    named_main: str = "/etc/bind/named.conf",
    key_directory: str = "/etc/bind/dwlab/keys",
    named_service: str = "bind9",
) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"} and not api_token:
        raise ValueError("--api-token is required when serve-api listens beyond loopback.")
    _API_STATE["desired_state_path"] = desired_state_path
    _API_STATE["api_token"] = api_token
    _API_STATE["releases_root"] = releases_root
    _API_STATE["runtime_root"] = runtime_root
    _API_STATE["named_options"] = named_options
    _API_STATE["named_local"] = named_local
    _API_STATE["named_main"] = named_main
    _API_STATE["key_directory"] = key_directory
    _API_STATE["named_service"] = named_service
    server = HTTPServer((host, port), BindApiHandler)
    server.serve_forever()
