"""Declarative, transport-independent desired state for a BIND server.

The classes in this module deliberately contain no filesystem, subprocess, or
BIND-specific rendering calls.  CLI and HTTP transports can therefore submit
the same payload to future application services.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Any, Mapping


SCHEMA_VERSION = "dwlabbind/v1"


class DesiredStateValidationError(ValueError):
    """Raised when a desired-state document is structurally invalid."""


def _require_non_empty(value: object, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise DesiredStateValidationError(f"{field_name} must not be empty")
    return text


def _as_string_tuple(values: object, field_name: str) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)):
        raise DesiredStateValidationError(f"{field_name} must be a list")
    return tuple(_require_non_empty(value, field_name) for value in values)


@dataclass(frozen=True)
class TsigKey:
    """A named TSIG key reference; secrets remain outside desired state."""

    name: str
    algorithm: str = "hmac-sha256"
    secret_reference: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_non_empty(self.name, "tsig key name"))
        object.__setattr__(self, "algorithm", _require_non_empty(self.algorithm, "tsig key algorithm"))
        object.__setattr__(
            self,
            "secret_reference",
            _require_non_empty(self.secret_reference, "tsig key secret_reference"),
        )

    def to_mapping(self) -> dict[str, str]:
        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "secret_reference": self.secret_reference,
        }


@dataclass(frozen=True)
class ResolverPolicy:
    """Controls recursive resolver access independently from authoritative zones."""

    recursion_enabled: bool = False
    allow_recursion: tuple[str, ...] = ()
    allow_query: tuple[str, ...] = ()
    forwarders: tuple[str, ...] = ()
    forward_mode: str = "first"

    def __post_init__(self) -> None:
        object.__setattr__(self, "allow_recursion", _as_string_tuple(self.allow_recursion, "allow_recursion"))
        object.__setattr__(self, "allow_query", _as_string_tuple(self.allow_query, "allow_query"))
        object.__setattr__(self, "forwarders", _as_string_tuple(self.forwarders, "forwarders"))
        if self.forward_mode not in {"first", "only"}:
            raise DesiredStateValidationError("forward_mode must be 'first' or 'only'")
        if self.recursion_enabled and not self.allow_recursion:
            raise DesiredStateValidationError("allow_recursion is required when recursion_enabled is true")
        for address in self.forwarders:
            try:
                ipaddress.ip_address(address)
            except ValueError as error:
                raise DesiredStateValidationError(f"forwarder is not an IP address: {address}") from error

    def to_mapping(self) -> dict[str, object]:
        return {
            "recursion_enabled": self.recursion_enabled,
            "allow_recursion": list(self.allow_recursion),
            "allow_query": list(self.allow_query),
            "forwarders": list(self.forwarders),
            "forward_mode": self.forward_mode,
        }


@dataclass(frozen=True)
class ListenerFamilyPolicy:
    """Explicit socket bindings for one IP address family.

    An empty ``addresses`` tuple intentionally renders ``none``.  The
    containing listener policy is optional so existing installations retain
    BIND's distribution default until an operator opts in to explicit binds.
    """

    addresses: tuple[str, ...] = ()
    port: int = 53

    def __post_init__(self) -> None:
        object.__setattr__(self, "addresses", _as_string_tuple(self.addresses, "listener addresses"))
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise DesiredStateValidationError("listener port must be an integer between 1 and 65535")
        if "any" in self.addresses and len(self.addresses) != 1:
            raise DesiredStateValidationError("listener address 'any' cannot be combined with concrete addresses")
        if len(self.addresses) != len(set(self.addresses)):
            raise DesiredStateValidationError("listener addresses must be unique")
        for address in self.addresses:
            if address == "any":
                continue
            try:
                ipaddress.ip_address(address)
            except ValueError as error:
                raise DesiredStateValidationError(
                    f"listener address is not an IP address or 'any': {address}"
                ) from error

    def to_mapping(self) -> dict[str, object]:
        return {"addresses": list(self.addresses), "port": self.port}


@dataclass(frozen=True)
class ListenerPolicy:
    """Global BIND listener configuration, independent from resolver policy."""

    ipv4: ListenerFamilyPolicy = field(default_factory=ListenerFamilyPolicy)
    ipv6: ListenerFamilyPolicy = field(default_factory=ListenerFamilyPolicy)

    def __post_init__(self) -> None:
        if not isinstance(self.ipv4, ListenerFamilyPolicy):
            raise DesiredStateValidationError("listener_policy.ipv4 must be a ListenerFamilyPolicy")
        if not isinstance(self.ipv6, ListenerFamilyPolicy):
            raise DesiredStateValidationError("listener_policy.ipv6 must be a ListenerFamilyPolicy")
        for address in self.ipv4.addresses:
            if address != "any" and ipaddress.ip_address(address).version != 4:
                raise DesiredStateValidationError(f"listener IPv4 address has the wrong address family: {address}")
        for address in self.ipv6.addresses:
            if address != "any" and ipaddress.ip_address(address).version != 6:
                raise DesiredStateValidationError(f"listener IPv6 address has the wrong address family: {address}")

    def to_mapping(self) -> dict[str, object]:
        return {"ipv4": self.ipv4.to_mapping(), "ipv6": self.ipv6.to_mapping()}


_RPZ_ACTIONS = {"answer", "nxdomain", "nodata", "passthru", "drop"}
_RPZ_RECORD_TYPES = {"A", "AAAA", "CNAME", "TXT"}
_POLICY_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _fqdn(value: object, field_name: str) -> str:
    name = _require_non_empty(value, field_name).rstrip(".").lower()
    if any(character.isspace() for character in name) or "." not in name:
        raise DesiredStateValidationError(f"{field_name} must be a fully qualified domain name")
    return name


def _domain_name(value: object, field_name: str) -> str:
    """Validate a concrete DNS domain name used to derive an RPZ policy."""
    domain_name = _fqdn(value, field_name)
    if not all(_DNS_LABEL.fullmatch(label) for label in domain_name.split(".")):
        raise DesiredStateValidationError(f"{field_name} must contain valid DNS labels")
    return domain_name


@dataclass(frozen=True)
class ResponsePolicyRecord:
    """One DNS record returned by an RPZ ``answer`` rule."""

    record_type: str
    value: str
    ttl: int | None = None

    def __post_init__(self) -> None:
        record_type = _require_non_empty(self.record_type, "response policy record type").upper()
        if record_type not in _RPZ_RECORD_TYPES:
            raise DesiredStateValidationError(f"unsupported response policy record type: {record_type}")
        value = _require_non_empty(self.value, "response policy record value")
        if record_type in {"A", "AAAA"}:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as error:
                raise DesiredStateValidationError(f"response policy {record_type} value is not an IP address: {value}") from error
            if address.version != (4 if record_type == "A" else 6):
                raise DesiredStateValidationError(f"response policy {record_type} value has the wrong address family: {value}")
        if self.ttl is not None and self.ttl <= 0:
            raise DesiredStateValidationError("response policy record ttl must be positive")
        object.__setattr__(self, "record_type", record_type)
        object.__setattr__(self, "value", value)

    def to_mapping(self) -> dict[str, object]:
        payload: dict[str, object] = {"type": self.record_type, "value": self.value}
        if self.ttl is not None:
            payload["ttl"] = self.ttl
        return payload


@dataclass(frozen=True)
class ResponsePolicyRule:
    """A declarative RPZ action for one queried DNS name."""

    query_name: str
    action: str = "answer"
    records: tuple[ResponsePolicyRecord, ...] = ()

    def __post_init__(self) -> None:
        action = _require_non_empty(self.action, "response policy rule action").lower()
        if action not in _RPZ_ACTIONS:
            raise DesiredStateValidationError(f"unsupported response policy action: {action}")
        object.__setattr__(self, "query_name", _fqdn(self.query_name, "response policy query_name"))
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "records", tuple(self.records))
        if not all(isinstance(record, ResponsePolicyRecord) for record in self.records):
            raise DesiredStateValidationError("response policy rule records must contain ResponsePolicyRecord objects")
        if action == "answer" and not self.records:
            raise DesiredStateValidationError("response policy answer rules require at least one record")
        if action != "answer" and self.records:
            raise DesiredStateValidationError(f"response policy {action} rules must not contain records")

    def to_mapping(self) -> dict[str, object]:
        return {
            "query_name": self.query_name,
            "action": self.action,
            "records": [record.to_mapping() for record in self.records],
        }


@dataclass(frozen=True)
class ResponsePolicy:
    """A named, independently managed local BIND response-policy zone."""

    name: str
    zone_name: str
    enabled: bool = True
    rules: tuple[ResponsePolicyRule, ...] = ()

    def __post_init__(self) -> None:
        name = _require_non_empty(self.name, "response policy name").lower()
        if not _POLICY_NAME.fullmatch(name):
            raise DesiredStateValidationError("response policy name must contain lowercase letters, digits, and hyphens only")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "zone_name", _fqdn(self.zone_name, "response policy zone_name"))
        object.__setattr__(self, "rules", tuple(self.rules))
        if not all(isinstance(rule, ResponsePolicyRule) for rule in self.rules):
            raise DesiredStateValidationError("response policy rules must contain ResponsePolicyRule objects")
        rule_names = [rule.query_name for rule in self.rules]
        if len(rule_names) != len(set(rule_names)):
            raise DesiredStateValidationError(f"response policy {name} rule query_names must be unique")

    @classmethod
    def for_domain(cls, domain_name: str) -> "ResponsePolicy":
        """Create the conventional customer override policy for one domain."""
        domain_name = _domain_name(domain_name, "response policy domain_name")
        return cls(
            name=f"{domain_name}-overrides",
            zone_name=f"rpz.{domain_name}-overrides",
        )

    @property
    def domain_name(self) -> str:
        """Return the domain encoded by the standard DW-Lab RPZ convention."""
        prefix = "rpz."
        suffix = "-overrides"
        if not self.zone_name.startswith(prefix) or not self.zone_name.endswith(suffix):
            raise DesiredStateValidationError(
                f"response policy {self.name} does not use the rpz.<domain>-overrides convention"
            )
        return _domain_name(self.zone_name[len(prefix) : -len(suffix)], "response policy domain_name")

    @property
    def file(self) -> str:
        """Generated relative filename; customers cannot inject arbitrary paths."""
        return f"rpz/{self.name}.zone"

    def to_mapping(self) -> dict[str, object]:
        return {
            "name": self.name,
            "zone_name": self.zone_name,
            "enabled": self.enabled,
            "rules": [rule.to_mapping() for rule in self.rules],
        }


@dataclass(frozen=True)
class Zone:
    """A DNS zone belonging either to the default server scope or one view."""

    name: str
    zone_type: str = "primary"
    file: str = ""
    dynamic_update_key: str | None = None
    primaries: tuple[str, ...] = ()
    forwarders: tuple[str, ...] = ()
    forward_mode: str = "first"
    records: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_non_empty(self.name, "zone name").rstrip(".").lower())
        if self.zone_type not in {"primary", "secondary", "forward", "hint"}:
            raise DesiredStateValidationError(f"unsupported zone_type: {self.zone_type}")
        if self.zone_type in {"primary", "secondary", "hint"}:
            object.__setattr__(self, "file", _require_non_empty(self.file, "zone file"))
        elif self.file:
            object.__setattr__(self, "file", self.file.strip())
        if self.dynamic_update_key and self.zone_type != "primary":
            raise DesiredStateValidationError("dynamic_update_key is only supported by primary zones")
        object.__setattr__(self, "primaries", _as_string_tuple(self.primaries, "zone primaries"))
        object.__setattr__(self, "forwarders", _as_string_tuple(self.forwarders, "zone forwarders"))
        if self.zone_type == "secondary" and not self.primaries:
            raise DesiredStateValidationError("secondary zones require primaries")
        if self.zone_type == "forward" and not self.forwarders:
            raise DesiredStateValidationError("forward zones require forwarders")
        if self.forward_mode not in {"first", "only"}:
            raise DesiredStateValidationError("zone forward_mode must be 'first' or 'only'")
        for address in (*self.primaries, *self.forwarders):
            try:
                ipaddress.ip_address(address)
            except ValueError as error:
                raise DesiredStateValidationError(f"zone endpoint is not an IP address: {address}") from error
        object.__setattr__(self, "records", _as_string_tuple(self.records, "zone records"))

    def to_mapping(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": self.name,
            "type": self.zone_type,
            "records": list(self.records),
        }
        if self.file:
            payload["file"] = self.file
        if self.dynamic_update_key:
            payload["dynamic_update_key"] = self.dynamic_update_key
        if self.primaries:
            payload["primaries"] = list(self.primaries)
        if self.forwarders:
            payload["forwarders"] = list(self.forwarders)
            payload["forward_mode"] = self.forward_mode
        return payload


@dataclass(frozen=True)
class View:
    """A split-horizon BIND view with explicit client matching and zones."""

    name: str
    match_clients: tuple[str, ...]
    zones: tuple[Zone, ...] = ()
    resolver_policy: ResolverPolicy = field(default_factory=ResolverPolicy)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _require_non_empty(self.name, "view name"))
        object.__setattr__(self, "match_clients", _as_string_tuple(self.match_clients, "match_clients"))
        if not self.match_clients:
            raise DesiredStateValidationError("match_clients must not be empty")
        object.__setattr__(self, "zones", tuple(self.zones))
        if not all(isinstance(zone, Zone) for zone in self.zones):
            raise DesiredStateValidationError("view zones must contain Zone objects")

    def to_mapping(self) -> dict[str, object]:
        return {
            "name": self.name,
            "match_clients": list(self.match_clients),
            "resolver_policy": self.resolver_policy.to_mapping(),
            "zones": [zone.to_mapping() for zone in self.zones],
        }


@dataclass(frozen=True)
class BindDesiredState:
    """The complete versioned desired state consumed by dwlabbind services."""

    server_name: str
    views: tuple[View, ...] = ()
    zones: tuple[Zone, ...] = ()
    tsig_keys: tuple[TsigKey, ...] = ()
    resolver_policy: ResolverPolicy = field(default_factory=ResolverPolicy)
    listener_policy: ListenerPolicy | None = None
    response_policies: tuple[ResponsePolicy, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise DesiredStateValidationError(
                f"unsupported schema_version {self.schema_version!r}; expected {SCHEMA_VERSION!r}"
            )
        object.__setattr__(self, "server_name", _require_non_empty(self.server_name, "server_name"))
        object.__setattr__(self, "views", tuple(self.views))
        object.__setattr__(self, "zones", tuple(self.zones))
        object.__setattr__(self, "tsig_keys", tuple(self.tsig_keys))
        if self.listener_policy is not None and not isinstance(self.listener_policy, ListenerPolicy):
            raise DesiredStateValidationError("listener_policy must be a ListenerPolicy or null")
        if not all(isinstance(view, View) for view in self.views):
            raise DesiredStateValidationError("views must contain View objects")
        if not all(isinstance(zone, Zone) for zone in self.zones):
            raise DesiredStateValidationError("zones must contain Zone objects")
        if not all(isinstance(key, TsigKey) for key in self.tsig_keys):
            raise DesiredStateValidationError("tsig_keys must contain TsigKey objects")
        object.__setattr__(self, "response_policies", tuple(self.response_policies))
        if not all(isinstance(policy, ResponsePolicy) for policy in self.response_policies):
            raise DesiredStateValidationError("response_policies must contain ResponsePolicy objects")
        self._validate_unique_names()

    def _validate_unique_names(self) -> None:
        view_names = [view.name.lower() for view in self.views]
        if len(view_names) != len(set(view_names)):
            raise DesiredStateValidationError("view names must be unique")
        key_names = [key.name.lower() for key in self.tsig_keys]
        if len(key_names) != len(set(key_names)):
            raise DesiredStateValidationError("TSIG key names must be unique")
        known_keys = set(key_names)
        policy_names = [policy.name for policy in self.response_policies]
        if len(policy_names) != len(set(policy_names)):
            raise DesiredStateValidationError("response policy names must be unique")
        policy_zone_names = [policy.zone_name for policy in self.response_policies]
        if len(policy_zone_names) != len(set(policy_zone_names)):
            raise DesiredStateValidationError("response policy zone names must be unique")
        for zone in (*self.zones, *(zone for view in self.views for zone in view.zones)):
            if zone.dynamic_update_key and zone.dynamic_update_key.lower() not in known_keys:
                raise DesiredStateValidationError(
                    f"zone {zone.name} references unknown TSIG key {zone.dynamic_update_key}"
                )

    def to_mapping(self) -> dict[str, object]:
        server: dict[str, object] = {
            "name": self.server_name,
            "resolver_policy": self.resolver_policy.to_mapping(),
        }
        if self.listener_policy is not None:
            server["listener_policy"] = self.listener_policy.to_mapping()
        return {
            "schema_version": self.schema_version,
            "server": server,
            "tsig_keys": [key.to_mapping() for key in self.tsig_keys],
            "zones": [zone.to_mapping() for zone in self.zones],
            "views": [view.to_mapping() for view in self.views],
            "response_policies": [policy.to_mapping() for policy in self.response_policies],
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "BindDesiredState":
        """Create desired state from a YAML/JSON-decoded mapping."""
        if not isinstance(payload, Mapping):
            raise DesiredStateValidationError("desired state must be a mapping")
        server = payload.get("server")
        if not isinstance(server, Mapping):
            raise DesiredStateValidationError("server must be a mapping")
        keys = tuple(
            TsigKey(
                name=item.get("name", ""),
                algorithm=item.get("algorithm", "hmac-sha256"),
                secret_reference=item.get("secret_reference", ""),
            )
            for item in cls._mapping_list(payload.get("tsig_keys", []), "tsig_keys")
        )
        zones = tuple(cls._zone_from_mapping(item) for item in cls._mapping_list(payload.get("zones", []), "zones"))
        views = tuple(cls._view_from_mapping(item) for item in cls._mapping_list(payload.get("views", []), "views"))
        response_policies = tuple(
            cls._response_policy_from_mapping(item)
            for item in cls._mapping_list(payload.get("response_policies", []), "response_policies")
        )
        return cls(
            schema_version=str(payload.get("schema_version", "")),
            server_name=str(server.get("name", "")),
            resolver_policy=cls._resolver_policy_from_mapping(server.get("resolver_policy", {})),
            listener_policy=cls._listener_policy_from_mapping(server.get("listener_policy")),
            tsig_keys=keys,
            zones=zones,
            views=views,
            response_policies=response_policies,
        )

    @staticmethod
    def _mapping_list(value: object, field_name: str) -> list[Mapping[str, Any]]:
        if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
            raise DesiredStateValidationError(f"{field_name} must be a list of mappings")
        return list(value)

    @classmethod
    def _zone_from_mapping(cls, payload: Mapping[str, Any]) -> Zone:
        return Zone(
            name=str(payload.get("name", "")),
            zone_type=str(payload.get("type", "primary")),
            file=str(payload.get("file", "")),
            dynamic_update_key=payload.get("dynamic_update_key"),
            primaries=_as_string_tuple(payload.get("primaries", []), "zone primaries"),
            forwarders=_as_string_tuple(payload.get("forwarders", []), "zone forwarders"),
            forward_mode=str(payload.get("forward_mode", "first")),
            records=_as_string_tuple(payload.get("records", []), "zone records"),
        )

    @classmethod
    def _view_from_mapping(cls, payload: Mapping[str, Any]) -> View:
        return View(
            name=str(payload.get("name", "")),
            match_clients=_as_string_tuple(payload.get("match_clients", []), "match_clients"),
            zones=tuple(cls._zone_from_mapping(item) for item in cls._mapping_list(payload.get("zones", []), "view zones")),
            resolver_policy=cls._resolver_policy_from_mapping(payload.get("resolver_policy", {})),
        )

    @classmethod
    def _response_policy_from_mapping(cls, payload: Mapping[str, Any]) -> ResponsePolicy:
        rules = tuple(
            ResponsePolicyRule(
                query_name=str(rule.get("query_name", "")),
                action=str(rule.get("action", "answer")),
                records=tuple(
                    ResponsePolicyRecord(
                        record_type=str(record.get("type", "")),
                        value=str(record.get("value", "")),
                        ttl=record.get("ttl"),
                    )
                    for record in cls._mapping_list(rule.get("records", []), "response policy rule records")
                ),
            )
            for rule in cls._mapping_list(payload.get("rules", []), "response policy rules")
        )
        return ResponsePolicy(
            name=str(payload.get("name", "")),
            zone_name=str(payload.get("zone_name", "")),
            enabled=bool(payload.get("enabled", True)),
            rules=rules,
        )

    @staticmethod
    def _resolver_policy_from_mapping(payload: object) -> ResolverPolicy:
        if not isinstance(payload, Mapping):
            raise DesiredStateValidationError("resolver_policy must be a mapping")
        return ResolverPolicy(
            recursion_enabled=bool(payload.get("recursion_enabled", False)),
            allow_recursion=_as_string_tuple(payload.get("allow_recursion", []), "allow_recursion"),
            allow_query=_as_string_tuple(payload.get("allow_query", []), "allow_query"),
            forwarders=_as_string_tuple(payload.get("forwarders", []), "forwarders"),
            forward_mode=str(payload.get("forward_mode", "first")),
        )

    @staticmethod
    def _listener_policy_from_mapping(payload: object) -> ListenerPolicy | None:
        if payload is None:
            return None
        if not isinstance(payload, Mapping):
            raise DesiredStateValidationError("listener_policy must be a mapping")

        def family(name: str) -> ListenerFamilyPolicy:
            family_payload = payload.get(name, {})
            if not isinstance(family_payload, Mapping):
                raise DesiredStateValidationError(f"listener_policy.{name} must be a mapping")
            return ListenerFamilyPolicy(
                addresses=_as_string_tuple(family_payload.get("addresses", []), f"listener_policy.{name}.addresses"),
                port=family_payload.get("port", 53),
            )

        unknown = set(payload) - {"ipv4", "ipv6"}
        if unknown:
            raise DesiredStateValidationError(f"unsupported listener_policy setting(s): {', '.join(sorted(unknown))}")
        return ListenerPolicy(ipv4=family("ipv4"), ipv6=family("ipv6"))
