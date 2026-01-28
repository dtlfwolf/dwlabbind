"""Core object model for BIND server management."""

from __future__ import annotations

from typing import List, Optional
import xml.etree.ElementTree as ET


class TSIGKey:
    def __init__(self, name: str, algorithm: str, secret: str) -> None:
        self.name = name
        self.algorithm = algorithm
        self.secret = secret

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "secret": self.secret,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TSIGKey":
        return cls(
            name=data.get("name", ""),
            algorithm=data.get("algorithm", "hmac-sha256"),
            secret=data.get("secret", ""),
        )

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("tsig_key")
        element.set("name", self.name)
        element.set("algorithm", self.algorithm)
        element.set("secret", self.secret)
        return element

    @classmethod
    def from_xml_element(cls, element: ET.Element) -> "TSIGKey":
        return cls(
            name=element.get("name", ""),
            algorithm=element.get("algorithm", "hmac-sha256"),
            secret=element.get("secret", ""),
        )


class SecurityConfig:
    def __init__(
        self,
        enabled: bool = False,
        allow_recursion: Optional[List[str]] = None,
        allow_transfer: Optional[List[str]] = None,
        tsig_keys: Optional[List[TSIGKey]] = None,
    ) -> None:
        self.enabled = enabled
        self.allow_recursion = allow_recursion or []
        self.allow_transfer = allow_transfer or []
        self.tsig_keys = tsig_keys or []

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "allow_recursion": list(self.allow_recursion),
            "allow_transfer": list(self.allow_transfer),
            "tsig_keys": [key.to_dict() for key in self.tsig_keys],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityConfig":
        keys = [TSIGKey.from_dict(item) for item in data.get("tsig_keys", [])]
        return cls(
            enabled=bool(data.get("enabled", False)),
            allow_recursion=list(data.get("allow_recursion", [])),
            allow_transfer=list(data.get("allow_transfer", [])),
            tsig_keys=keys,
        )

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("security")
        element.set("enabled", "true" if self.enabled else "false")
        for network in self.allow_recursion:
            item = ET.SubElement(element, "allow_recursion")
            item.text = network
        for network in self.allow_transfer:
            item = ET.SubElement(element, "allow_transfer")
            item.text = network
        keys_element = ET.SubElement(element, "tsig_keys")
        for key in self.tsig_keys:
            keys_element.append(key.to_xml_element())
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SecurityConfig":
        if element is None:
            return cls()
        allow_recursion = [
            item.text or "" for item in element.findall("allow_recursion")
        ]
        allow_transfer = [
            item.text or "" for item in element.findall("allow_transfer")
        ]
        keys_element = element.find("tsig_keys")
        tsig_keys = []
        if keys_element is not None:
            for item in keys_element.findall("tsig_key"):
                tsig_keys.append(TSIGKey.from_xml_element(item))
        return cls(
            enabled=element.get("enabled", "false") == "true",
            allow_recursion=allow_recursion,
            allow_transfer=allow_transfer,
            tsig_keys=tsig_keys,
        )


class HAConfig:
    def __init__(
        self,
        enabled: bool = False,
        mode: str = "active-passive",
        peers: Optional[List[str]] = None,
    ) -> None:
        self.enabled = enabled
        self.mode = mode
        self.peers = peers or []

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "peers": list(self.peers),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HAConfig":
        return cls(
            enabled=bool(data.get("enabled", False)),
            mode=data.get("mode", "active-passive"),
            peers=list(data.get("peers", [])),
        )

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("high_availability")
        element.set("enabled", "true" if self.enabled else "false")
        element.set("mode", self.mode)
        for peer in self.peers:
            item = ET.SubElement(element, "peer")
            item.text = peer
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "HAConfig":
        if element is None:
            return cls()
        peers = [item.text or "" for item in element.findall("peer")]
        return cls(
            enabled=element.get("enabled", "false") == "true",
            mode=element.get("mode", "active-passive"),
            peers=peers,
        )


class NameServerProfile:
    def __init__(self, server_type: str = "bind9", version: str = "") -> None:
        self.server_type = server_type
        self.version = version

    def to_dict(self) -> dict:
        return {"server_type": self.server_type, "version": self.version}

    @classmethod
    def from_dict(cls, data: dict) -> "NameServerProfile":
        return cls(
            server_type=data.get("server_type", "bind9"),
            version=data.get("version", ""),
        )

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("server_profile")
        element.set("type", self.server_type)
        element.set("version", self.version)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NameServerProfile":
        if element is None:
            return cls()
        return cls(
            server_type=element.get("type", "bind9"),
            version=element.get("version", ""),
        )


class OptionsConfig:
    DEFAULT_EXCLUSIVE_GROUPS = [
        {"dnssec-validation", "dnssec-enable"},
    ]
    DEFAULT_ALLOWED_VALUES = {
        "recursion": {"yes", "no"},
        "dnssec-validation": {"auto", "yes", "no"},
        "dnssec-enable": {"yes", "no"},
    }

    def __init__(
        self,
        options: Optional[dict] = None,
        exclusive_groups: Optional[List[set]] = None,
        allowed_values: Optional[dict] = None,
    ) -> None:
        self.options = options or {}
        self.exclusive_groups = exclusive_groups or list(self.DEFAULT_EXCLUSIVE_GROUPS)
        self.allowed_values = allowed_values or dict(self.DEFAULT_ALLOWED_VALUES)

    def add_option(self, name: str, value: str) -> None:
        self._validate_option(name, value)
        self.options[name] = value

    def update_option(self, name: str, value: str) -> None:
        self.add_option(name, value)

    def remove_option(self, name: str) -> None:
        self.options.pop(name, None)

    def add_exclusive_group(self, names: List[str]) -> None:
        self.exclusive_groups.append(set(names))

    def _validate_option(self, name: str, value: str) -> None:
        allowed = self.allowed_values.get(name)
        if allowed and value not in allowed:
            raise ValueError(f"Unsupported value for {name}: {value}")
        for group in self.exclusive_groups:
            if name in group:
                conflicts = group - {name}
                for other in conflicts:
                    if other in self.options:
                        raise ValueError(
                            f"Option {name} is mutually exclusive with {other}"
                        )

    def to_dict(self) -> dict:
        return {"options": dict(self.options)}

    @classmethod
    def from_dict(cls, data: dict) -> "OptionsConfig":
        return cls(options=dict(data.get("options", {})))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("options")
        for name, value in self.options.items():
            item = ET.SubElement(element, "option")
            item.set("name", name)
            item.set("value", str(value))
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "OptionsConfig":
        if element is None:
            return cls()
        options: dict = {}
        for item in element.findall("option"):
            name = item.get("name", "")
            value = item.get("value", "")
            if name:
                options[name] = value
        return cls(options=options)


class BindZone:
    def __init__(
        self,
        name: str,
        zone_type: str,
        file: str,
        masters: Optional[List[str]] = None,
        allow_update: bool = False,
    ) -> None:
        self.name = name
        self.zone_type = zone_type
        self.file = file
        self.masters = masters or []
        self.allow_update = allow_update

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.zone_type,
            "file": self.file,
            "masters": list(self.masters),
            "allow_update": self.allow_update,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BindZone":
        return cls(
            name=data.get("name", ""),
            zone_type=data.get("type", "master"),
            file=data.get("file", ""),
            masters=list(data.get("masters", [])),
            allow_update=bool(data.get("allow_update", False)),
        )

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("zone")
        element.set("name", self.name)
        element.set("type", self.zone_type)
        element.set("file", self.file)
        element.set("allow_update", "true" if self.allow_update else "false")
        masters_element = ET.SubElement(element, "masters")
        for master in self.masters:
            item = ET.SubElement(masters_element, "master")
            item.text = master
        return element

    @classmethod
    def from_xml_element(cls, element: ET.Element) -> "BindZone":
        masters_element = element.find("masters")
        masters = []
        if masters_element is not None:
            masters = [item.text or "" for item in masters_element.findall("master")]
        return cls(
            name=element.get("name", ""),
            zone_type=element.get("type", "master"),
            file=element.get("file", ""),
            masters=masters,
            allow_update=element.get("allow_update", "false") == "true",
        )


class BindServer:
    def __init__(
        self,
        name: str,
        ip: str,
        port: int = 53,
        role: str = "master",
        zones: Optional[List[BindZone]] = None,
        server_profile: Optional[NameServerProfile] = None,
        options: Optional[OptionsConfig] = None,
        security: Optional[SecurityConfig] = None,
        high_availability: Optional[HAConfig] = None,
    ) -> None:
        self.name = name
        self.ip = ip
        self.port = port
        self.role = role
        self.zones = zones or []
        self.server_profile = server_profile or NameServerProfile()
        self.options = options or OptionsConfig()
        self.security = security or SecurityConfig()
        self.high_availability = high_availability or HAConfig()

    def add_zone(self, zone: BindZone) -> None:
        self.zones.append(zone)

    def remove_zone(self, zone_name: str) -> None:
        self.zones = [zone for zone in self.zones if zone.name != zone_name]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "role": self.role,
            "zones": [zone.to_dict() for zone in self.zones],
            "server_profile": self.server_profile.to_dict(),
            "options": self.options.to_dict(),
            "security": self.security.to_dict(),
            "high_availability": self.high_availability.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BindServer":
        zones = [BindZone.from_dict(item) for item in data.get("zones", [])]
        return cls(
            name=data.get("name", ""),
            ip=data.get("ip", ""),
            port=int(data.get("port", 53)),
            role=data.get("role", "master"),
            zones=zones,
            server_profile=NameServerProfile.from_dict(data.get("server_profile", {})),
            options=OptionsConfig.from_dict(data.get("options", {})),
            security=SecurityConfig.from_dict(data.get("security", {})),
            high_availability=HAConfig.from_dict(data.get("high_availability", {})),
        )

    def to_xml_element(self) -> ET.Element:
        element = ET.Element("bind_server")
        element.set("name", self.name)
        element.set("ip", self.ip)
        element.set("port", str(self.port))
        element.set("role", self.role)
        zones_element = ET.SubElement(element, "zones")
        for zone in self.zones:
            zones_element.append(zone.to_xml_element())
        element.append(self.server_profile.to_xml_element())
        element.append(self.options.to_xml_element())
        element.append(self.security.to_xml_element())
        element.append(self.high_availability.to_xml_element())
        return element

    @classmethod
    def from_xml_element(cls, element: ET.Element) -> "BindServer":
        zones_element = element.find("zones")
        zones = []
        if zones_element is not None:
            zones = [BindZone.from_xml_element(item) for item in zones_element.findall("zone")]
        server_profile = NameServerProfile.from_xml_element(element.find("server_profile"))
        options = OptionsConfig.from_xml_element(element.find("options"))
        security = SecurityConfig.from_xml_element(element.find("security"))
        ha = HAConfig.from_xml_element(element.find("high_availability"))
        return cls(
            name=element.get("name", ""),
            ip=element.get("ip", ""),
            port=int(element.get("port", "53")),
            role=element.get("role", "master"),
            zones=zones,
            server_profile=server_profile,
            options=options,
            security=security,
            high_availability=ha,
        )


class MasterServer(BindServer):
    def __init__(
        self,
        name: str,
        ip: str,
        port: int = 53,
        zones: Optional[List[BindZone]] = None,
        security: Optional[SecurityConfig] = None,
        high_availability: Optional[HAConfig] = None,
    ) -> None:
        super().__init__(
            name=name,
            ip=ip,
            port=port,
            role="master",
            zones=zones,
            security=security,
            high_availability=high_availability,
        )


class SlaveServer(BindServer):
    def __init__(
        self,
        name: str,
        ip: str,
        port: int = 53,
        zones: Optional[List[BindZone]] = None,
        security: Optional[SecurityConfig] = None,
        high_availability: Optional[HAConfig] = None,
    ) -> None:
        super().__init__(
            name=name,
            ip=ip,
            port=port,
            role="slave",
            zones=zones,
            security=security,
            high_availability=high_availability,
        )
