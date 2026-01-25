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
        security: Optional[SecurityConfig] = None,
        high_availability: Optional[HAConfig] = None,
    ) -> None:
        self.name = name
        self.ip = ip
        self.port = port
        self.role = role
        self.zones = zones or []
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
        element.append(self.security.to_xml_element())
        element.append(self.high_availability.to_xml_element())
        return element

    @classmethod
    def from_xml_element(cls, element: ET.Element) -> "BindServer":
        zones_element = element.find("zones")
        zones = []
        if zones_element is not None:
            zones = [BindZone.from_xml_element(item) for item in zones_element.findall("zone")]
        security = SecurityConfig.from_xml_element(element.find("security"))
        ha = HAConfig.from_xml_element(element.find("high_availability"))
        return cls(
            name=element.get("name", ""),
            ip=element.get("ip", ""),
            port=int(element.get("port", "53")),
            role=element.get("role", "master"),
            zones=zones,
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
