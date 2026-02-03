"""Core BIND configuration containers (skeleton)."""

from __future__ import annotations

from typing import List, Optional

from dwlabbind.bind_statements import *


class BindServer:
    def __init__(
        self,
        name: str,
        zone_files: Optional[List["BindZoneFile"]] = None,
        options: Optional["BindOptionFile"] = None,
        hosts_files: Optional[List["BindZoneHostsFile"]] = None,
    ) -> None:
        self.name = name
        self.zone_files = zone_files or []
        self.options = options
        self.hosts_files = hosts_files or []

    @classmethod
    def readConf(cls, filename: Optional[str] = None) -> "BindServer":
        path = filename or "/etc/bind/named.conf"
        return cls(name=path)

class BindZoneFile:
    def __init__(self, zone_name: str) -> None:
        self.zone_name = zone_name


class BindZoneHostsFile:
    def __init__(self, zone_name: str) -> None:
        self.zone_name = zone_name


class BindOptionsFile:
    def __init__(self) -> None:
        pass
