"""First-install inspection and safety policy for BIND deployments."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, Sequence


class BindInstallationError(RuntimeError):
    """Raised when a selected installation mode is unsafe or unavailable."""


class BindInstallationMode(str, Enum):
    """Explicit ownership choices for a first dwlabbind activation."""

    NEW_SERVER = "new-server"
    ADDITIVE = "additive"
    ADOPT_EXISTING = "adopt-existing"


@dataclass(frozen=True)
class DiscoveredBindZone:
    """A zone discovered from the active BIND configuration tree."""

    name: str
    zone_type: str
    file_path: str
    management_state: str


class BindZoneInventory(Protocol):
    """Port for reading zones from an existing BIND configuration."""

    def list_zones_from_conf(self, named_conf: str) -> Sequence[dict[str, object]]:
        """Return the effective zones defined by ``named_conf``."""


@dataclass(frozen=True)
class BindInstallationInspection:
    """Read-only facts used to choose a safe first-install mode."""

    named_conf: Path
    named_conf_exists: bool
    zones: tuple[DiscoveredBindZone, ...]

    @property
    def non_default_zones(self) -> tuple[DiscoveredBindZone, ...]:
        """Return existing zones that are not supplied by the BIND package.

        A newly installed Ubuntu BIND server includes localhost and loopback
        zones.  Those zones are not customer DNS state and must not prevent a
        first DW-Lab activation in ``new-server`` mode.
        """

        return tuple(
            zone
            for zone in self.zones
            if zone.management_state != "package-managed"
        )

    def to_mapping(self) -> dict[str, object]:
        """Provide a transport-neutral inspection representation."""

        return {
            "named_conf": str(self.named_conf),
            "named_conf_exists": self.named_conf_exists,
            "zones": [
                {
                    "name": zone.name,
                    "type": zone.zone_type,
                    "file_path": zone.file_path,
                    "management_state": zone.management_state,
                }
                for zone in self.zones
            ],
            "non_default_zone_count": len(self.non_default_zones),
            "available_modes": [mode.value for mode in BindInstallationMode],
        }


class BindInstallationInspector:
    """Classify an existing BIND setup without modifying any BIND file."""

    def __init__(self, inventory: BindZoneInventory) -> None:
        self._inventory = inventory

    def inspect(self, named_conf: str | Path) -> BindInstallationInspection:
        """Discover active zones, returning an empty inventory when BIND is absent."""

        configuration_path = Path(named_conf)
        if not configuration_path.is_file():
            return BindInstallationInspection(configuration_path, False, ())
        zones = tuple(self._to_zone(item) for item in self._inventory.list_zones_from_conf(str(configuration_path)))
        return BindInstallationInspection(configuration_path, True, zones)

    def validate_mode(
        self,
        mode: BindInstallationMode,
        inspection: BindInstallationInspection,
    ) -> None:
        """Reject modes that could silently claim or replace existing DNS state."""

        if mode is BindInstallationMode.NEW_SERVER and inspection.non_default_zones:
            zone_names = ", ".join(zone.name for zone in inspection.non_default_zones)
            raise BindInstallationError(
                "new-server mode cannot be used because existing non-default zones were discovered: "
                f"{zone_names}. Use additive to manage only new DW-Lab zones, or adopt-existing after "
                "reviewing a generated migration proposal."
            )
        if mode is BindInstallationMode.ADOPT_EXISTING:
            raise BindInstallationError(
                "adopt-existing is intentionally not activated automatically. Run installation-inspect, "
                "review the generated migration proposal, and use the dedicated migration command when available."
            )

    @staticmethod
    def _to_zone(item: dict[str, object]) -> DiscoveredBindZone:
        return DiscoveredBindZone(
            name=str(item.get("zone_name") or ""),
            zone_type=str(item.get("zone_type") or ""),
            file_path=str(item.get("file_path") or ""),
            management_state=str(item.get("management_state") or "un-managed"),
        )
