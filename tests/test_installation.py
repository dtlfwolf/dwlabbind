from pathlib import Path

import pytest

from dwlabbind.installation import (
    BindInstallationError,
    BindInstallationInspector,
    BindInstallationMode,
)


class RecordingInventory:
    def __init__(self, zones: list[dict[str, object]]) -> None:
        self._zones = zones
        self.paths: list[str] = []

    def list_zones_from_conf(self, named_conf: str) -> list[dict[str, object]]:
        self.paths.append(named_conf)
        return self._zones


def test_inspection_of_missing_bind_configuration_is_safe_for_new_server(tmp_path: Path) -> None:
    inspector = BindInstallationInspector(RecordingInventory([]))

    inspection = inspector.inspect(tmp_path / "missing-named.conf")

    assert inspection.named_conf_exists is False
    assert inspection.zones == ()
    inspector.validate_mode(BindInstallationMode.NEW_SERVER, inspection)


def test_new_server_rejects_existing_customer_zone(tmp_path: Path) -> None:
    named_conf = tmp_path / "named.conf"
    named_conf.write_text("include \"named.conf.local\";\n", encoding="utf-8")
    inspector = BindInstallationInspector(
        RecordingInventory([
            {"zone_name": ".", "zone_type": "hint", "file_path": "/usr/share/dns/root.hints"},
            {"zone_name": "example.internal", "zone_type": "master", "file_path": "/var/lib/bind/example.zone"},
        ])
    )

    inspection = inspector.inspect(named_conf)

    with pytest.raises(BindInstallationError, match="example.internal"):
        inspector.validate_mode(BindInstallationMode.NEW_SERVER, inspection)
    inspector.validate_mode(BindInstallationMode.ADDITIVE, inspection)


def test_new_server_accepts_ubuntu_package_default_zones(tmp_path: Path) -> None:
    named_conf = tmp_path / "named.conf"
    named_conf.write_text('include "named.conf.default-zones";\n', encoding="utf-8")
    inspector = BindInstallationInspector(
        RecordingInventory([
            {"zone_name": ".", "zone_type": "hint", "management_state": "package-managed"},
            {"zone_name": "localhost", "zone_type": "master", "management_state": "package-managed"},
            {"zone_name": "0.in-addr.arpa", "zone_type": "master", "management_state": "package-managed"},
            {"zone_name": "127.in-addr.arpa", "zone_type": "master", "management_state": "package-managed"},
            {"zone_name": "255.in-addr.arpa", "zone_type": "master", "management_state": "package-managed"},
        ])
    )

    inspection = inspector.inspect(named_conf)

    assert inspection.non_default_zones == ()
    inspector.validate_mode(BindInstallationMode.NEW_SERVER, inspection)


def test_adopt_existing_requires_dedicated_migration_even_when_no_zones(tmp_path: Path) -> None:
    inspector = BindInstallationInspector(RecordingInventory([]))
    inspection = inspector.inspect(tmp_path / "missing-named.conf")

    with pytest.raises(BindInstallationError, match="not activated automatically"):
        inspector.validate_mode(BindInstallationMode.ADOPT_EXISTING, inspection)
