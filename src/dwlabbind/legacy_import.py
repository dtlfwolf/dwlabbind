"""Explicit migration adapter from the legacy XML model to dwlabbind/v1."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .bind_conf import BindServer, BindServerXmlSerializer
from .desired_state import BindDesiredState, Zone


@dataclass(frozen=True)
class MigrationIssue:
    """A legacy behavior that needs an operator decision before activation."""

    code: str
    message: str
    severity: str = "warning"


@dataclass(frozen=True)
class LegacyImportResult:
    """Imported state and all migration observations."""

    desired_state: BindDesiredState
    issues: tuple[MigrationIssue, ...]


class LegacyXmlDesiredStateImporter:
    """Imports XML zone data without importing hidden legacy side effects."""

    _ZONE_TYPE_MAP = {"": "primary", "master": "primary", "primary": "primary"}

    def from_xml(self, xml_path: str | Path) -> LegacyImportResult:
        server = BindServerXmlSerializer().read_server_xml(str(xml_path))
        return self.from_server(server, source_name=Path(xml_path).stem)

    def from_server(self, server: BindServer, source_name: str | None = None) -> LegacyImportResult:
        issues: list[MigrationIssue] = [
            MigrationIssue(
                code="RESOLVER_POLICY_REVIEW_REQUIRED",
                message="Legacy resolver ACLs and forwarders are not inferred; configure them explicitly in dwlabbind/v1.",
            )
        ]
        zones: list[Zone] = []
        for zone_file in server._zone_files:
            if zone_file.externally_managed:
                issues.append(
                    MigrationIssue(
                        code="EXTERNAL_ZONE_SKIPPED",
                        message=f"Skipped externally managed zone {zone_file.zone_name}.",
                        severity="info",
                    )
                )
                continue
            legacy_type = (zone_file.zone_type or "").strip().lower()
            zone_type = self._ZONE_TYPE_MAP.get(legacy_type)
            if zone_type is None:
                issues.append(
                    MigrationIssue(
                        code="UNSUPPORTED_ZONE_TYPE_SKIPPED",
                        message=f"Skipped zone {zone_file.zone_name} with legacy type {legacy_type!r}.",
                    )
                )
                continue
            if zone_file.ddns_enabled:
                issues.append(
                    MigrationIssue(
                        code="DYNAMIC_ZONE_REQUIRES_TSIG_REVIEW",
                        message=(
                            f"Imported dynamic zone {zone_file.zone_name} without allow-update; "
                            "declare a new TSIG secret reference before activation."
                        ),
                    )
                )
            records = tuple(
                zone_file._serialize_statement(statement)
                for statement in (*zone_file.zone_file_statements, *zone_file.fixed_host_statements)
            )
            zones.append(
                Zone(
                    name=zone_file.zone_name,
                    zone_type=zone_type,
                    file=self._target_zone_file(zone_file.zone_name),
                    records=records,
                )
            )
        if any(statement.__class__.__name__ == "Key" for statement in server._statements):
            issues.append(
                MigrationIssue(
                    code="TSIG_SECRETS_NOT_IMPORTED",
                    message="Legacy TSIG key material was not copied; add file:// secret references to the new state.",
                )
            )
        return LegacyImportResult(
            desired_state=BindDesiredState(server_name=source_name or Path(server.name).stem, zones=tuple(zones)),
            issues=tuple(issues),
        )

    @staticmethod
    def _target_zone_file(zone_name: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", zone_name.strip().rstrip("."))
        return f"zones/{normalized}.zone"
