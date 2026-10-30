"""Explicit migration adapter from the legacy XML model to dwlabbind/v1."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .bind_conf import BindServer, BindServerXmlSerializer
from .desired_state import BindDesiredState, TsigKey, Zone


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

    def from_conf(self, named_conf: str | Path, base_state: BindDesiredState) -> LegacyImportResult:
        """Import live BIND zones while retaining reviewed server policy.

        XML loses the source file of each TSIG declaration.  Directly reading
        ``named.conf`` is therefore required for a migration candidate that
        can continue dynamic DNS updates.
        """
        server = BindServer.fromConfFile(str(named_conf))
        result = self.from_server(server, source_name=base_state.server_name)
        key_files = self._key_files(server)
        zone_keys = self._zone_keys(server)
        keys = tuple(TsigKey(name=name, secret_reference=f"file://{path}") for name, path in sorted(key_files.items()))
        zones = tuple(
            Zone(
                name=zone.name,
                zone_type=zone.zone_type,
                file=zone.file,
                dynamic_update_key=zone_keys.get(zone.name),
                records=zone.records,
            )
            for zone in result.desired_state.zones
        )
        state = BindDesiredState(
            server_name=base_state.server_name,
            resolver_policy=base_state.resolver_policy,
            listener_policy=base_state.listener_policy,
            tsig_keys=keys,
            zones=zones,
            views=base_state.views,
        )
        issues = tuple(issue for issue in result.issues if issue.code not in {"DYNAMIC_ZONE_REQUIRES_TSIG_REVIEW", "TSIG_SECRETS_NOT_IMPORTED"})
        return LegacyImportResult(desired_state=state, issues=issues)

    @staticmethod
    def _zone_keys(server: BindServer) -> dict[str, str]:
        keys: dict[str, str] = {}
        for statement in server._statements:
            if getattr(statement, "statement_name", "") != "zone":
                continue
            names = server._extract_allow_update_key_names(statement)
            if len(names) == 1:
                keys[server._normalize_zone_name(getattr(statement, "value", ""))] = names[0]
        return keys

    @staticmethod
    def _key_files(server: BindServer) -> dict[str, str]:
        keys: dict[str, str] = {}
        for source in server._source_files:
            path = Path(source)
            if not path.is_file():
                continue
            for name in re.findall(r'key\s+"([^"]+)"\s*\{', path.read_text(encoding="utf-8")):
                keys[name] = str(path)
        return keys

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
            records = self._records_for_desired_state(zone_file)
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
    def _records_for_desired_state(zone_file: object) -> tuple[str, ...]:
        """Render self-contained records with explicit inherited owners."""
        records: list[str] = []
        inherited_owner = "@"
        statements = (*zone_file.zone_file_statements, *zone_file.fixed_host_statements)
        for statement in statements:
            if getattr(statement, "statement_name", "") == "$INCLUDE":
                continue
            rendered = zone_file._serialize_statement(statement)
            rr_type = getattr(statement, "rr_type", None)
            owner = getattr(statement, "owner", None)
            if rr_type and owner is None:
                rendered = f"{inherited_owner} {rendered.lstrip()}"
            elif rr_type and owner:
                # Legacy files commonly start with ``$ORIGIN .`` and spell the
                # zone apex explicitly. The managed file uses the zone origin,
                # so preserve its meaning with the portable ``@`` owner.
                if owner.rstrip(".").lower() == zone_file.zone_name.rstrip(".").lower():
                    rendered = re.sub(rf"^\s*{re.escape(owner)}(?=\s)", "@", rendered)
                    inherited_owner = "@"
                else:
                    inherited_owner = owner
            records.append(rendered)
        return tuple(records)

    @staticmethod
    def _target_zone_file(zone_name: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", zone_name.strip().rstrip("."))
        return f"zones/{normalized}.zone"
