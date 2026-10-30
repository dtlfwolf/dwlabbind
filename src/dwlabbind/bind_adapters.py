"""BIND infrastructure adapters for the desired-state reconciliation flow."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

from .desired_state import BindDesiredState, ListenerFamilyPolicy, ListenerPolicy, ResolverPolicy, ResponsePolicy, ResponsePolicyRule, View, Zone
from .ports import BindServiceController, RenderedBindConfiguration, ValidationIssue


class BindRenderingError(RuntimeError):
    """Raised when a desired-state value cannot safely be rendered as BIND."""


class StagingBindRenderer:
    """Render desired state into an empty, explicitly supplied staging root.

    This adapter is intentionally staging-only. It never writes to a live BIND
    directory and therefore cannot reload or change a running DNS service.
    """

    def __init__(self, staging_root: str | Path, runtime_root: str | Path | None = None) -> None:
        self._staging_root = Path(staging_root)
        self._runtime_root = Path(runtime_root) if runtime_root is not None else self._staging_root

    def render(self, desired_state: BindDesiredState) -> RenderedBindConfiguration:
        if self._staging_root.exists() and any(self._staging_root.iterdir()):
            raise BindRenderingError(f"staging root is not empty: {self._staging_root}")
        self._staging_root.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []
        zone_definitions: list[str] = []
        active_response_policies = tuple(policy for policy in desired_state.response_policies if policy.enabled)
        if desired_state.views:
            for view in desired_state.views:
                rendered, created_files = self._render_view(view, active_response_policies)
                zone_definitions.append(rendered)
                files.extend(created_files)
        else:
            for zone in desired_state.zones:
                rendered, created_files = self._render_zone(zone)
                zone_definitions.append(rendered)
                files.extend(created_files)
            for policy in active_response_policies:
                policy_zone = Zone(
                    name=policy.zone_name,
                    file=policy.file,
                    records=self._render_response_policy_records(policy),
                )
                rendered, created_files = self._render_zone(policy_zone)
                zone_definitions.append(rendered)
                files.extend(created_files)

        named_conf = self._staging_root / "named.conf"
        options_conf = self._staging_root / "options.conf"
        zones_conf = self._staging_root / "zones.conf"
        options_text = self._render_options(
            desired_state.resolver_policy,
            listener_policy=desired_state.listener_policy,
            include_container=False,
            include_resolver_settings=not desired_state.views,
        )
        if not desired_state.views:
            for policy in active_response_policies:
                options_text.append(f'response-policy {{ zone "{self._bind_string(policy.zone_name)}"; }};')
        top_level_items = self._render_tsig_includes(desired_state) + zone_definitions
        options_conf.write_text("\n".join(options_text) + "\n", encoding="utf-8")
        zones_conf.write_text("\n".join(top_level_items) + "\n", encoding="utf-8")
        named_conf.write_text(self._render_named_conf(options_text, top_level_items), encoding="utf-8")
        files[0:0] = [named_conf, options_conf, zones_conf]
        return RenderedBindConfiguration(
            root_path=str(self._staging_root),
            files=tuple(str(path) for path in files),
        )

    def _render_response_policy_records(self, policy: ResponsePolicy) -> tuple[str, ...]:
        records = [
            "$TTL 60",
            f"@ IN SOA localhost. hostmaster.localhost. ( 1 3600 900 604800 60 )",
            "@ IN NS localhost.",
        ]
        for rule in policy.rules:
            records.extend(self._render_response_policy_rule(rule))
        return tuple(records)

    @staticmethod
    def _render_response_policy_rule(rule: ResponsePolicyRule) -> tuple[str, ...]:
        if rule.action == "answer":
            return tuple(
                # RPZ query-name triggers are relative to the policy zone.
                f"{rule.query_name}" + (f" {record.ttl}" if record.ttl is not None else "") + f" IN {record.record_type} {record.value}"
                for record in rule.records
            )
        special_target = {
            "nxdomain": ".",
            "nodata": "*.",
            "passthru": "rpz-passthru.",
            "drop": "rpz-drop.",
        }[rule.action]
        return (f"{rule.query_name} IN CNAME {special_target}",)

    def _render_named_conf(self, options_text: list[str], zone_definitions: list[str]) -> str:
        lines: list[str] = []
        lines.append("options {")
        # Validation happens before the runtime symlink is activated. Use the
        # staged directory here so named-checkconf never depends on live state.
        lines.append(f'    directory "{self._bind_string(str(self._staging_root))}";')
        lines.extend(f"    {line}" for line in options_text)
        lines.append("};")
        lines.extend(zone_definitions)
        return "\n".join(lines) + "\n"

    def _render_tsig_includes(self, desired_state: BindDesiredState) -> list[str]:
        lines: list[str] = []
        for key in desired_state.tsig_keys:
            if not key.secret_reference.startswith("file://"):
                raise BindRenderingError(f"TSIG key {key.name} must use a file:// secret_reference")
            secret_path = self._bind_string(key.secret_reference.removeprefix("file://"))
            lines.append(f'include "{secret_path}";')
        return lines

    def _render_view(self, view: View, response_policies: tuple[ResponsePolicy, ...]) -> tuple[str, list[Path]]:
        lines = [f'view "{self._bind_string(view.name)}" {{']
        lines.append(f"    match-clients {{ {self._acl(view.match_clients)} }};")
        lines.extend(f"    {line}" for line in self._render_options(view.resolver_policy, include_container=False))
        files: list[Path] = []
        for zone in view.zones:
            definition, zone_files = self._render_zone(zone)
            lines.extend(f"    {line}" for line in definition.splitlines())
            files.extend(zone_files)
        for policy in response_policies:
            definition, zone_files = self._render_zone(
                Zone(
                    name=policy.zone_name,
                    file=policy.file,
                    records=self._render_response_policy_records(policy),
                )
            )
            lines.extend(f"    {line}" for line in definition.splitlines())
            lines.append(f'    response-policy {{ zone "{self._bind_string(policy.zone_name)}"; }};')
            files.extend(zone_files)
        lines.append("};")
        return "\n".join(lines), files

    def _render_options(
        self,
        policy: ResolverPolicy,
        listener_policy: ListenerPolicy | None = None,
        include_container: bool = True,
        include_resolver_settings: bool = True,
    ) -> list[str]:
        settings = []
        if listener_policy is not None:
            settings.extend(self._render_listener_policy(listener_policy))
        if include_resolver_settings:
            settings.append(f"recursion {'yes' if policy.recursion_enabled else 'no'};")
            if policy.allow_query:
                settings.append(f"allow-query {{ {self._acl(policy.allow_query)} }};")
            if policy.allow_recursion:
                settings.append(f"allow-recursion {{ {self._acl(policy.allow_recursion)} }};")
            if policy.forwarders:
                settings.append(f"forward {policy.forward_mode};")
                settings.append(f"forwarders {{ {self._acl(policy.forwarders)} }};")
        if not include_container:
            return settings
        return ["options {"] + [f"    {setting}" for setting in settings] + ["};"]

    def _render_listener_policy(self, policy: ListenerPolicy) -> list[str]:
        return [
            self._render_listener_family("listen-on", policy.ipv4),
            self._render_listener_family("listen-on-v6", policy.ipv6),
        ]

    def _render_listener_family(self, statement: str, policy: ListenerFamilyPolicy) -> str:
        port = "" if policy.port == 53 else f" port {policy.port}"
        addresses = "none" if not policy.addresses else self._acl(policy.addresses).rstrip(";")
        return f"{statement}{port} {{ {addresses}; }};"

    def _render_zone(self, zone: Zone) -> tuple[str, list[Path]]:
        zone_name = self._bind_string(zone.name)
        lines = [f'zone "{zone_name}" {{', f"    type {zone.zone_type};"]
        zone_files = self._render_zone_files(zone)
        if zone.file:
            rendered_file = self._bind_string(str(self._runtime_root / zone.file))
            lines.append(f'    file "{rendered_file}";')
        if zone.primaries:
            lines.append(f"    primaries {{ {self._acl(zone.primaries)} }};")
        if zone.forwarders:
            lines.append(f"    forward {zone.forward_mode};")
            lines.append(f"    forwarders {{ {self._acl(zone.forwarders)} }};")
        if zone.dynamic_update_key:
            lines.append(f'    allow-update {{ key "{self._bind_string(zone.dynamic_update_key)}"; }};')
        lines.append("};")
        return "\n".join(lines), zone_files

    def _render_zone_files(self, zone: Zone) -> list[Path]:
        if not zone.file:
            return []
        path = self._safe_zone_path(zone.file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(zone.records) + ("\n" if zone.records else ""), encoding="utf-8")
        return [path]

    def _safe_zone_path(self, relative_path: str) -> Path:
        candidate = self._staging_root / relative_path
        try:
            candidate.relative_to(self._staging_root)
        except ValueError as error:
            raise BindRenderingError(f"zone file escapes staging root: {relative_path}") from error
        return candidate

    @staticmethod
    def _acl(values: tuple[str, ...]) -> str:
        return " ".join(f"{StagingBindRenderer._acl_token(value)};" for value in values)

    @staticmethod
    def _acl_token(value: str) -> str:
        text = value.strip()
        if not text or any(char in text for char in '{};"\\'):
            raise BindRenderingError(f"unsafe ACL value: {value!r}")
        return text

    @staticmethod
    def _bind_string(value: str) -> str:
        if any(char in value for char in '"\n\r'):
            raise BindRenderingError("BIND strings must not contain quotes or newlines")
        return value


class NamedCheckValidator:
    """Validate staged BIND configuration through named-checkconf and zones."""

    def __init__(self, named_checkconf: str = "named-checkconf", named_checkzone: str = "named-checkzone") -> None:
        self._named_checkconf = named_checkconf
        self._named_checkzone = named_checkzone

    def validate(self, rendered: RenderedBindConfiguration) -> tuple[ValidationIssue, ...]:
        root = Path(rendered.root_path)
        named_conf = root / "named.conf"
        issues = self._run((self._named_checkconf, str(named_conf)), "NAMED_CHECKCONF_FAILED")
        if issues:
            return issues
        for zone_file in sorted(root.rglob("*.zone")):
            issues += self._run((self._named_checkzone, zone_file.stem, str(zone_file)), "NAMED_CHECKZONE_FAILED")
        return tuple(issues)

    @staticmethod
    def _run(command: tuple[str, ...], code: str) -> tuple[ValidationIssue, ...]:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode == 0:
            return ()
        message = (completed.stderr or completed.stdout or "BIND validation failed").strip()
        return (ValidationIssue(code=code, message=message),)


class BindActivationError(RuntimeError):
    """Raised when a managed-release switch cannot be completed safely."""


class AtomicSymlinkActivator:
    """Activate a staged release by atomically replacing a managed symlink.

    The stable symlink is the BIND runtime root declared by ``StagingBindRenderer``.
    The renderer's staging directory must live below ``releases_root``. No release
    directory is deleted by this class, preserving the previous configuration for
    rollback and later retention policy.
    """

    def __init__(
        self,
        current_link: str | Path,
        releases_root: str | Path,
        service_controller: BindServiceController,
    ) -> None:
        self._current_link = Path(current_link)
        self._releases_root = Path(releases_root)
        self._service_controller = service_controller

    def activate(self, rendered: RenderedBindConfiguration) -> None:
        staged_release = Path(rendered.root_path).resolve()
        releases_root = self._releases_root.resolve()
        try:
            staged_release.relative_to(releases_root)
        except ValueError as error:
            raise BindActivationError(
                f"staged configuration must be below releases root {releases_root}: {staged_release}"
            ) from error
        if not (staged_release / "named.conf").is_file():
            raise BindActivationError(f"staged configuration has no named.conf: {staged_release}")
        if self._current_link.exists() and not self._current_link.is_symlink():
            raise BindActivationError(f"managed runtime path is not a symlink: {self._current_link}")

        previous_target = self._read_current_target()
        self._switch_to(staged_release)
        try:
            self._service_controller.reload()
        except Exception as error:
            self._restore(previous_target)
            try:
                self._service_controller.reload()
            except Exception:
                pass
            raise BindActivationError(f"BIND reload failed; previous release restored: {error}") from error

    def _read_current_target(self) -> Path | None:
        if not self._current_link.is_symlink():
            return None
        return self._current_link.resolve()

    def _switch_to(self, target: Path) -> None:
        self._current_link.parent.mkdir(parents=True, exist_ok=True)
        temporary_link = self._current_link.with_name(f".{self._current_link.name}.new")
        if temporary_link.exists() or temporary_link.is_symlink():
            temporary_link.unlink()
        os.symlink(target, temporary_link)
        os.replace(temporary_link, self._current_link)

    def _restore(self, previous_target: Path | None) -> None:
        if previous_target is None:
            if self._current_link.exists() or self._current_link.is_symlink():
                self._current_link.unlink()
            return
        self._switch_to(previous_target)


class SystemdBindServiceController:
    """Systemd implementation used only by the future deployment adapter."""

    def __init__(self, service_name: str = "bind9", systemctl: str = "systemctl") -> None:
        self._service_name = service_name
        self._systemctl = systemctl

    def reload(self) -> None:
        completed = subprocess.run(
            (self._systemctl, "reload", self._service_name),
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode:
            message = (completed.stderr or completed.stdout or "systemctl reload failed").strip()
            raise BindActivationError(message)
