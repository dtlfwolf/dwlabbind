"""Runtime reconciliation services for a deployed BIND installation.

This module owns the privileged BIND lifecycle.  Deployment packages only
install the wheel, configuration defaults, and a launcher for these services.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import grp
import ipaddress
import os
from pathlib import Path
import re
import secrets
import tempfile
import subprocess

from dwlabbasicpy.dwlabOperation import NullOperationReporter, OperationReporter

from .application import BindReconciliationService
from .bind_adapters import AtomicSymlinkActivator, NamedCheckValidator, StagingBindRenderer
from .desired_state import BindDesiredState, TsigKey, Zone
from .desired_state_io import YamlDesiredStateRepository
from .legacy_import import LegacyXmlDesiredStateImporter
from .bind_conf import BindServer
from .ports import BindServiceController


class BindRuntimeError(RuntimeError):
    """Raised when a deployed BIND runtime cannot be safely changed."""


@dataclass(frozen=True)
class BindRuntimeConfiguration:
    """Filesystem and service integration points for one BIND runtime."""

    state_path: Path
    releases_root: Path
    runtime_root: Path
    named_options: Path
    named_local: Path
    named_main: Path
    key_directory: Path = Path("/etc/bind/dwlab/keys")


@dataclass
class ManagedIncludeTransaction:
    """Own the exact pre-change include files for activation rollback."""

    options_file: Path
    local_file: Path
    runtime_root: Path
    named_main_file: Path | None = None
    split_views: bool = False
    main_replacement: str | None = None
    _before: dict[Path, bytes] | None = None

    def apply(self) -> None:
        if not self.options_file.is_file() or not self.local_file.is_file():
            raise BindRuntimeError("named.conf.options and named.conf.local must both exist")
        self._before = {
            self.options_file: self.options_file.read_bytes(),
            self.local_file: self.local_file.read_bytes(),
        }
        if self.split_views or self.main_replacement is not None:
            if self.named_main_file is None or not self.named_main_file.is_file():
                raise BindRuntimeError("named.conf must exist when activating split DNS views")
            self._before[self.named_main_file] = self.named_main_file.read_bytes()
        options_include = f'include "{self.runtime_root}/options.conf";'
        zones_include = f'include "{self.runtime_root}/zones.conf";'
        self._atomic_write(self.options_file, self._insert_options_include(self._before[self.options_file].decode("utf-8"), options_include))
        self._atomic_write(self.local_file, self._append_local_include(self._before[self.local_file].decode("utf-8"), zones_include))
        if self.main_replacement is not None:
            assert self.named_main_file is not None
            self._atomic_write(self.named_main_file, self.main_replacement)
        elif self.split_views:
            assert self.named_main_file is not None
            self._atomic_write(
                self.named_main_file,
                self._disable_global_root_hints(self._before[self.named_main_file].decode("utf-8")),
            )

    def rollback(self) -> None:
        if self._before is None:
            return
        for path, content in self._before.items():
            self._atomic_write(path, content.decode("utf-8"))

    @staticmethod
    def _insert_options_include(content: str, include: str) -> str:
        begin = "// DW-Lab dwlabbind options - BEGIN"
        end = "// DW-Lab dwlabbind options - END"
        marker_pairs = (
            (begin, end),
            ("// DW-Lab dwlab-bind-deploy options - BEGIN", "// DW-Lab dwlab-bind-deploy options - END"),
        )
        for managed_begin, managed_end in marker_pairs:
            if managed_begin in content or managed_end in content:
                if managed_begin in content and managed_end in content and include in content:
                    return content
                raise BindRuntimeError("named.conf.options contains an incompatible DW-Lab managed block")
        options_start = content.find("options")
        open_brace = content.find("{", options_start)
        if options_start < 0 or open_brace < 0:
            raise BindRuntimeError("could not find options block in named.conf.options")
        depth = 0
        for index in range(open_brace, len(content)):
            if content[index] == "{":
                depth += 1
            elif content[index] == "}":
                depth -= 1
                if depth == 0:
                    block = f"    {begin}\n    {include}\n    {end}\n"
                    return content[:index] + block + content[index:]
        raise BindRuntimeError("options block in named.conf.options is not balanced")

    @staticmethod
    def _append_local_include(content: str, include: str) -> str:
        begin = "// DW-Lab dwlabbind zones - BEGIN"
        end = "// DW-Lab dwlabbind zones - END"
        marker_pairs = (
            (begin, end),
            ("// DW-Lab dwlab-bind-deploy zones - BEGIN", "// DW-Lab dwlab-bind-deploy zones - END"),
        )
        for managed_begin, managed_end in marker_pairs:
            if managed_begin in content or managed_end in content:
                if managed_begin in content and managed_end in content and include in content:
                    return content
                raise BindRuntimeError("named.conf.local contains an incompatible DW-Lab managed block")
        suffix = "" if not content or content.endswith("\n") else "\n"
        return f"{content}{suffix}{begin}\n{include}\n{end}\n"

    @staticmethod
    def _disable_global_root_hints(content: str) -> str:
        begin = "// DW-Lab dwlabbind root hints - BEGIN"
        end = "// DW-Lab dwlabbind root hints - END"
        if begin in content or end in content:
            if begin in content and end in content:
                return content
            raise BindRuntimeError("named.conf contains an incompatible DW-Lab root-hints block")
        pattern = re.compile(r'^(?P<indent>\s*)include\s+"/etc/bind/named\.conf\.root-hints";\s*$', re.MULTILINE)
        match = pattern.search(content)
        if match is None:
            raise BindRuntimeError("named.conf has no manageable /etc/bind/named.conf.root-hints include")
        indent = match.group("indent")
        replacement = f"{indent}{begin}\n{indent}// {match.group(0).strip()}\n{indent}{end}"
        return content[: match.start()] + replacement + content[match.end() :]

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(temporary, path.stat().st_mode & 0o777)
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


class BindRuntimeService:
    """Apply desired state and manage OpenVPN DNS zones in a BIND runtime."""

    def __init__(
        self,
        service_controller: BindServiceController,
        reporter: OperationReporter | None = None,
    ) -> None:
        self._service_controller = service_controller
        self._reporter = reporter or NullOperationReporter()

    def configure(self, configuration: BindRuntimeConfiguration, release_name: str, main_replacement: str | None = None) -> str:
        """Stage, validate, and atomically activate a desired-state release."""
        operation = "bind-configure"
        context = {"release_name": release_name, "state_path": str(configuration.state_path)}
        phase = "load-desired-state"
        try:
            self._reporter.started(operation, phase, context)
            state = YamlDesiredStateRepository().load(configuration.state_path)
            self._reporter.passed(operation, phase, context)
            phase = "stage-and-validate-release"
            self._reporter.started(operation, phase, context)
            release_path = configuration.releases_root / release_name
            staged = BindReconciliationService(
                renderer=StagingBindRenderer(release_path, runtime_root=configuration.runtime_root),
                validator=NamedCheckValidator(),
            ).stage(state)
            self._reporter.passed(operation, phase, context)
            phase = "prepare-dynamic-zone-runtime"
            self._reporter.started(operation, phase, context)
            self._prepare_dynamic_zone_runtime(state, Path(staged.rendered.root_path))
            self._reporter.passed(operation, phase, context)
            phase = "activate-release"
            self._reporter.started(operation, phase, context)
            includes = ManagedIncludeTransaction(
                configuration.named_options,
                configuration.named_local,
                configuration.runtime_root,
                named_main_file=configuration.named_main,
                split_views=bool(state.views),
                main_replacement=main_replacement,
            )
            includes.apply()
            try:
                AtomicSymlinkActivator(
                    current_link=configuration.runtime_root,
                    releases_root=configuration.releases_root,
                    service_controller=self._service_controller,
                ).activate(staged.rendered)
            except Exception:
                includes.rollback()
                self._service_controller.reload()
                raise
            self._reporter.passed(operation, phase, context)
        except Exception as error:
            self._reporter.failed(operation, phase, context, error)
            raise
        return staged.rendered.root_path

    def migrate_legacy(
        self,
        configuration: BindRuntimeConfiguration,
        release_name: str,
        backup_path: Path,
        legacy_named_conf: Path | None = None,
    ) -> str:
        """Convert a legacy top-level BIND layout into the managed release layout."""
        active_server = BindServer.fromConfFile(str(configuration.named_main))
        active_server.backup(str(backup_path))
        source_path = legacy_named_conf or configuration.named_main
        server = active_server if source_path == configuration.named_main else BindServer.fromConfFile(str(source_path))
        dynamic_zones = [zone.zone_name for zone in server._zone_files if zone.ddns_enabled]
        for zone_name in dynamic_zones:
            subprocess.run(["rndc", "sync", zone_name], check=True, capture_output=True, text=True)
        base_state = YamlDesiredStateRepository().load(configuration.state_path)
        previous_state = configuration.state_path.read_bytes()
        migrated = LegacyXmlDesiredStateImporter().from_conf(source_path, base_state)
        blocking_issues = self._blocking_migration_issues(migrated.issues)
        if blocking_issues:
            raise BindRuntimeError("legacy migration requires review: " + "; ".join(issue.message for issue in blocking_issues))
        YamlDesiredStateRepository().save(migrated.desired_state, configuration.state_path)
        includes = [
            'include "/etc/bind/named.conf.options";',
            'include "/etc/bind/named.conf.local";',
        ]
        default_zones = configuration.named_main.parent / "named.conf.default-zones"
        if default_zones.is_file():
            includes.append(f'include "{default_zones}";')
        try:
            return self.configure(configuration, release_name, main_replacement="\n".join(includes) + "\n")
        except Exception:
            configuration.state_path.write_bytes(previous_state)
            raise

    @staticmethod
    def _blocking_migration_issues(issues: tuple[MigrationIssue, ...]) -> tuple[MigrationIssue, ...]:
        """Return migration observations that require operator review."""
        return tuple(
            issue
            for issue in issues
            if issue.severity != "info" and issue.code != "RESOLVER_POLICY_REVIEW_REQUIRED"
        )

    def ensure_ovpn_zone(
        self,
        configuration: BindRuntimeConfiguration,
        domain_name: str,
        dns_server_cidr: str,
        base_hostname: str,
    ) -> dict[str, str]:
        """Create and activate the forward/reverse dynamic DNS zones for OVPN."""
        operation = "ovpn-zone-ensure"
        context = {"domain_name": domain_name, "dns_server_cidr": dns_server_cidr, "state_path": str(configuration.state_path)}
        phase = "validate-active-runtime"
        try:
            self._reporter.started(operation, phase, context)
            self._require_initialized_runtime(configuration)
            self._reporter.passed(operation, phase, context)
            phase = "load-and-validate-input"
            self._reporter.started(operation, phase, context)
            state = YamlDesiredStateRepository().load(configuration.state_path)
            network = ipaddress.ip_interface(dns_server_cidr)
            if network.version != 4 or network.network.prefixlen != 24:
                raise BindRuntimeError("OpenVPN dynamic DNS currently requires an IPv4 /24 network")
            domain = domain_name.strip().rstrip(".").lower()
            key_name = f"ovpn-{self._safe_name(domain)}"
            key_path = configuration.key_directory / f"{key_name}.key"
            reverse_zone = ".".join(reversed(str(network.network.network_address).split(".")[:3])) + ".in-addr.arpa"
            self._reporter.passed(operation, phase, context)
            if any(zone.name == domain for zone in state.zones):
                return self._allocation(domain, reverse_zone, network, key_path)

            phase = "create-tsig-key"
            self._reporter.started(operation, phase, context)
            self._write_tsig_key(key_path, key_name)
            self._reporter.passed(operation, phase, context)
            phase = "persist-and-activate-zones"
            self._reporter.started(operation, phase, context)
            updated = BindDesiredState(
            server_name=state.server_name,
            resolver_policy=state.resolver_policy,
            listener_policy=state.listener_policy,
            tsig_keys=(*state.tsig_keys, TsigKey(name=key_name, secret_reference=f"file://{key_path}")),
            zones=(
                *state.zones,
                Zone(
                    name=domain,
                    file=f"zones/{domain}.zone",
                    dynamic_update_key=key_name,
                    records=self._zone_records(domain, base_hostname, str(network.ip)),
                ),
                Zone(
                    name=reverse_zone,
                    file=f"zones/{reverse_zone}.zone",
                    dynamic_update_key=key_name,
                    records=self._reverse_zone_records(reverse_zone, domain, base_hostname, network),
                ),
            ),
            views=state.views,
            response_policies=state.response_policies,
            )
            previous_content = configuration.state_path.read_bytes()
            YamlDesiredStateRepository().save(updated, configuration.state_path)
            try:
                self.configure(configuration, self._release_name(domain))
            except Exception:
                configuration.state_path.write_bytes(previous_content)
                key_path.unlink(missing_ok=True)
                raise
            self._reporter.passed(operation, phase, context)
            return self._allocation(domain, reverse_zone, network, key_path)
        except Exception as error:
            self._reporter.failed(operation, phase, context, error)
            raise

    def remove_ovpn_zone(self, configuration: BindRuntimeConfiguration, domain_name: str) -> None:
        """Remove an OVPN zone and its TSIG key from desired state and BIND."""
        self._require_initialized_runtime(configuration)
        state = YamlDesiredStateRepository().load(configuration.state_path)
        domain = domain_name.strip().rstrip(".").lower()
        key_name = f"ovpn-{self._safe_name(domain)}"
        retained_zones = tuple(zone for zone in state.zones if zone.name != domain and zone.dynamic_update_key != key_name)
        retained_keys = tuple(key for key in state.tsig_keys if key.name != key_name)
        if len(retained_zones) == len(state.zones):
            return
        updated = BindDesiredState(
            server_name=state.server_name,
            resolver_policy=state.resolver_policy,
            listener_policy=state.listener_policy,
            tsig_keys=retained_keys,
            zones=retained_zones,
            views=state.views,
            response_policies=state.response_policies,
        )
        previous_content = configuration.state_path.read_bytes()
        YamlDesiredStateRepository().save(updated, configuration.state_path)
        try:
            self.configure(configuration, self._release_name(f"remove-{domain}"))
        except Exception:
            configuration.state_path.write_bytes(previous_content)
            raise
        (configuration.key_directory / f"{key_name}.key").unlink(missing_ok=True)

    @staticmethod
    def _require_initialized_runtime(configuration: BindRuntimeConfiguration) -> None:
        """Require an explicit first activation before dynamic operations mutate state."""

        if not configuration.runtime_root.is_symlink():
            raise BindRuntimeError(
                "no active DW-Lab BIND release exists. Select and validate new-server or additive "
                "installation mode, then run configure before managing OpenVPN zones."
            )

    @staticmethod
    def _prepare_dynamic_zone_runtime(state: BindDesiredState, release_path: Path) -> None:
        dynamic_zones = tuple(zone for zone in state.zones if zone.dynamic_update_key)
        if not dynamic_zones:
            return
        bind_group = grp.getgrnam("bind").gr_gid
        release_root = release_path.resolve()
        for zone in dynamic_zones:
            if not zone.file:
                raise BindRuntimeError(f"dynamic zone {zone.name} must define a zone file")
            zone_path = (release_path / zone.file).resolve()
            try:
                zone_path.relative_to(release_root)
            except ValueError as error:
                raise BindRuntimeError(f"dynamic zone {zone.name} file escapes its release") from error
            if zone_path.parent == release_root:
                raise BindRuntimeError(f"dynamic zone {zone.name} must use a dedicated writable directory below its release")
            if not zone_path.is_file():
                raise BindRuntimeError(f"dynamic zone {zone.name} file was not rendered: {zone_path}")
            os.chown(zone_path.parent, 0, bind_group)
            zone_path.parent.chmod(0o770)
            os.chown(zone_path, 0, bind_group)
            zone_path.chmod(0o660)

    @staticmethod
    def _allocation(domain: str, reverse_zone: str, network: ipaddress.IPv4Interface, key_path: Path) -> dict[str, str]:
        return {"zone_name": domain, "reverse_zone": reverse_zone, "dns_server_ip": str(network.ip), "key_file": str(key_path)}

    @staticmethod
    def _safe_name(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")

    @classmethod
    def _release_name(cls, domain: str) -> str:
        return f"ovpn-{cls._safe_name(domain)}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"

    @staticmethod
    def _write_tsig_key(path: Path, key_name: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        bind_group = grp.getgrnam("bind").gr_gid
        os.chown(path.parent, 0, bind_group)
        path.parent.chmod(0o750)
        secret = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        path.write_text(f'key "{key_name}" {{\n    algorithm hmac-sha256;\n    secret "{secret}";\n}};\n', encoding="utf-8")
        os.chown(path, 0, bind_group)
        path.chmod(0o640)

    @staticmethod
    def _zone_records(domain: str, base_hostname: str, dns_server_ip: str) -> tuple[str, ...]:
        nameserver = f"{base_hostname.rstrip('.')}.{domain}."
        return ("$TTL 60", f"@ IN SOA {nameserver} hostmaster.{domain}. ( 1 3600 900 604800 60 )", f"@ IN NS {nameserver}", f"{base_hostname.rstrip('.')} IN A {dns_server_ip}")

    @staticmethod
    def _reverse_zone_records(reverse_zone: str, domain: str, base_hostname: str, network: ipaddress.IPv4Interface) -> tuple[str, ...]:
        nameserver = f"{base_hostname.rstrip('.')}.{domain}."
        return ("$TTL 60", f"@ IN SOA {nameserver} hostmaster.{domain}. ( 1 3600 900 604800 60 )", f"@ IN NS {nameserver}", f"{str(network.ip).split('.')[-1]} IN PTR {nameserver}")
