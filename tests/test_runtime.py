from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from dwlabbind.desired_state import BindDesiredState, TsigKey, Zone
from dwlabbind.legacy_import import MigrationIssue
from dwlabbind.runtime import BindRuntimeConfiguration, BindRuntimeService, ManagedIncludeTransaction


class RecordingOperationReporter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, str]] = []

    def started(self, operation: str, phase: str, _context: dict[str, str]) -> None:
        self.events.append(("START", operation, phase))

    def passed(self, operation: str, phase: str, _context: dict[str, str]) -> None:
        self.events.append(("PASS", operation, phase))

    def failed(self, operation: str, phase: str, _context: dict[str, str], _error: Exception) -> None:
        self.events.append(("FAIL", operation, phase))


class RecordingServiceController:
    def reload(self) -> None:
        pass


def test_legacy_migration_does_not_block_on_informational_external_zones() -> None:
    issues = (
        MigrationIssue(
            code="EXTERNAL_ZONE_SKIPPED",
            message="Skipped externally managed zone ..",
            severity="info",
        ),
        MigrationIssue(
            code="RESOLVER_POLICY_REVIEW_REQUIRED",
            message="Resolver policy is retained from desired state.",
        ),
    )

    assert BindRuntimeService._blocking_migration_issues(issues) == ()


def test_legacy_migration_blocks_unsupported_zone_types() -> None:
    issue = MigrationIssue(
        code="UNSUPPORTED_ZONE_TYPE_SKIPPED",
        message="Unsupported legacy zone type.",
    )

    assert BindRuntimeService._blocking_migration_issues((issue,)) == (issue,)


def test_legacy_deployment_options_marker_is_idempotent() -> None:
    include = 'include "/etc/bind/dwlab/current/options.conf";'
    content = "\n".join(
        (
            "options {",
            "    // DW-Lab dwlab-bind-deploy options - BEGIN",
            f"    {include}",
            "    // DW-Lab dwlab-bind-deploy options - END",
            "};",
        )
    )

    assert ManagedIncludeTransaction._insert_options_include(content, include) == content


def test_legacy_deployment_zones_marker_is_idempotent() -> None:
    include = 'include "/etc/bind/dwlab/current/zones.conf";'
    content = "\n".join(
        (
            "// DW-Lab dwlab-bind-deploy zones - BEGIN",
            include,
            "// DW-Lab dwlab-bind-deploy zones - END",
        )
    )

    assert ManagedIncludeTransaction._append_local_include(content, include) == content


def test_dynamic_zone_runtime_allows_bind_to_write_only_zone_journals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = tmp_path / "release"
    zone_file = release / "zones" / "vpn.example.test.zone"
    zone_file.parent.mkdir(parents=True)
    zone_file.write_text("$TTL 60\n", encoding="utf-8")
    chown_calls: list[tuple[Path, int, int]] = []
    monkeypatch.setattr("dwlabbind.runtime.grp.getgrnam", lambda _name: SimpleNamespace(gr_gid=987))
    monkeypatch.setattr(
        "dwlabbind.runtime.os.chown",
        lambda path, uid, gid: chown_calls.append((Path(path), uid, gid)),
    )
    state = BindDesiredState(
        server_name="test",
        tsig_keys=(TsigKey(name="vpn-example-test", secret_reference="file:///tmp/test.key"),),
        zones=(Zone(name="vpn.example.test", file="zones/vpn.example.test.zone", dynamic_update_key="vpn-example-test"),),
    )

    BindRuntimeService._prepare_dynamic_zone_runtime(state, release)

    assert chown_calls == [(zone_file.parent, 0, 987), (zone_file, 0, 987)]
    assert zone_file.parent.stat().st_mode & 0o777 == 0o770
    assert zone_file.stat().st_mode & 0o777 == 0o660


def test_ensure_ovpn_zone_writes_desired_state_and_activates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    state_file = tmp_path / "state.yaml"
    state_file.write_text(
        yaml.safe_dump({"schema_version": "dwlabbind/v1", "server": {"name": "test"}, "zones": []}),
        encoding="utf-8",
    )
    configuration = BindRuntimeConfiguration(
        state_path=state_file,
        releases_root=tmp_path / "releases",
        runtime_root=tmp_path / "current",
        named_options=tmp_path / "named.conf.options",
        named_local=tmp_path / "named.conf.local",
        named_main=tmp_path / "named.conf",
        key_directory=tmp_path / "keys",
    )
    service = BindRuntimeService(RecordingServiceController())
    activation_calls: list[str] = []
    active_release = tmp_path / "active-release"
    active_release.mkdir()
    configuration.runtime_root.symlink_to(active_release)

    def write_test_key(path: Path, _key: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("key", encoding="utf-8")

    monkeypatch.setattr(service, "_write_tsig_key", write_test_key)
    monkeypatch.setattr(service, "configure", lambda _configuration, release: activation_calls.append(release) or "release")

    result = service.ensure_ovpn_zone(configuration, "vpn.example.test", "10.8.4.1/24", "central")

    saved = yaml.safe_load(state_file.read_text(encoding="utf-8"))
    assert result == {
        "zone_name": "vpn.example.test",
        "reverse_zone": "4.8.10.in-addr.arpa",
        "dns_server_ip": "10.8.4.1",
        "key_file": str(configuration.key_directory / "ovpn-vpn-example-test.key"),
    }
    assert [zone["name"] for zone in saved["zones"]] == ["vpn.example.test", "4.8.10.in-addr.arpa"]
    assert activation_calls and activation_calls[0].startswith("ovpn-vpn-example-test-")


def test_ensure_ovpn_zone_requires_explicit_first_activation(tmp_path: Path) -> None:
    state_file = tmp_path / "state.yaml"
    state_file.write_text(
        yaml.safe_dump({"schema_version": "dwlabbind/v1", "server": {"name": "test"}, "zones": []}),
        encoding="utf-8",
    )
    configuration = BindRuntimeConfiguration(
        state_path=state_file,
        releases_root=tmp_path / "releases",
        runtime_root=tmp_path / "current",
        named_options=tmp_path / "named.conf.options",
        named_local=tmp_path / "named.conf.local",
        named_main=tmp_path / "named.conf",
    )

    reporter = RecordingOperationReporter()
    with pytest.raises(RuntimeError, match="no active DW-Lab BIND release exists"):
        BindRuntimeService(RecordingServiceController(), reporter).ensure_ovpn_zone(
            configuration, "vpn.example.test", "10.8.4.1/24", "central"
        )
    assert reporter.events == [
        ("START", "ovpn-zone-ensure", "validate-active-runtime"),
        ("FAIL", "ovpn-zone-ensure", "validate-active-runtime"),
    ]
