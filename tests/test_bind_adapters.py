from __future__ import annotations

from pathlib import Path

import pytest

from dwlabbind.bind_adapters import (
    AtomicSymlinkActivator,
    BindActivationError,
    NamedCheckValidator,
    StagingBindRenderer,
)
from dwlabbind.desired_state import BindDesiredState, ResolverPolicy, View, Zone


VALID_ZONE_RECORDS = (
    "$TTL 300",
    "@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 300 )",
    "@ IN NS ns1.example.test.",
    "ns1 IN A 192.0.2.53",
)


def test_staging_renderer_writes_a_valid_bind_configuration(tmp_path: Path) -> None:
    state = BindDesiredState(
        server_name="dns-01",
        resolver_policy=ResolverPolicy(allow_query=("any",)),
        zones=(Zone(name="example.test", file="zones/example.test.zone", records=VALID_ZONE_RECORDS),),
    )

    rendered = StagingBindRenderer(tmp_path / "stage").render(state)

    named_conf = Path(rendered.root_path) / "named.conf"
    assert 'zone "example.test"' in named_conf.read_text(encoding="utf-8")
    assert "allow-query { any; };" in (Path(rendered.root_path) / "options.conf").read_text(encoding="utf-8")
    assert 'zone "example.test"' in (Path(rendered.root_path) / "zones.conf").read_text(encoding="utf-8")
    assert NamedCheckValidator().validate(rendered) == ()


def test_staging_renderer_writes_view_specific_configuration(tmp_path: Path) -> None:
    state = BindDesiredState(
        server_name="dns-01",
        views=(
            View(
                name="internal",
                match_clients=("10.100.0.0/16",),
                resolver_policy=ResolverPolicy(allow_query=("10.100.0.0/16",)),
                zones=(
                    Zone(
                        name="cmk-dev.dw-lab.com",
                        file="zones/internal/cmk-dev.dw-lab.com.zone",
                        records=VALID_ZONE_RECORDS,
                    ),
                ),
            ),
        ),
    )

    rendered = StagingBindRenderer(tmp_path / "stage").render(state)

    text = (Path(rendered.root_path) / "named.conf").read_text(encoding="utf-8")
    assert 'view "internal"' in text
    assert "match-clients { 10.100.0.0/16; };" in text


class FakeServiceController:
    def __init__(self, failures: int = 0) -> None:
        self.failures = failures
        self.calls = 0

    def reload(self) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("BIND rejected the release")


def _render_release(releases: Path, name: str) -> object:
    return StagingBindRenderer(releases / name, runtime_root=releases.parent / "current").render(
        BindDesiredState(
            server_name="dns-01",
            zones=(Zone(name="example.test", file="zones/example.test.zone", records=VALID_ZONE_RECORDS),),
        )
    )


def test_atomic_activator_switches_current_release_after_validation(tmp_path: Path) -> None:
    releases = tmp_path / "releases"
    releases.mkdir()
    old_release = _render_release(releases, "old")
    new_release = _render_release(releases, "new")
    current = tmp_path / "current"
    current.symlink_to(old_release.root_path)
    controller = FakeServiceController()

    AtomicSymlinkActivator(current, releases, controller).activate(new_release)

    assert current.resolve() == Path(new_release.root_path).resolve()
    assert controller.calls == 1


def test_atomic_activator_restores_previous_release_when_reload_fails(tmp_path: Path) -> None:
    releases = tmp_path / "releases"
    releases.mkdir()
    old_release = _render_release(releases, "old")
    new_release = _render_release(releases, "new")
    current = tmp_path / "current"
    current.symlink_to(old_release.root_path)
    controller = FakeServiceController(failures=1)

    with pytest.raises(BindActivationError, match="previous release restored"):
        AtomicSymlinkActivator(current, releases, controller).activate(new_release)

    assert current.resolve() == Path(old_release.root_path).resolve()
    assert controller.calls == 2
