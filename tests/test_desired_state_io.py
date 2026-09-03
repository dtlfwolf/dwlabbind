from __future__ import annotations

from pathlib import Path

from dwlabbind.desired_state_io import YamlDesiredStateRepository


def test_yaml_desired_state_repository_loads_versioned_state(tmp_path: Path) -> None:
    path = tmp_path / "state.yaml"
    path.write_text(
        "\n".join(
            [
                "schema_version: dwlabbind/v1",
                "server:",
                "  name: dns-01",
                "  resolver_policy:",
                "    recursion_enabled: false",
                "    allow_query: [any]",
                "    allow_recursion: []",
                "    forwarders: []",
                "    forward_mode: first",
                "tsig_keys: []",
                "zones: []",
                "views: []",
            ]
        ),
        encoding="utf-8",
    )

    state = YamlDesiredStateRepository().load(path)

    assert state.server_name == "dns-01"
