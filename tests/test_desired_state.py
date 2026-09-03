from __future__ import annotations

import pytest

from dwlabbind.desired_state import (
    SCHEMA_VERSION,
    BindDesiredState,
    DesiredStateValidationError,
    ResolverPolicy,
    TsigKey,
    View,
    Zone,
)


def test_desired_state_round_trips_a_split_dns_configuration() -> None:
    expected = BindDesiredState(
        server_name="dns-01",
        resolver_policy=ResolverPolicy(allow_query=("any",)),
        tsig_keys=(
            TsigKey(
                name="vpn.lab.dwlab.test",
                secret_reference="file:///etc/bind/dwlab/keys/vpn.lab.dwlab.test.key",
            ),
        ),
        views=(
            View(
                name="internal",
                match_clients=("192.168.0.0/16", "10.100.0.0/16"),
                resolver_policy=ResolverPolicy(
                    recursion_enabled=True,
                    allow_recursion=("192.168.0.0/16", "10.100.0.0/16"),
                    forwarders=("1.1.1.1",),
                ),
                zones=(
                    Zone(
                        name="cmk-dev.dw-lab.com",
                        file="zones/internal/cmk-dev.dw-lab.com.zone",
                        records=("@ IN A 192.168.12.11",),
                    ),
                    Zone(
                        name="vpn.lab.dwlab.test",
                        file="zones/internal/vpn.lab.dwlab.test.zone",
                        dynamic_update_key="vpn.lab.dwlab.test",
                    ),
                ),
            ),
        ),
    )

    restored = BindDesiredState.from_mapping(expected.to_mapping())

    assert restored == expected
    assert restored.to_mapping()["schema_version"] == SCHEMA_VERSION


def test_desired_state_rejects_unknown_dynamic_dns_key() -> None:
    with pytest.raises(DesiredStateValidationError, match="unknown TSIG key"):
        BindDesiredState(
            server_name="dns-01",
            zones=(
                Zone(
                    name="vpn.lab.dwlab.test",
                    file="zones/vpn.lab.dwlab.test.zone",
                    dynamic_update_key="missing-key",
                ),
            ),
        )


def test_resolver_policy_requires_an_acl_when_recursion_is_enabled() -> None:
    with pytest.raises(DesiredStateValidationError, match="allow_recursion"):
        ResolverPolicy(recursion_enabled=True)


def test_zone_requires_endpoints_for_secondary_and_forward_types() -> None:
    with pytest.raises(DesiredStateValidationError, match="secondary zones require primaries"):
        Zone(name="secondary.example.test", zone_type="secondary", file="zones/secondary.zone")
    with pytest.raises(DesiredStateValidationError, match="forward zones require forwarders"):
        Zone(name="forward.example.test", zone_type="forward")
