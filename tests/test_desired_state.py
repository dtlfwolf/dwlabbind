from __future__ import annotations

import pytest

from dwlabbind.desired_state import (
    SCHEMA_VERSION,
    BindDesiredState,
    DesiredStateValidationError,
    ListenerFamilyPolicy,
    ListenerPolicy,
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


def test_listener_policy_round_trips_and_retains_an_explicit_disabled_ipv6_family() -> None:
    state = BindDesiredState(
        server_name="dns-01",
        listener_policy=ListenerPolicy(
            ipv4=ListenerFamilyPolicy(addresses=("127.0.0.1", "192.168.2.30")),
            ipv6=ListenerFamilyPolicy(),
        ),
    )

    restored = BindDesiredState.from_mapping(state.to_mapping())

    assert restored == state
    assert restored.to_mapping()["server"]["listener_policy"]["ipv6"]["addresses"] == []


def test_listener_policy_rejects_non_local_address_selectors_and_wrong_family() -> None:
    with pytest.raises(DesiredStateValidationError, match="not an IP address"):
        ListenerFamilyPolicy(addresses=("192.168.2.0/24",))
    with pytest.raises(DesiredStateValidationError, match="wrong address family"):
        ListenerPolicy(ipv4=ListenerFamilyPolicy(addresses=("::1",)))


def test_zone_requires_endpoints_for_secondary_and_forward_types() -> None:
    with pytest.raises(DesiredStateValidationError, match="secondary zones require primaries"):
        Zone(name="secondary.example.test", zone_type="secondary", file="zones/secondary.zone")
    with pytest.raises(DesiredStateValidationError, match="forward zones require forwarders"):
        Zone(name="forward.example.test", zone_type="forward")
