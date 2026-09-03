from __future__ import annotations

from pathlib import Path

import pytest

from dwlabbind.bind_adapters import NamedCheckValidator, StagingBindRenderer
from dwlabbind.desired_state import (
    BindDesiredState,
    DesiredStateValidationError,
    ResolverPolicy,
    ResponsePolicy,
    ResponsePolicyRecord,
    ResponsePolicyRule,
    View,
)
from dwlabbind.response_policy import (
    ResponsePolicyAlreadyExistsError,
    ResponsePolicyNotFoundError,
    ResponsePolicyService,
)


def _state() -> BindDesiredState:
    return BindDesiredState(
        server_name="dns-01",
        resolver_policy=ResolverPolicy(recursion_enabled=True, allow_recursion=("192.168.2.0/24",)),
        response_policies=(
            ResponsePolicy(
                name="internal-host-overrides",
                zone_name="rpz.internal.dw-lab",
            ),
        ),
    )


def test_response_policy_round_trip_and_renderer_are_valid(tmp_path: Path) -> None:
    state = ResponsePolicyService().add_rule(
        _state(),
        "internal-host-overrides",
        ResponsePolicyRule(
            query_name="t-com.dw-lab.com",
            records=(ResponsePolicyRecord(record_type="A", value="192.168.2.31"),),
        ),
    )
    state = ResponsePolicyService().add_rule(
        state,
        "internal-host-overrides",
        ResponsePolicyRule(query_name="unwanted.dw-lab.com", action="nxdomain"),
    )

    restored = BindDesiredState.from_mapping(state.to_mapping())
    rendered = StagingBindRenderer(tmp_path / "stage").render(restored)
    named_conf = (Path(rendered.root_path) / "named.conf").read_text(encoding="utf-8")
    zone = (Path(rendered.root_path) / "rpz" / "internal-host-overrides.zone").read_text(encoding="utf-8")

    assert 'response-policy { zone "rpz.internal.dw-lab"; };' in named_conf
    assert "t-com.dw-lab.com IN A 192.168.2.31" in zone
    assert "unwanted.dw-lab.com IN CNAME ." in zone
    assert NamedCheckValidator().validate(rendered) == ()


def test_response_policy_is_rendered_inside_each_view(tmp_path: Path) -> None:
    state = BindDesiredState(
        server_name="dns-01",
        response_policies=(ResponsePolicy(name="overrides", zone_name="rpz.internal.dw-lab"),),
        views=(
            View(name="internal", match_clients=("192.168.2.0/24",)),
        ),
    )

    rendered = StagingBindRenderer(tmp_path / "stage").render(state)
    text = (Path(rendered.root_path) / "named.conf").read_text(encoding="utf-8")

    assert 'view "internal"' in text
    assert 'response-policy { zone "rpz.internal.dw-lab"; };' in text
    assert NamedCheckValidator().validate(rendered) == ()


def test_response_policy_service_has_explicit_add_update_delete_contract() -> None:
    service = ResponsePolicyService()
    rule = ResponsePolicyRule(
        query_name="dwlab-cmk-dev.dw-lab.com",
        records=(ResponsePolicyRecord(record_type="A", value="192.168.2.31"),),
    )
    updated = service.add_rule(_state(), "internal-host-overrides", rule)

    with pytest.raises(ResponsePolicyAlreadyExistsError):
        service.add_rule(updated, "internal-host-overrides", rule)

    changed = service.update_rule(
        updated,
        "internal-host-overrides",
        ResponsePolicyRule(query_name=rule.query_name, action="nxdomain"),
    )
    assert changed.response_policies[0].rules[0].action == "nxdomain"
    deleted = service.delete_rule(changed, "internal-host-overrides", rule.query_name)
    assert deleted.response_policies[0].rules == ()

    with pytest.raises(ResponsePolicyNotFoundError):
        service.delete_rule(deleted, "internal-host-overrides", rule.query_name)


def test_response_policy_rejects_non_answer_records_and_invalid_addresses() -> None:
    with pytest.raises(DesiredStateValidationError, match="must not contain records"):
        ResponsePolicyRule(
            query_name="blocked.dw-lab.com",
            action="nxdomain",
            records=(ResponsePolicyRecord(record_type="A", value="192.168.2.31"),),
        )
    with pytest.raises(DesiredStateValidationError, match="not an IP address"):
        ResponsePolicyRecord(record_type="A", value="not-an-address")
