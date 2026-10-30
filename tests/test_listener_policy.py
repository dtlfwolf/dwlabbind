from __future__ import annotations

from dwlabbind.desired_state import BindDesiredState, ListenerFamilyPolicy, ListenerPolicy
from dwlabbind.listener_policy import ListenerPolicyService


def test_listener_policy_service_replaces_and_clears_only_listener_state() -> None:
    state = BindDesiredState(server_name="dns-01")
    policy = ListenerPolicy(ipv4=ListenerFamilyPolicy(addresses=("192.168.2.30",)))

    updated = ListenerPolicyService().update_policy(state, policy)

    assert updated.listener_policy == policy
    assert updated.server_name == "dns-01"
    assert ListenerPolicyService().clear_policy(updated).listener_policy is None
