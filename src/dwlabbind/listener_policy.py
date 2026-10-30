"""Application service for global BIND listener desired state."""

from __future__ import annotations

from dataclasses import replace

from .desired_state import BindDesiredState, ListenerPolicy


class ListenerPolicyService:
    """Mutate global listener state without depending on a transport or filesystem."""

    @staticmethod
    def get_policy(state: BindDesiredState) -> ListenerPolicy | None:
        """Return the explicit policy, or ``None`` when BIND defaults apply."""
        return state.listener_policy

    @staticmethod
    def update_policy(state: BindDesiredState, policy: ListenerPolicy) -> BindDesiredState:
        """Replace the complete explicit listener policy."""
        return replace(state, listener_policy=policy)

    @staticmethod
    def clear_policy(state: BindDesiredState) -> BindDesiredState:
        """Remove explicit bindings and restore BIND's distribution defaults."""
        return replace(state, listener_policy=None)
