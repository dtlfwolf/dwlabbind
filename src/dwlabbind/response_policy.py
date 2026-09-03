"""Application service for transport-independent response-policy mutations."""

from __future__ import annotations

from dataclasses import replace

from .desired_state import BindDesiredState, ResponsePolicy, ResponsePolicyRule


class ResponsePolicyNotFoundError(ValueError):
    """Raised when a requested policy or rule does not exist."""


class ResponsePolicyAlreadyExistsError(ValueError):
    """Raised when an add operation would replace an existing rule."""


class ResponsePolicyService:
    """Mutate RPZ desired state without depending on CLI, HTTP, or filesystem."""

    @staticmethod
    def list_policies(state: BindDesiredState) -> tuple[ResponsePolicy, ...]:
        return state.response_policies

    @staticmethod
    def get_policy(state: BindDesiredState, policy_name: str) -> ResponsePolicy:
        normalized = policy_name.strip().lower()
        for policy in state.response_policies:
            if policy.name == normalized:
                return policy
        raise ResponsePolicyNotFoundError(f"response policy not found: {policy_name}")

    def add_rule(self, state: BindDesiredState, policy_name: str, rule: ResponsePolicyRule) -> BindDesiredState:
        policy = self.get_policy(state, policy_name)
        if any(existing.query_name == rule.query_name for existing in policy.rules):
            raise ResponsePolicyAlreadyExistsError(
                f"response policy rule already exists: {policy.name}/{rule.query_name}"
            )
        return self._replace_policy(state, replace(policy, rules=(*policy.rules, rule)))

    def update_rule(self, state: BindDesiredState, policy_name: str, rule: ResponsePolicyRule) -> BindDesiredState:
        policy = self.get_policy(state, policy_name)
        if not any(existing.query_name == rule.query_name for existing in policy.rules):
            raise ResponsePolicyNotFoundError(
                f"response policy rule not found: {policy.name}/{rule.query_name}"
            )
        return self._replace_policy(
            state,
            replace(policy, rules=tuple(rule if existing.query_name == rule.query_name else existing for existing in policy.rules)),
        )

    def delete_rule(self, state: BindDesiredState, policy_name: str, query_name: str) -> BindDesiredState:
        policy = self.get_policy(state, policy_name)
        normalized = query_name.strip().rstrip(".").lower()
        remaining = tuple(rule for rule in policy.rules if rule.query_name != normalized)
        if len(remaining) == len(policy.rules):
            raise ResponsePolicyNotFoundError(f"response policy rule not found: {policy.name}/{query_name}")
        return self._replace_policy(state, replace(policy, rules=remaining))

    @staticmethod
    def _replace_policy(state: BindDesiredState, policy: ResponsePolicy) -> BindDesiredState:
        return replace(
            state,
            response_policies=tuple(policy if item.name == policy.name else item for item in state.response_policies),
        )
