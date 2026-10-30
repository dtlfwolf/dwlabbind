"""Application service for transport-independent response-policy mutations."""

from __future__ import annotations

from dataclasses import replace
import ipaddress
import re

from .desired_state import BindDesiredState, ResponsePolicy, ResponsePolicyRecord, ResponsePolicyRule


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

    def create_policy(self, state: BindDesiredState, domain_name: str) -> BindDesiredState:
        """Add the conventional RPZ policy for one customer DNS domain."""
        policy = ResponsePolicy.for_domain(domain_name)
        if any(existing.name == policy.name or existing.zone_name == policy.zone_name for existing in state.response_policies):
            raise ResponsePolicyAlreadyExistsError(f"response policy already exists: {policy.name}")
        return replace(state, response_policies=(*state.response_policies, policy))

    def delete_policy(self, state: BindDesiredState, policy_name: str) -> BindDesiredState:
        """Remove one empty response policy from the desired state."""
        policy = self.get_policy(state, policy_name)
        if policy.rules:
            raise ValueError(f"response policy {policy.name} still contains rules; delete them before deleting the policy")
        return replace(state, response_policies=tuple(item for item in state.response_policies if item.name != policy.name))

    def add_fixed_host(self, state: BindDesiredState, policy_name: str, hostname: str, ip_address: str) -> BindDesiredState:
        """Add an exact A or AAAA override below a convention-based policy domain."""
        policy = self.get_policy(state, policy_name)
        normalized_hostname = hostname.strip().rstrip(".").lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", normalized_hostname):
            raise ValueError("response policy hostname must be one DNS host label")
        try:
            address = ipaddress.ip_address(ip_address.strip())
        except ValueError as error:
            raise ValueError(f"response policy fixed-host address is not an IP address: {ip_address}") from error
        record_type = "A" if address.version == 4 else "AAAA"
        return self.add_rule(
            state,
            policy.name,
            ResponsePolicyRule(
                query_name=f"{normalized_hostname}.{policy.domain_name}",
                records=(ResponsePolicyRecord(record_type=record_type, value=str(address)),),
            ),
        )

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
