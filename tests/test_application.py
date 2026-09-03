from __future__ import annotations

import pytest

from dwlabbind.application import BindReconciliationService, ReconciliationError
from dwlabbind.desired_state import BindDesiredState, View, Zone
from dwlabbind.ports import RenderedBindConfiguration, ValidationIssue


class FakeRenderer:
    def __init__(self) -> None:
        self.calls = 0

    def render(self, desired_state: BindDesiredState) -> RenderedBindConfiguration:
        self.calls += 1
        return RenderedBindConfiguration(root_path="/stage", files=("/stage/named.conf",))


class FakeValidator:
    def __init__(self, issues: tuple[ValidationIssue, ...] = ()) -> None:
        self.issues = issues
        self.calls = 0

    def validate(self, rendered: RenderedBindConfiguration) -> tuple[ValidationIssue, ...]:
        self.calls += 1
        return self.issues


class FakeActivator:
    def __init__(self) -> None:
        self.calls = 0

    def activate(self, rendered: RenderedBindConfiguration) -> None:
        self.calls += 1


def _service(issues: tuple[ValidationIssue, ...] = ()) -> tuple[BindReconciliationService, FakeRenderer, FakeValidator, FakeActivator]:
    renderer = FakeRenderer()
    validator = FakeValidator(issues)
    activator = FakeActivator()
    return BindReconciliationService(renderer, validator, activator), renderer, validator, activator


def test_reconcile_uses_renderer_validator_and_activator_after_preflight() -> None:
    service, renderer, validator, activator = _service()
    state = BindDesiredState(
        server_name="dns-01",
        zones=(Zone(name="example.test", file="zones/example.test.zone"),),
    )

    result = service.reconcile(state)

    assert result.rendered.root_path == "/stage"
    assert renderer.calls == validator.calls == activator.calls == 1


def test_plan_rejects_global_zones_when_views_are_configured() -> None:
    service, renderer, validator, activator = _service()
    state = BindDesiredState(
        server_name="dns-01",
        zones=(Zone(name="example.test", file="zones/example.test.zone"),),
        views=(View(name="internal", match_clients=("10.0.0.0/8",)),),
    )

    plan = service.plan(state)

    assert not plan.can_apply
    assert [issue.code for issue in plan.issues] == ["GLOBAL_ZONES_WITH_VIEWS"]
    with pytest.raises(ReconciliationError):
        service.reconcile(state)
    assert renderer.calls == validator.calls == activator.calls == 0


def test_plan_requires_any_view_to_be_last() -> None:
    service, _, _, _ = _service()
    state = BindDesiredState(
        server_name="dns-01",
        views=(
            View(name="catch-all", match_clients=("any",)),
            View(name="internal", match_clients=("10.0.0.0/8",)),
        ),
    )

    assert [issue.code for issue in service.plan(state).issues] == ["VIEW_ANY_NOT_LAST"]


def test_reconcile_does_not_activate_when_bind_validation_fails() -> None:
    service, renderer, validator, activator = _service(
        (ValidationIssue(code="NAMED_CHECKCONF_FAILED", message="invalid zone"),)
    )
    state = BindDesiredState(
        server_name="dns-01",
        zones=(Zone(name="example.test", file="zones/example.test.zone"),),
    )

    with pytest.raises(ReconciliationError, match="NAMED_CHECKCONF_FAILED"):
        service.reconcile(state)

    assert renderer.calls == validator.calls == 1
    assert activator.calls == 0


def test_stage_validates_without_an_activator() -> None:
    renderer = FakeRenderer()
    validator = FakeValidator()
    service = BindReconciliationService(renderer, validator)
    state = BindDesiredState(
        server_name="dns-01",
        zones=(Zone(name="example.test", file="zones/example.test.zone"),),
    )

    result = service.stage(state)

    assert result.rendered.root_path == "/stage"
    assert renderer.calls == validator.calls == 1
