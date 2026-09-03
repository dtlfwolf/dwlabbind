"""Application services shared by future dwlabbind CLI and HTTP transports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from .desired_state import BindDesiredState, Zone
from .ports import (
    BindConfigurationActivator,
    BindConfigurationRenderer,
    BindConfigurationValidator,
    RenderedBindConfiguration,
    ValidationIssue,
)


class ReconciliationError(RuntimeError):
    """Raised when a desired state cannot safely be reconciled."""

    def __init__(self, issues: tuple[ValidationIssue, ...]) -> None:
        self.issues = issues
        super().__init__("; ".join(f"[{issue.code}] {issue.message}" for issue in issues))


@dataclass(frozen=True)
class ReconciliationPlan:
    """Preflight result used by CLI/API plan and apply operations."""

    desired_state: BindDesiredState
    issues: tuple[ValidationIssue, ...]

    @property
    def can_apply(self) -> bool:
        return not any(issue.is_error for issue in self.issues)


@dataclass(frozen=True)
class ReconciliationResult:
    """Successful rendering, validation, and activation result."""

    plan: ReconciliationPlan
    rendered: RenderedBindConfiguration
    validation_issues: tuple[ValidationIssue, ...]


@dataclass(frozen=True)
class StagingResult:
    """A successfully rendered and validated release that is not active yet."""

    plan: ReconciliationPlan
    rendered: RenderedBindConfiguration
    validation_issues: tuple[ValidationIssue, ...]


class BindReconciliationService:
    """Coordinates plan, staging, validation, and activation through ports."""

    def __init__(
        self,
        renderer: BindConfigurationRenderer,
        validator: BindConfigurationValidator,
        activator: BindConfigurationActivator | None = None,
    ) -> None:
        self._renderer = renderer
        self._validator = validator
        self._activator = activator

    def plan(self, desired_state: BindDesiredState) -> ReconciliationPlan:
        """Create a deterministic preflight plan without touching the system."""
        issues: list[ValidationIssue] = []
        if desired_state.views and desired_state.zones:
            issues.append(
                ValidationIssue(
                    code="GLOBAL_ZONES_WITH_VIEWS",
                    message="BIND configurations with views must place every zone in a view.",
                )
            )
        for scope, zones in self._zone_scopes(desired_state):
            self._validate_scope(scope, zones, issues)
        self._validate_view_order(desired_state, issues)
        return ReconciliationPlan(desired_state=desired_state, issues=tuple(issues))

    def reconcile(self, desired_state: BindDesiredState) -> ReconciliationResult:
        """Stage, validate, and activate a state only after preflight succeeds."""
        staged = self.stage(desired_state)
        if self._activator is None:
            raise RuntimeError("reconciliation activation is not configured")
        self._activator.activate(staged.rendered)
        return ReconciliationResult(
            plan=staged.plan,
            rendered=staged.rendered,
            validation_issues=staged.validation_issues,
        )

    def stage(self, desired_state: BindDesiredState) -> StagingResult:
        """Render and validate a release without changing the active BIND service."""
        plan = self.plan(desired_state)
        if not plan.can_apply:
            raise ReconciliationError(plan.issues)

        rendered = self._renderer.render(desired_state)
        validation_issues = self._validator.validate(rendered)
        errors = tuple(issue for issue in validation_issues if issue.is_error)
        if errors:
            raise ReconciliationError(errors)
        return StagingResult(
            plan=plan,
            rendered=rendered,
            validation_issues=validation_issues,
        )

    @staticmethod
    def _zone_scopes(desired_state: BindDesiredState) -> tuple[tuple[str, tuple[Zone, ...]], ...]:
        scopes: list[tuple[str, tuple[Zone, ...]]] = [("server", desired_state.zones)]
        scopes.extend((f"view {view.name}", view.zones) for view in desired_state.views)
        return tuple(scopes)

    @staticmethod
    def _validate_scope(scope: str, zones: tuple[Zone, ...], issues: list[ValidationIssue]) -> None:
        names = [zone.name.lower() for zone in zones]
        duplicate_names = sorted({name for name in names if names.count(name) > 1})
        for name in duplicate_names:
            issues.append(
                ValidationIssue(
                    code="DUPLICATE_ZONE",
                    message=f"Zone {name} occurs more than once in {scope}.",
                )
            )
        for zone in zones:
            if zone.file and PurePosixPath(zone.file).is_absolute():
                issues.append(
                    ValidationIssue(
                        code="ABSOLUTE_ZONE_FILE",
                        message=f"Zone {zone.name} has an absolute file path in {scope}: {zone.file}",
                    )
                )

    @staticmethod
    def _validate_view_order(desired_state: BindDesiredState, issues: list[ValidationIssue]) -> None:
        for index, view in enumerate(desired_state.views):
            if "any" in {item.lower() for item in view.match_clients} and index != len(desired_state.views) - 1:
                issues.append(
                    ValidationIssue(
                        code="VIEW_ANY_NOT_LAST",
                        message=f"View {view.name} matches 'any' but is not the final view.",
                    )
                )
