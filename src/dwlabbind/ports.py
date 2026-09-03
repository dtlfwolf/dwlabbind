"""Ports implemented by BIND and operating-system infrastructure adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .desired_state import BindDesiredState


@dataclass(frozen=True)
class RenderedBindConfiguration:
    """A staged configuration produced by a renderer, not yet activated."""

    root_path: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class ValidationIssue:
    """A deterministic validation result suitable for CLI and HTTP responses."""

    code: str
    message: str
    severity: str = "error"

    @property
    def is_error(self) -> bool:
        return self.severity == "error"


class BindConfigurationRenderer(Protocol):
    """Renders desired state into an isolated BIND staging location."""

    def render(self, desired_state: BindDesiredState) -> RenderedBindConfiguration:
        """Render configuration without activating it."""


class BindConfigurationValidator(Protocol):
    """Validates a staged configuration, normally with named-checkconf tools."""

    def validate(self, rendered: RenderedBindConfiguration) -> tuple[ValidationIssue, ...]:
        """Return all validation issues found in the staged configuration."""


class BindConfigurationActivator(Protocol):
    """Atomically activates a configuration that has already been validated."""

    def activate(self, rendered: RenderedBindConfiguration) -> None:
        """Activate the staged configuration and reload BIND."""


class BindServiceController(Protocol):
    """Controls BIND after a previously validated configuration switch."""

    def reload(self) -> None:
        """Reload BIND and raise an exception if the service rejects the configuration."""
