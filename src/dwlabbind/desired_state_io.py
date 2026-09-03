"""File adapter for the versioned desired-state document."""

from __future__ import annotations

from pathlib import Path
import os
import tempfile

import yaml

from .desired_state import BindDesiredState, DesiredStateValidationError


class DesiredStateFileError(RuntimeError):
    """Raised when a desired-state file cannot be read or decoded."""


class YamlDesiredStateRepository:
    """Load a desired-state YAML document without leaking YAML into the domain."""

    def load(self, path: str | Path) -> BindDesiredState:
        source = Path(path)
        try:
            payload = yaml.safe_load(source.read_text(encoding="utf-8"))
        except OSError as error:
            raise DesiredStateFileError(f"cannot read desired-state file {source}: {error}") from error
        except yaml.YAMLError as error:
            raise DesiredStateFileError(f"invalid YAML in desired-state file {source}: {error}") from error
        try:
            return BindDesiredState.from_mapping(payload)
        except DesiredStateValidationError as error:
            raise DesiredStateFileError(f"invalid desired-state file {source}: {error}") from error

    def save(self, desired_state: BindDesiredState, path: str | Path) -> Path:
        """Write a portable YAML document from the pure domain model."""
        target = Path(path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            content = yaml.safe_dump(desired_state.to_mapping(), sort_keys=False)
            descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as temporary_file:
                    temporary_file.write(content)
                    temporary_file.flush()
                    os.fsync(temporary_file.fileno())
                os.replace(temporary_name, target)
            except Exception:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
                raise
        except OSError as error:
            raise DesiredStateFileError(f"cannot write desired-state file {target}: {error}") from error
        return target
