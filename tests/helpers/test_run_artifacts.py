"""Persistent test-run artifact layout helpers for archive-based integration tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import shutil
from typing import Any, Optional


OUTPUT_ROOT = Path(__file__).resolve().parent.parent / "output"


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "").strip())
    cleaned = cleaned.strip("._-")
    return cleaned or "unnamed"


def _json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


@dataclass
class ScenarioArtifacts:
    """Represents one scenario subdirectory within a sample test run."""

    root: Path

    def write_status(self, payload: dict[str, Any]) -> None:
        """Write the scenario status.json file."""
        _json_dump(self.root / "status.json", payload)

    def write_text(self, relative_path: str, content: str) -> None:
        """Write one UTF-8 text artifact into the scenario directory."""
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def copy_file(self, source: Path, relative_path: Optional[str] = None) -> None:
        """Copy one file artifact into the scenario directory."""
        if not source.exists():
            return
        target = self.root / (relative_path or source.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    def copy_tree(self, source: Path, relative_path: str) -> None:
        """Copy one directory tree artifact into the scenario directory."""
        if not source.exists():
            return
        target = self.root / relative_path
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target, symlinks=True)


@dataclass
class SampleArtifacts:
    """Represents one fixture/sample block inside a test run."""

    root: Path
    fixture_name: str

    def scenario(self, index: int, name: str) -> ScenarioArtifacts:
        """Return one numbered scenario artifact directory."""
        scenario_dir = self.root / "steps" / f"{index:02d}-{_safe_name(name)}"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        return ScenarioArtifacts(root=scenario_dir)

    def write_fixture_metadata(self, payload: dict[str, Any]) -> None:
        """Write fixture-level metadata for review."""
        _json_dump(self.root / "fixture" / "manifest.json", payload)

    def copy_fixture_file(self, source: Path, relative_name: Optional[str] = None) -> None:
        """Copy one original fixture file for audit/review."""
        if not source.exists():
            return
        target = self.root / "fixture" / (relative_name or source.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    def append_log(self, log_name: str, message: str) -> None:
        """Append one line to a sample-level log file."""
        log_path = self.root / "logs" / log_name
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(message.rstrip("\n") + "\n")


class TestRunArtifacts:
    """Creates and manages one persistent test run directory under tests/output."""

    def __init__(self, run_root: Path) -> None:
        self.run_root = run_root

    @classmethod
    def create(cls) -> "TestRunArtifacts":
        """Create one timestamped test-run directory."""
        OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("run-%Y-%m-%d_%H-%M-%S")
        run_root = OUTPUT_ROOT / timestamp
        suffix = 1
        while run_root.exists():
            suffix += 1
            run_root = OUTPUT_ROOT / f"{timestamp}-{suffix:02d}"
        run_root.mkdir(parents=True, exist_ok=False)
        _json_dump(
            run_root / "summary.json",
            {
                "created_at": datetime.now().isoformat(),
                "status": "running",
            },
        )
        return cls(run_root=run_root)

    def sample(self, fixture_name: str) -> SampleArtifacts:
        """Return one sample artifact block for the given fixture."""
        sample_root = self.run_root / f"sample-{_safe_name(fixture_name)}"
        sample_root.mkdir(parents=True, exist_ok=True)
        return SampleArtifacts(root=sample_root, fixture_name=fixture_name)

    def write_summary(self, payload: dict[str, Any]) -> None:
        """Overwrite the run-level summary.json."""
        _json_dump(self.run_root / "summary.json", payload)

