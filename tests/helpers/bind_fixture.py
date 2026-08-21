"""Reusable fixture loader for archive-based dwlabbind integration tests."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
from typing import Any, Optional


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
ARCHIVES_DIR = FIXTURES_DIR / "archives"
MANIFESTS_DIR = FIXTURES_DIR / "manifests"
REQUIRED_MANIFEST_FIELDS: dict[str, type] = {
    "name": str,
    "named_conf": str,
    "named_etc": str,
    "named_var": str,
    "expected_zones": list,
    "expected_package_managed_zones": list,
    "expected_managed_zones": list,
    "expected_unmanaged_zones": list,
    "expected_ddns_zones": list,
    "expected_reverse_zones": list,
}


def validate_manifest_data(data: dict[str, Any], source: Path) -> dict[str, Any]:
    """Validate one fixture manifest and raise a clear error on malformed input."""
    missing = [key for key in REQUIRED_MANIFEST_FIELDS if key not in data]
    if missing:
        raise ValueError(f"Fixture manifest is missing required keys {missing}: {source}")

    for key, expected_type in REQUIRED_MANIFEST_FIELDS.items():
        value = data.get(key)
        if not isinstance(value, expected_type):
            raise ValueError(
                f"Fixture manifest field '{key}' must be {expected_type.__name__}: {source}"
            )
        if expected_type is list and not all(isinstance(item, str) for item in value):
            raise ValueError(f"Fixture manifest field '{key}' must contain only strings: {source}")

    for key in ("name", "named_conf", "named_etc", "named_var"):
        value = str(data.get(key, "")).strip()
        if not value:
            raise ValueError(f"Fixture manifest field '{key}' must not be empty: {source}")

    for key in ("named_conf", "named_etc", "named_var"):
        value = str(data[key])
        if not value.startswith("/"):
            raise ValueError(f"Fixture manifest field '{key}' must be an absolute path: {source}")

    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise ValueError(f"Fixture manifest field 'notes' must be a string when present: {source}")

    return data


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Fixture manifest must contain a JSON object: {path}")
    return validate_manifest_data(data, path)


def _fixture_file(base_name: str, suffix: str, *directories: Path) -> Optional[Path]:
    for directory in directories:
        candidate = directory / f"{base_name}{suffix}"
        if candidate.exists():
            return candidate
    return None


def discover_fixture_names() -> list[str]:
    """Return all fixture base names that have both an archive and a manifest."""
    manifest_names: set[str] = set()
    archive_names: set[str] = set()

    for directory in (MANIFESTS_DIR, ARCHIVES_DIR):
        if not directory.exists():
            continue
        for path in directory.glob("*.json"):
            manifest_names.add(path.stem)

    for suffix in ("*.tar", "*.tar.gz", "*.tgz"):
        for path in ARCHIVES_DIR.glob(suffix):
            name = path.name
            if name.endswith(".tar.gz"):
                archive_names.add(name[:-7])
            elif name.endswith(".tgz"):
                archive_names.add(name[:-4])
            elif name.endswith(".tar"):
                archive_names.add(name[:-4])

    return sorted(manifest_names.intersection(archive_names))


@dataclass
class BindFixture:
    """Represents one extracted named.conf fixture tree for integration tests."""

    name: str
    manifest_path: Path
    archive_path: Path
    manifest: dict[str, Any]
    temp_dir: Path
    rootfs: Path

    @classmethod
    def load(cls, name: str) -> "BindFixture":
        """Create a temporary extracted fixture from archive and manifest by base name."""
        manifest_path = _fixture_file(name, ".json", MANIFESTS_DIR, ARCHIVES_DIR)
        if manifest_path is None:
            raise FileNotFoundError(f"Fixture manifest not found for '{name}'")

        archive_path = _fixture_file(name, ".tar", ARCHIVES_DIR)
        if archive_path is None:
            archive_path = _fixture_file(name, ".tar.gz", ARCHIVES_DIR)
        if archive_path is None:
            archive_path = _fixture_file(name, ".tgz", ARCHIVES_DIR)
        if archive_path is None:
            raise FileNotFoundError(f"Fixture archive not found for '{name}'")

        manifest = _read_json(manifest_path)
        temp_dir = Path(tempfile.mkdtemp(prefix=f"{name}-", dir="/tmp"))
        rootfs = temp_dir / "rootfs"
        rootfs.mkdir(parents=True, exist_ok=True)

        fixture = cls(
            name=name,
            manifest_path=manifest_path,
            archive_path=archive_path,
            manifest=manifest,
            temp_dir=temp_dir,
            rootfs=rootfs,
        )
        fixture.extract()
        return fixture

    @classmethod
    def discover(cls) -> list[str]:
        """Return all fixture names that can be loaded successfully by base name."""
        return discover_fixture_names()

    @property
    def named_conf(self) -> Path:
        """Absolute path to the extracted named.conf file."""
        return self.abs_path(str(self.manifest["named_conf"]))

    @property
    def named_etc(self) -> Path:
        """Absolute path to the extracted named config directory."""
        return self.abs_path(str(self.manifest["named_etc"]))

    @property
    def named_var(self) -> Path:
        """Absolute path to the extracted named zone directory root."""
        return self.abs_path(str(self.manifest["named_var"]))

    @property
    def expected_zones(self) -> list[str]:
        """Zones expected to be visible after import."""
        zones = self.manifest.get("expected_zones", [])
        if not isinstance(zones, list):
            raise ValueError("expected_zones must be a JSON list")
        return [str(item) for item in zones]

    @property
    def expected_package_managed_zones(self) -> list[str]:
        """Zones expected to be classified as package-managed."""
        zones = self.manifest.get("expected_package_managed_zones", [])
        if not isinstance(zones, list):
            raise ValueError("expected_package_managed_zones must be a JSON list")
        return [str(item) for item in zones]

    @property
    def expected_managed_zones(self) -> list[str]:
        """Zones expected to be classified as managed."""
        zones = self.manifest.get("expected_managed_zones", [])
        if not isinstance(zones, list):
            raise ValueError("expected_managed_zones must be a JSON list")
        return [str(item) for item in zones]

    @property
    def expected_unmanaged_zones(self) -> list[str]:
        """Zones expected to be classified as un-managed."""
        zones = self.manifest.get("expected_unmanaged_zones", [])
        if not isinstance(zones, list):
            raise ValueError("expected_unmanaged_zones must be a JSON list")
        return [str(item) for item in zones]

    @property
    def expected_ddns_zones(self) -> list[str]:
        """Zones expected to have DDNS enabled."""
        zones = self.manifest.get("expected_ddns_zones", [])
        if not isinstance(zones, list):
            raise ValueError("expected_ddns_zones must be a JSON list")
        return [str(item) for item in zones]

    @property
    def expected_reverse_zones(self) -> list[str]:
        """Zones expected to be reverse lookup zones."""
        zones = self.manifest.get("expected_reverse_zones", [])
        if not isinstance(zones, list):
            raise ValueError("expected_reverse_zones must be a JSON list")
        return [str(item) for item in zones]

    def abs_path(self, root_relative_path: str) -> Path:
        """Resolve a path stored relative to '/' inside the extracted rootfs."""
        relative = (root_relative_path or "").strip()
        if not relative.startswith("/"):
            raise ValueError(f"Expected absolute root-relative path, got: {root_relative_path}")
        return self.rootfs / relative.lstrip("/")

    def extract(self) -> None:
        """Extract the archive into the temporary rootfs, preserving relative-to-/ paths."""
        with tarfile.open(self.archive_path, "r:*") as tar:
            for member in tar.getmembers():
                normalized = member.name.lstrip("/")
                if not normalized or normalized.startswith("../") or "/../" in normalized:
                    raise ValueError(f"Unsafe archive member path: {member.name}")
                target = self.rootfs / normalized
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if member.issym():
                    target.symlink_to(member.linkname)
                    continue
                if member.islnk():
                    link_target = self.rootfs / member.linkname.lstrip("/")
                    target.hardlink_to(link_target)
                    continue
                if member.isfile():
                    source = tar.extractfile(member)
                    if source is None:
                        continue
                    with source, target.open("wb") as handle:
                        shutil.copyfileobj(source, handle)
        self._rebase_absolute_paths()

    def _rebase_absolute_paths(self) -> None:
        """Rewrite extracted absolute /etc and /var references to the temporary rootfs."""
        replacements = {
            '"/etc/': f'"{self.rootfs}/etc/',
            '"/var/': f'"{self.rootfs}/var/',
            " /etc/": f" {self.rootfs}/etc/",
            " /var/": f" {self.rootfs}/var/",
        }
        for path in self.rootfs.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except Exception:
                continue
            updated = content
            for old, new in replacements.items():
                updated = updated.replace(old, new)
            if updated != content:
                path.write_text(updated, encoding="utf-8")

    def read_text(self, root_relative_path: str, encoding: str = "utf-8") -> str:
        """Read one extracted text file by its original root-relative path."""
        return self.abs_path(root_relative_path).read_text(encoding=encoding)

    def cleanup(self) -> None:
        """Delete the extracted temporary fixture tree."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def __enter__(self) -> "BindFixture":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()
