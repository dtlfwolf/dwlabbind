"""DNS-scoped archive planning and validated, rollback-capable restoration."""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from tempfile import TemporaryDirectory
from typing import Callable, Iterable
from uuid import uuid4


class ArchiveSecurityError(RuntimeError):
    """An archive is not safe for the approved DNS installation."""


class DnsArchiveManifest:
    """Integrity metadata; target authorization always comes from local policy."""

    NAME = ".dwlabbind-manifest.json"

    def add_files(self, archive: tarfile.TarFile, files: Iterable[str]) -> None:
        hashes = {}
        for name in dict.fromkeys(files):
            source = Path(name)
            if not source.is_file():
                continue
            content = source.read_bytes()
            member = archive.gettarinfo(str(source), arcname=str(source.absolute()).lstrip("/"))
            # Flatten file aliases, not their parent directory trees.
            member.type, member.linkname, member.size = tarfile.REGTYPE, "", len(content)
            archive.addfile(member, io.BytesIO(content))
            hashes[member.name] = hashlib.sha256(content).hexdigest()
        content = json.dumps({"schema": "dwlabbind-backup/v1", "files": hashes}, sort_keys=True).encode()
        member = tarfile.TarInfo(self.NAME)
        member.size, member.mode = len(content), 0o600
        archive.addfile(member, io.BytesIO(content))


@dataclass(frozen=True)
class RestoreEntry:
    """A verified archive file, never an executable extraction instruction."""

    path: Path
    target: Path
    content: bytes
    readonly: bool = False


class DnsRestorePolicy:
    """Only explicitly approved DNS roots can authorize writes or cleanup."""

    def __init__(self, roots: Iterable[Path] = (Path("/etc/bind"), Path("/var/lib/bind"),
                                               Path("/var/cache/bind"))) -> None:
        self.roots = tuple(Path(root).absolute() for root in roots)
        for root in self.roots:
            if root.parts[-3:] == ("var", "lib", "bind"):
                cache = root.parent.parent / "cache/bind"
                if cache not in self.roots:
                    self.roots += (cache,)
        if not self.roots or any(str(root) in {"/", "/etc", "/var", "/tmp", "/usr", "/home"}
                                 or ".." in root.parts or root != root.resolve() for root in self.roots):
            raise ArchiveSecurityError("Restore roots must be dedicated DNS directories")

    def target(self, path: Path) -> Path:
        """Resolve current aliases only if both spelling and referent remain scoped."""
        if not any(path.is_relative_to(root) and path != root for root in self.roots):
            raise ArchiveSecurityError("Archive target is outside approved DNS roots")
        resolved = path.resolve()
        if not any(resolved.is_relative_to(root) and resolved != root
                   for root in self.roots):
            raise ArchiveSecurityError("Restore target follows a link outside DNS roots")
        if resolved.exists() and not resolved.is_file():
            raise ArchiveSecurityError("Restore cannot replace a directory or special file")
        return path.parent.resolve() / path.name


class DnsRestoreTransaction:
    """Preflight every member, stage configuration, then write with rollback."""

    def __init__(self, policy: DnsRestorePolicy,
                 protected: Callable[[str], bool] | None = None) -> None:
        self.policy = policy
        self.protected = protected or (lambda path: False)

    def plan(self, archive_path: str, *, allow_legacy: bool = False) -> list[RestoreEntry]:
        entries, links, hashes = {}, {}, {}
        manifest = None
        total = 0
        with tarfile.open(archive_path, "r:*") as archive:
            for number, member in enumerate(archive):
                name = PurePosixPath(member.name)
                if (number >= 20000 or name.is_absolute() or ".." in name.parts
                        or "\\" in member.name or any(ord(char) < 32 for char in member.name)):
                    raise ArchiveSecurityError("Unsafe or excessive archive member path")
                normalized = str(name)
                if normalized in entries or normalized in links:
                    raise ArchiveSecurityError("Duplicate archive member")
                if member.isdir():
                    raise ArchiveSecurityError("Archive directory members are not accepted")
                if member.issym() or member.islnk():
                    if not allow_legacy:
                        raise ArchiveSecurityError("Archive links require explicit legacy review")
                    target = PurePosixPath(member.linkname)
                    if target.is_absolute() or ".." in target.parts:
                        raise ArchiveSecurityError("Legacy archive link escapes its scope")
                    links[normalized] = str(target if member.islnk() else name.parent / target)
                    continue
                if not member.isfile() or member.issparse() or not 0 <= member.size <= 67108864:
                    raise ArchiveSecurityError("Unexpected or excessive archive member type/size")
                total += member.size
                if total > 1073741824:
                    raise ArchiveSecurityError("Archive exceeds restore size limit")
                content = archive.extractfile(member).read()
                if normalized == DnsArchiveManifest.NAME:
                    if manifest is not None:
                        raise ArchiveSecurityError("Duplicate archive manifest")
                    try:
                        manifest = json.loads(content)
                    except (ValueError, UnicodeDecodeError):
                        raise ArchiveSecurityError("Invalid archive manifest") from None
                else:
                    entries[normalized] = content
                    hashes[normalized] = hashlib.sha256(content).hexdigest()
        if manifest is None and not allow_legacy:
            raise ArchiveSecurityError("Legacy archive requires explicit --allow-legacy-archive review")
        if manifest is not None and (not isinstance(manifest, dict)
                                     or manifest.get("schema") != "dwlabbind-backup/v1"
                                     or manifest.get("files") != hashes or links):
            raise ArchiveSecurityError("Archive manifest integrity check failed")
        for name in links:
            current, visited = name, set()
            while current in links:
                if current in visited:
                    raise ArchiveSecurityError("Cyclic archive links")
                visited.add(current)
                current = links[current]
            if current not in entries:
                raise ArchiveSecurityError("Legacy link target is not an archived regular file")
            entries[name] = entries[current]
        planned = []
        canonical = {}
        for name, content in entries.items():
            path = Path("/") / name
            readonly = self.protected(str(path))
            if path.is_relative_to(Path("/usr/share/dns")):
                readonly = True
            target = path if path.is_relative_to(Path("/usr/share/dns")) else self.policy.target(path)
            if target in canonical and canonical[target] != content:
                raise ArchiveSecurityError("Conflicting archive aliases")
            canonical[target] = content
            planned.append(RestoreEntry(path, target, content, readonly))
        return planned

    def restore(self, entries: list[RestoreEntry], named_conf: Path,
                validator: Callable[[str], None]) -> None:
        if named_conf not in {entry.path for entry in entries}:
            raise ArchiveSecurityError("Archive does not contain the approved named.conf")
        with TemporaryDirectory(prefix="dwlabbind-restore-") as temporary:
            stage = Path(temporary)
            mappings = sorted({str(root) for root in self.policy.roots} | {"/usr/share/dns"}, key=len, reverse=True)
            for root in self.policy.roots:
                (stage / str(root).lstrip("/")).mkdir(parents=True, exist_ok=True)
            for entry in entries:
                destination = stage / str(entry.path).lstrip("/")
                destination.parent.mkdir(parents=True, exist_ok=True)
                content = entry.path.read_bytes() if entry.readonly and entry.path.is_file() else entry.content
                try:
                    text = content.decode("utf-8")
                except UnicodeDecodeError:
                    destination.write_bytes(content)
                    continue
                # Rewrite paths only in the isolated validation copy, never live data.
                if re.search(r'\b(?:dlz|dyndb|plugin)\s+["{]', text):
                    raise ArchiveSecurityError("Plugin configurations require separate manual recovery review")
                pattern = r'(?P<prefix>\b(?:include|file|directory|pid-file|session-keyfile|managed-keys-directory|key-directory|dump-file|statistics-file|memstatistics-file|recursing-file|secroots-file|bindkeys-file)\s+)(?P<quote>["\x27])(?P<path>/[^"\x27]*)(?P=quote)'
                def relocate(match):
                    value = match.group("path")
                    allowed = mappings + ["/run/named", "/var/run/named", "/var/log/named"]
                    for root in self.policy.roots:
                        if root.parts[-2:] == ("etc", "bind"):
                            base = root.parent.parent
                            allowed += [str(base / suffix) for suffix in ("run/named", "var/run/named", "var/log/named")]
                    if ".." in Path(value).parts or not any(value == root or value.startswith(root + "/") for root in allowed):
                        raise ArchiveSecurityError("Configuration references a path outside approved DNS locations")
                    value = str(stage / value.lstrip("/"))
                    return match.group("prefix") + match.group("quote") + value + match.group("quote")
                destination.write_text(re.sub(pattern, relocate, text))
            validator(str(stage / str(named_conf).lstrip("/")))
        snapshots = {}
        try:
            for entry in entries:
                if entry.readonly or entry.target in snapshots:
                    continue
                # Recheck immediately before opening an anchored, no-follow parent.
                target = self.policy.target(entry.path)
                if target != entry.target:
                    raise ArchiveSecurityError("Restore target changed after validation")
                info = target.stat() if target.exists() else None
                with self._parent(target) as directory:
                    try:
                        link_info = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        link_info = None
                    if link_info is not None and stat.S_ISLNK(link_info.st_mode):
                        snapshots[target] = (os.readlink(target.name, dir_fd=directory), link_info)
                        self._write(target, entry.content, link_info)
                        continue
                    try:
                        source = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                    except FileNotFoundError:
                        snapshots[target] = (None, None)
                    else:
                        with os.fdopen(source, "rb") as stream:
                            info = os.fstat(stream.fileno())
                            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                                raise ArchiveSecurityError("Untrusted existing restore file")
                            original = stream.read(67108865)
                            if len(original) > 67108864:
                                raise ArchiveSecurityError("Existing restore target exceeds size limit")
                            snapshots[target] = (original, info)
                self._write(target, entry.content, info)
            validator(str(named_conf))
        except BaseException:
            for target, (content, info) in reversed(list(snapshots.items())):
                if content is None:
                    with self._parent(target) as directory:
                        try:
                            os.unlink(target.name, dir_fd=directory)
                        except FileNotFoundError:
                            pass
                elif isinstance(content, str):
                    with self._parent(target) as directory:
                        os.unlink(target.name, dir_fd=directory)
                        os.symlink(content, target.name, dir_fd=directory)
                else:
                    self._write(target, content, info, restore_metadata=True)
            raise

    @contextmanager
    def _parent(self, path: Path):
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parent.parts[1:]:
                try:
                    os.mkdir(part, 0o750, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            yield descriptor
        finally:
            os.close(descriptor)

    def _write(self, path: Path, content: bytes, previous, *, restore_metadata: bool = False) -> None:
        with self._parent(path) as directory:
            temporary = f".dwlabbind-restore-{uuid4().hex}"
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o640, dir_fd=directory)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    os.fchmod(output.fileno(), stat.S_IMODE(previous.st_mode) if restore_metadata else 0o640)
                    if os.geteuid() == 0:
                        import grp
                        owner = previous.st_uid if previous is not None else 0
                        group = previous.st_gid if previous is not None and (owner != 0 or restore_metadata) else grp.getgrnam("bind").gr_gid
                        os.fchown(output.fileno(), owner, group)
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                    if restore_metadata:
                        os.utime(output.fileno(), ns=(previous.st_atime_ns, previous.st_mtime_ns))
                os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
