"""Atomic owner-only publication of credential-bearing DNS backups and exports."""

from __future__ import annotations

from contextlib import contextmanager
from functools import partial
import os
from pathlib import Path
import stat
import tarfile
from typing import BinaryIO, Callable, Iterable
from uuid import uuid4

from .archive_security import ArchiveSecurityError, DnsArchiveManifest


class PrivateFilePublisher:
    """Never expose partial/private content or follow output path aliases."""

    @contextmanager
    def _directory(self, path: Path, require_private: bool):
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in path.parts[1:]:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                info = os.fstat(descriptor)
                sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not sticky_root):
                    raise ArchiveSecurityError("Backup/export directory ancestry is untrusted")
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or (require_private and info.st_mode & 0o077):
                raise ArchiveSecurityError("Backup directory must be owner-controlled and private (0700)")
            yield descriptor
        finally:
            os.close(descriptor)

    def _check_target(self, directory: int, name: str, overwrite: bool) -> None:
        try:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ArchiveSecurityError("Backup/export target must be an owned regular, unlinked file")
        if not overwrite:
            raise ArchiveSecurityError("Backup already exists; choose a new name or explicitly allow overwrite")

    def publish(self, path: Path, writer: Callable[[BinaryIO], None], *,
                overwrite: bool = False, private_directory: bool = True) -> None:
        """Fsync and atomically publish 0600 content without changing process umask."""
        path = path.absolute()
        if ".." in path.parts:
            raise ArchiveSecurityError("Backup/export paths cannot contain traversal")
        with self._directory(path.parent, private_directory) as directory:
            self._check_target(directory, path.name, overwrite)
            temporary = f".dwlabbind-private-{uuid4().hex}"
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    writer(stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._check_target(directory, path.name, overwrite)
                os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass


class DnsBackupWriter:
    """Protect the full archive, including its embedded manifest and TSIG keys."""

    def write(self, path: Path, files: Iterable[str], *, overwrite: bool = False) -> None:
        PrivateFilePublisher().publish(path, partial(self._write_archive, files=tuple(files)),
                                       overwrite=overwrite)

    def _write_archive(self, stream: BinaryIO, *, files: tuple[str, ...]) -> None:
        with tarfile.open(fileobj=stream, mode="w") as archive:
            DnsArchiveManifest().add_files(archive, files)
