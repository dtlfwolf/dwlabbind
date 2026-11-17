"""Credential-bearing backups stay private even with a permissive umask."""

import os
from pathlib import Path
import stat
import tarfile

import pytest

from dwlabbind.archive_security import ArchiveSecurityError, DnsArchiveManifest
from dwlabbind.backup_security import PrivateFilePublisher
from dwlabbind.bind_conf import BindConfigurationManager, BindServer


def test_archive_manifest_and_xml_are_owner_only_under_umask_zero(tmp_path):
    conf = tmp_path / "etc/bind/named.conf"
    conf.parent.mkdir(parents=True)
    key = conf.parent / "ddns.key"
    key.write_text('key "test" { algorithm hmac-sha256; secret "c3ludGhldGljLXRlc3Q="; };\n')
    key.chmod(0o600)
    conf.write_text(f'include "{key}";\noptions {{}};\n')
    target = tmp_path / "private-backups/dns.tar"
    previous = os.umask(0)
    try:
        manager = BindConfigurationManager()
        manager.backup_named_conf(str(conf), str(target))
        xml = Path(manager.import_named_conf(str(conf)))
    finally:
        os.umask(previous)
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(xml.stat().st_mode) == 0o600
    with tarfile.open(target) as archive:
        assert archive.getmember(DnsArchiveManifest.NAME).mode == 0o600
        assert b"c3ludGhldGljLXRlc3Q=" in archive.extractfile(str(key).lstrip("/")).read()


def test_backup_overwrite_is_explicit_and_protects_new_content(tmp_path):
    conf = tmp_path / "named.conf"
    conf.write_text("options {};\n")
    target = tmp_path / "private/dns.tar"
    server = BindServer.fromConfFile(str(conf))
    server.backup(str(target))
    target.chmod(0o644)
    original = target.read_bytes()
    with pytest.raises(ArchiveSecurityError, match="already exists"):
        server.backup(str(target))
    assert target.read_bytes() == original
    server.backup(str(target), overwrite=True)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_backup_cannot_follow_or_replace_output_aliases(tmp_path, kind):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    original = tmp_path / "original"
    original.write_bytes(b"preserve")
    target = parent / "dns.tar"
    if kind == "symlink":
        target.symlink_to(original)
    else:
        os.link(original, target)
    with pytest.raises(ArchiveSecurityError):
        PrivateFilePublisher().publish(target, lambda stream: stream.write(b"private"), overwrite=True)
    assert original.read_bytes() == b"preserve"


def test_interrupted_backup_keeps_prior_archive_and_removes_partial(tmp_path):
    path = tmp_path / "private/dns.tar"
    publisher = PrivateFilePublisher()
    publisher.publish(path, lambda stream: stream.write(b"original"))

    class BrokenWriter:
        def write(self, stream):
            stream.write(b"private partial content")
            raise RuntimeError("injected failure")

    with pytest.raises(RuntimeError):
        publisher.publish(path, BrokenWriter().write, overwrite=True)
    assert path.read_bytes() == b"original"
    assert list(path.parent.iterdir()) == [path]


def test_public_or_symlinked_backup_directory_is_rejected(tmp_path):
    parent = tmp_path / "public"
    parent.mkdir(mode=0o755)
    with pytest.raises(ArchiveSecurityError):
        PrivateFilePublisher().publish(parent / "dns.tar", lambda stream: None)
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    link = tmp_path / "link"
    link.symlink_to(parent, target_is_directory=True)
    with pytest.raises(OSError):
        PrivateFilePublisher().publish(link / "dns.tar", lambda stream: None)
