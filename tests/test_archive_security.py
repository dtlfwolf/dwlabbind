"""Untrusted archives cannot select non-DNS targets or activate invalid data."""

import io
from pathlib import Path
import stat
import tarfile

import pytest

from dwlabbind.archive_security import ArchiveSecurityError, DnsArchiveManifest, DnsRestorePolicy, DnsRestoreTransaction
from dwlabbind.bind_conf import BindConfigurationManager


class ArchiveFixture:
    def __init__(self, root: Path) -> None:
        self.etc, self.var = root / "etc/bind", root / "var/lib/bind"
        self.etc.mkdir(parents=True)
        self.var.mkdir(parents=True)
        self.main = self.etc / "named.conf"
        self.main.write_text("options {};\n")
        self.archive = root / "backup.tar"
        self.transaction = DnsRestoreTransaction(DnsRestorePolicy((self.etc, self.var)))

    def valid(self, text="options {};\n") -> None:
        self.main.write_text(text)
        with tarfile.open(self.archive, "w") as archive:
            DnsArchiveManifest().add_files(archive, [str(self.main)])


@pytest.mark.parametrize("name,kind,link", [
    ("etc/cron.d/evil", tarfile.REGTYPE, ""), ("../../etc/passwd", tarfile.REGTYPE, ""),
    ("/etc/bind/named.conf", tarfile.REGTYPE, ""), ("etc/bind/fifo", tarfile.FIFOTYPE, ""),
    ("etc/bind/link", tarfile.SYMTYPE, "/etc/passwd"),
    ("etc/bind/link", tarfile.LNKTYPE, "../../etc/shadow"),
])
def test_unsafe_members_rejected_before_restore_writes(tmp_path, name, kind, link):
    fixture = ArchiveFixture(tmp_path)
    before = fixture.main.read_bytes()
    with tarfile.open(fixture.archive, "w") as archive:
        member = tarfile.TarInfo(name)
        member.type, member.linkname = kind, link
        member.size = 4 if kind == tarfile.REGTYPE else 0
        archive.addfile(member, io.BytesIO(b"evil") if member.isfile() else None)
    with pytest.raises(ArchiveSecurityError):
        fixture.transaction.plan(str(fixture.archive), allow_legacy=True)
    assert fixture.main.read_bytes() == before
    assert not (tmp_path / "etc/cron.d").exists()


def test_manifest_integrity_rejected(tmp_path):
    fixture = ArchiveFixture(tmp_path)
    fixture.valid()
    with tarfile.open(fixture.archive, "a") as archive:
        member = tarfile.TarInfo(str(fixture.etc / "injected.conf").lstrip("/"))
        member.size = 4
        archive.addfile(member, io.BytesIO(b"evil"))
    with pytest.raises(ArchiveSecurityError, match="integrity"):
        fixture.transaction.plan(str(fixture.archive))


def test_invalid_staged_configuration_leaves_live_files_untouched(tmp_path):
    fixture = ArchiveFixture(tmp_path)
    fixture.valid("invalid { syntax;\n")
    fixture.main.write_text("options {};\n")
    with pytest.raises(RuntimeError, match="named-checkconf failed"):
        fixture.transaction.restore(fixture.transaction.plan(str(fixture.archive)), fixture.main,
                                     BindConfigurationManager()._validate_existing_conf)
    assert fixture.main.read_text() == "options {};\n"


def test_failed_live_validation_rolls_back_content_and_mode(tmp_path):
    fixture = ArchiveFixture(tmp_path)
    fixture.valid("options { recursion no; };\n")
    fixture.main.write_text("options {};\n")
    fixture.main.chmod(0o644)

    class Validator:
        calls = 0

        def validate(self, path):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("live validation failed")

    with pytest.raises(RuntimeError):
        fixture.transaction.restore(fixture.transaction.plan(str(fixture.archive)), fixture.main, Validator().validate)
    assert fixture.main.read_text() == "options {};\n"
    assert stat.S_IMODE(fixture.main.stat().st_mode) == 0o644


def test_existing_symlink_cannot_redirect_restore(tmp_path):
    fixture = ArchiveFixture(tmp_path)
    fixture.valid()
    outside = tmp_path / "outside"
    outside.mkdir()
    fixture.main.unlink()
    fixture.etc.rmdir()
    fixture.etc.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ArchiveSecurityError):
        fixture.transaction.plan(str(fixture.archive))
    assert not list(outside.iterdir())


def test_legacy_requires_review_but_preserves_genuine_backup_support(tmp_path):
    fixture = ArchiveFixture(tmp_path)
    with tarfile.open(fixture.archive, "w") as archive:
        archive.add(fixture.main, arcname=str(fixture.main).lstrip("/"))
    with pytest.raises(ArchiveSecurityError, match="legacy"):
        fixture.transaction.plan(str(fixture.archive))
    entries = fixture.transaction.plan(str(fixture.archive), allow_legacy=True)
    fixture.transaction.restore(entries, fixture.main, BindConfigurationManager()._validate_existing_conf)
    assert fixture.main.read_text() == "options {};\n"


def test_configuration_cannot_make_validator_read_non_dns_files(tmp_path):
    fixture = ArchiveFixture(tmp_path)
    fixture.valid('include "/etc/shadow";\n')
    fixture.main.write_text("options {};\n")
    with pytest.raises(ArchiveSecurityError, match="outside approved DNS"):
        fixture.transaction.restore(fixture.transaction.plan(str(fixture.archive)), fixture.main,
                                     BindConfigurationManager()._validate_existing_conf)
    assert fixture.main.read_text() == "options {};\n"
