from unittest.mock import patch

import pytest

with patch("dwlabbasicpy.dwlabLogger.setup_logging"):
    from dwlabbind.bind_conf import BindServer


@pytest.mark.parametrize("release_location", ["local", "external"])
def test_configuration_write_preserves_deployment_releases(tmp_path, release_location):
    etc = tmp_path / "etc"
    var = tmp_path / "var"
    managed = etc / "dwlab"
    managed.mkdir(parents=True)
    release_root = managed / "releases"
    if release_location == "external":
        external = tmp_path / "external-releases"
        external.mkdir()
        release_root.symlink_to(external, target_is_directory=True)
    release = release_root / "release1"
    release.mkdir(parents=True)
    contents = {"zones.conf": "// zones\n", "options.conf": "// options\n"}
    for name, content in contents.items():
        (release / name).write_text(content)
    current = managed / "current"
    current.symlink_to(release, target_is_directory=True)
    local = etc / "named.conf.local"
    local_content = f'include "{current}/zones.conf";\n'
    local.write_text(local_content)
    (etc / "named.conf").write_text(f'include "{local}";\n')

    server = BindServer(name="test")
    server.create_zone_minimal("example.test", "192.0.2.30/24", "ns1")
    with patch.object(server, "_validate_layout"):
        server.toConfFile(named_etc=str(etc), named_var=str(var))

    assert current.is_symlink()
    assert local.read_text() == local_content
    for name, content in contents.items():
        assert (current / name).read_text() == content


def test_cleanup_preserves_unowned_files_and_removes_stale_generated_files(tmp_path):
    etc, var = tmp_path / "etc", tmp_path / "var"
    keys = etc / "dwlab" / "keys"
    zones = var / "dwlab"
    keys.mkdir(parents=True)
    zones.mkdir(parents=True)
    stale = [keys / "old.key", keys.parent / "old.conf", zones / "old.zone", zones / "old.zone.FixedHosts"]
    preserved = [keys.parent / "notes.txt", zones / "active.zone.jnl", keys / "notes.txt", zones / "active.zone"]
    for path in stale + preserved:
        path.write_text("original\n")
    server = BindServer(name="test")
    server._prune_managed_layout_files(
        {"files": {str(zones / "active.zone"): "original\n"}}, str(etc), str(var)
    )
    assert all(not path.exists() for path in stale)
    assert all(path.read_text() == "original\n" for path in preserved)
