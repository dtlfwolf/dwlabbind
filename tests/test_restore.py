import os
import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_conf_exports():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindServer, module.BindConfigurationManager


class TestRestore(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_restore_archive_fixture_after_initialize(self) -> None:
        BindServer, BindConfigurationManager = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_restore",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"restore start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    original_named_conf = fixture.named_conf.read_text(encoding="utf-8")
                    backup_tar = sample.root / "steps" / "10-restore" / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)

                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        init_result = manager.initialize_named_conf(
                            named_conf=str(fixture.named_conf),
                            backup_output=str(backup_tar),
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                            cleanup=False,
                        )

                    named_conf_path = fixture.named_etc / "named.conf"
                    if named_conf_path.exists() or named_conf_path.is_symlink():
                        named_conf_path.unlink()
                    named_conf_path.write_text("broken { config; };\n", encoding="utf-8")
                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    if generated_conf.exists():
                        generated_conf.unlink()
                    stale_group_conf = fixture.named_etc / "dwlab" / "stale-zone.conf"
                    stale_zone_file = fixture.named_var / "dwlab" / "stale-zone.example.zone"
                    stale_fixed_hosts = fixture.named_var / "dwlab" / "stale-zone.example.zone.FixedHosts"
                    stale_group_conf.parent.mkdir(parents=True, exist_ok=True)
                    stale_zone_file.parent.mkdir(parents=True, exist_ok=True)
                    stale_group_conf.write_text('zone "stale-zone.example" { type master; file "/var/lib/bind/dwlab/stale-zone.example.zone"; };\n', encoding="utf-8")
                    stale_zone_file.write_text("$TTL 3600\n@ IN SOA ns1.stale-zone.example. hostmaster.stale-zone.example. (2026010101 3600 600 1209600 3600)\n@ IN NS ns1.stale-zone.example.\n", encoding="utf-8")
                    stale_fixed_hosts.write_text("host IN A 192.0.2.99\n", encoding="utf-8")

                    with mock.patch.object(BindConfigurationManager, "_validate_existing_conf", return_value=None):
                        restore_result = manager.restore_named_conf(
                            named_conf=str(named_conf_path),
                            archive_path=str(backup_tar),
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )

                    restored_named_conf = fixture.named_etc / "named.conf"
                    restored_text = restored_named_conf.read_text(encoding="utf-8")
                    scenario = sample.scenario(10, "restore")
                    scenario.copy_file(fixture.named_conf, "input/named.conf.after")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "initialize_result": init_result,
                        "restore_result": restore_result,
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "restore.log",
                        f"fixture={fixture_name} archive={backup_tar} restored_named_conf={restored_named_conf}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(restore_result["archive"], str(backup_tar))
                    self.assertEqual(restore_result["named_conf"], str(restored_named_conf))
                    self.assertTrue(os.path.exists(restore_result["xml"]))
                    self.assertEqual(restored_text, original_named_conf)
                    self.assertFalse(stale_group_conf.exists())
                    self.assertFalse(stale_zone_file.exists())
                    self.assertFalse(stale_fixed_hosts.exists())

        self.artifacts.write_summary(summary)


if __name__ == "__main__":
    unittest.main()
