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


class TestDeleteZone(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_delete_zone_archive_fixture_and_write(self) -> None:
        BindServer, BindConfigurationManager = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_delete_zone",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"zone-delete start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    domain_name = "dwlabbind-delete.example"
                    dns_server_cidr = "10.201.30.40/24"
                    base_hostname = "ns1"
                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        create_result = manager.create_zone_and_write(
                            named_conf=str(fixture.named_conf),
                            domain_name=domain_name,
                            dns_server_cidr=dns_server_cidr,
                            base_hostname=base_hostname,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )
                        delete_result = manager.delete_zone_and_write(
                            named_conf=str(fixture.named_conf),
                            zone_name=domain_name,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                            remove_files=True,
                            delete_related=True,
                        )

                    forward_zone_file = fixture.named_var / "dwlab" / "dwlabbind-delete.example.zone"
                    reverse_zone_file = fixture.named_var / "dwlab" / "30.201.10.in-addr.arpa.zone"
                    generated_main_conf = fixture.named_etc / "dwlab.named.conf"
                    generated_group_conf = fixture.named_etc / "dwlab" / "dwlabbind-delete.example.key.conf"
                    generated_key_file = fixture.named_etc / "dwlab" / "keys" / "dwlabbind-delete.example.key.key"
                    main_conf_text = generated_main_conf.read_text(encoding="utf-8")
                    group_conf_text = (
                        generated_group_conf.read_text(encoding="utf-8")
                        if generated_group_conf.exists()
                        else ""
                    )
                    scenario = sample.scenario(8, "zone-delete")
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if generated_main_conf.exists():
                        scenario.copy_file(generated_main_conf, f"generated/{generated_main_conf.name}")
                    if generated_group_conf.exists():
                        scenario.copy_file(generated_group_conf, f"generated/{generated_group_conf.name}")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "create_result": create_result,
                        "delete_result": delete_result,
                        "generated_main_conf": str(generated_main_conf),
                        "generated_group_conf": str(generated_group_conf),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "zone-delete.log",
                        f"fixture={fixture_name} deleted_zones={','.join(delete_result['deleted_zones'])}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertIn(domain_name, delete_result["deleted_zones"])
                    self.assertIn("30.201.10.in-addr.arpa", delete_result["deleted_zones"])
                    self.assertFalse(forward_zone_file.exists())
                    self.assertFalse(reverse_zone_file.exists())
                    self.assertTrue(generated_main_conf.exists())
                    self.assertNotIn("dwlabbind-delete.example.key.conf", main_conf_text)
                    self.assertNotIn("dwlabbind-delete.example.key.key", main_conf_text)
                    if generated_group_conf.exists():
                        self.assertNotIn(domain_name, group_conf_text)
                        self.assertNotIn("30.201.10.in-addr.arpa", group_conf_text)
                    if generated_key_file.exists():
                        self.assertNotIn("dwlabbind-delete.example.key.key", main_conf_text)
                    self.assertTrue(os.path.exists(delete_result["xml"]))
                    self.assertTrue(os.path.exists(delete_result["conf"]))

        self.artifacts.write_summary(summary)


if __name__ == "__main__":
    unittest.main()
