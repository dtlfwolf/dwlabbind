import os
from pathlib import Path
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


class TestUpdateZone(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_update_zone_archive_fixture_and_write(self) -> None:
        BindServer, BindConfigurationManager = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_update_zone",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"zone-update start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    zone_name = fixture.expected_zones[0]
                    before_server = BindServer.fromConfFile(str(fixture.named_conf))
                    before_zone = next(zone for zone in before_server._zone_files if zone.zone_name == zone_name)
                    before_soa = before_zone.find_soa_record()
                    self.assertIsNotNone(before_soa, f"No SOA record found for zone {zone_name}")
                    before_serial = before_soa.serial or ""

                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        result = manager.update_zone_serial_and_write(
                            named_conf=str(fixture.named_conf),
                            zone_name=zone_name,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )

                    after_server = BindServer.fromConfFile(str(fixture.named_conf))
                    after_zone = next(zone for zone in after_server._zone_files if zone.zone_name == zone_name)
                    after_soa = after_zone.find_soa_record()
                    self.assertIsNotNone(after_soa, f"No SOA record found for zone {zone_name} after update")
                    after_serial = after_soa.serial or ""
                    written_zone_path = Path(str(result["file_path"]))
                    managed_zone_path = Path(str(fixture.named_var)) / "dwlab" / (
                        f"{before_server._normalize_name_for_filename(zone_name)}.zone"
                    )
                    inspected_zone_path = managed_zone_path if managed_zone_path.exists() else written_zone_path
                    written_zone_text = inspected_zone_path.read_text(encoding="utf-8")

                    scenario = sample.scenario(11, "zone-update")
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if inspected_zone_path.exists():
                        scenario.copy_file(inspected_zone_path, f"generated/{inspected_zone_path.name}")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "zone_name": zone_name,
                        "old_serial": before_serial,
                        "new_serial": after_serial,
                        "written_zone_file": str(inspected_zone_path),
                        "result": result,
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "zone-update.log",
                        f"fixture={fixture_name} zone={zone_name} old_serial={before_serial} new_serial={after_serial}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(result["zone"], zone_name)
                    self.assertEqual(result["old_serial"], before_serial)
                    self.assertEqual(result["new_serial"], after_serial)
                    self.assertNotEqual(before_serial, after_serial)
                    self.assertTrue(inspected_zone_path.exists())
                    self.assertIn(after_serial, written_zone_text)
                    self.assertTrue(os.path.exists(result["xml"]))
                    self.assertTrue(os.path.exists(result["conf"]))

        self.artifacts.write_summary(summary)


if __name__ == "__main__":
    unittest.main()
