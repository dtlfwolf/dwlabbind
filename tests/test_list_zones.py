import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_manager_class():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindConfigurationManager


class TestListZones(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_list_zones_archive_fixtures(self) -> None:
        BindConfigurationManager = _bind_manager_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_list_zones",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"list-zones start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    zones = manager.list_zones_from_conf(str(fixture.named_conf))

                    discovered_zone_names = sorted(str(item.get("zone_name")) for item in zones)
                    expected_zones = sorted(fixture.expected_zones)
                    expected_package_managed_zones = sorted(fixture.expected_package_managed_zones)
                    expected_managed_zones = sorted(fixture.expected_managed_zones)
                    expected_unmanaged_zones = sorted(fixture.expected_unmanaged_zones)
                    expected_ddns_zones = sorted(fixture.expected_ddns_zones)
                    expected_reverse_zones = sorted(fixture.expected_reverse_zones)
                    discovered_package_managed_zones = sorted(
                        str(item.get("zone_name"))
                        for item in zones
                        if (item.get("management_state") == "package-managed")
                    )
                    discovered_managed_zones = sorted(
                        str(item.get("zone_name"))
                        for item in zones
                        if (item.get("management_state") == "managed")
                    )
                    discovered_unmanaged_zones = sorted(
                        str(item.get("zone_name"))
                        for item in zones
                        if (item.get("management_state") == "un-managed")
                    )
                    discovered_ddns_zones = sorted(
                        str(item.get("zone_name"))
                        for item in zones
                        if item.get("ddns_enabled")
                    )
                    discovered_reverse_zones = sorted(
                        str(item.get("zone_name"))
                        for item in zones
                        if item.get("reverse")
                    )

                    rendered_lines = []
                    for zone in zones:
                        status = zone.get("management_state") or (
                            "package-managed" if zone.get("externally_managed") else "un-managed"
                        )
                        direction = "reverse" if zone.get("reverse") else "forward"
                        ddns = "ddns" if zone.get("ddns_enabled") else "static"
                        rendered_lines.append(
                            f"{zone.get('zone_name')} | {direction} | {zone.get('zone_type') or '-'} | {ddns} | {status} | {zone.get('file_path')}"
                        )

                    scenario = sample.scenario(2, "list-zones")
                    scenario.write_text("zones.txt", "\n".join(rendered_lines) + ("\n" if rendered_lines else ""))
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    status_payload = {
                        "fixture": fixture_name,
                        "named_conf": str(fixture.named_conf),
                        "expected_zones": expected_zones,
                        "expected_package_managed_zones": expected_package_managed_zones,
                        "expected_managed_zones": expected_managed_zones,
                        "expected_unmanaged_zones": expected_unmanaged_zones,
                        "expected_ddns_zones": expected_ddns_zones,
                        "expected_reverse_zones": expected_reverse_zones,
                        "discovered_zones": discovered_zone_names,
                        "discovered_package_managed_zones": discovered_package_managed_zones,
                        "discovered_managed_zones": discovered_managed_zones,
                        "discovered_unmanaged_zones": discovered_unmanaged_zones,
                        "discovered_ddns_zones": discovered_ddns_zones,
                        "discovered_reverse_zones": discovered_reverse_zones,
                        "zone_count": len(zones),
                        "status": "passed",
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "list-zones.log",
                        f"fixture={fixture_name} zone_count={len(zones)} expected_matches={len(expected_zones)}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(zones)
                    self.assertTrue(set(expected_zones).issubset(set(discovered_zone_names)))
                    self.assertTrue(
                        set(expected_package_managed_zones).issubset(set(discovered_package_managed_zones))
                    )
                    self.assertTrue(set(expected_managed_zones).issubset(set(discovered_managed_zones)))
                    self.assertTrue(set(expected_unmanaged_zones).issubset(set(discovered_unmanaged_zones)))
                    self.assertTrue(set(expected_ddns_zones).issubset(set(discovered_ddns_zones)))
                    self.assertTrue(set(expected_reverse_zones).issubset(set(discovered_reverse_zones)))

        self.artifacts.write_summary(summary)


if __name__ == "__main__":
    unittest.main()
