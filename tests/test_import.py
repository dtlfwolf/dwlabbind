import os
import tempfile
import unittest
from importlib import import_module
from unittest import mock
from datetime import datetime

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_server_class():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindServer


class TestBindConfImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_read_conf_with_include_and_zone(self) -> None:
        BindServer = _bind_server_class()
        with tempfile.TemporaryDirectory() as tmpdir:
            main_conf = os.path.join(tmpdir, "named.conf")
            include_conf = os.path.join(tmpdir, "zones.conf")
            zone_file = os.path.join(tmpdir, "example.com.zone")

            with open(zone_file, "w", encoding="utf-8") as handle:
                handle.write(
                    "$TTL 3600\n"
                    "@ IN SOA ns1.example.com. hostmaster.example.com. (2026012801 3600 600 1209600 3600)\n"
                    "@ IN NS ns1.example.com.\n"
                    "ns1 IN A 192.0.2.10\n"
                )

            with open(include_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    'zone "example.com" {\n'
                    '    type master;\n'
                    f'    file "{zone_file}";\n'
                    '};\n'
                )

            with open(main_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    'options { recursion yes; };\n'
                    f'include "{include_conf}";\n'
                )

            server = BindServer.fromConfFile(main_conf)

            self.assertEqual(server.name, main_conf)
            self.assertEqual(len(server._zone_files), 1)
            self.assertEqual(server._zone_files[0].zone_name, "example.com")

    def test_import_archive_fixture_named_conf(self) -> None:
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_import",
            "fixtures": [],
        }
        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"import start fixture={fixture_name}")

                    server = BindServer.fromConfFile(str(fixture.named_conf))

                    discovered_zones = sorted(zone.zone_name for zone in server._zone_files)
                    expected_zones = sorted(fixture.expected_zones)
                    scenario = sample.scenario(1, "import")
                    scenario.write_text("zones.txt", "\n".join(discovered_zones) + ("\n" if discovered_zones else ""))
                    if fixture.named_conf.exists():
                        scenario.copy_file(fixture.named_conf, "input/named.conf")

                    status_payload = {
                        "fixture": fixture_name,
                        "named_conf": str(fixture.named_conf),
                        "expected_zones": expected_zones,
                        "discovered_zones": discovered_zones,
                        "status": "passed",
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "import.log",
                        f"fixture={fixture_name} discovered_zones={len(discovered_zones)}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(server.source_path, str(fixture.named_conf))
                    self.assertTrue(discovered_zones)
                    self.assertTrue(set(expected_zones).issubset(set(discovered_zones)))

        self.artifacts.write_summary(summary)

    def test_archive_fixture_manifests_are_complete(self) -> None:
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    self.assertEqual(fixture.manifest["name"], fixture_name)
                    self.assertTrue(fixture.named_conf.is_absolute())
                    self.assertTrue(fixture.named_etc.is_absolute())
                    self.assertTrue(fixture.named_var.is_absolute())
                    self.assertIsInstance(fixture.expected_zones, list)
                    self.assertIsInstance(fixture.expected_package_managed_zones, list)
                    self.assertIsInstance(fixture.expected_managed_zones, list)
                    self.assertIsInstance(fixture.expected_unmanaged_zones, list)
                    self.assertIsInstance(fixture.expected_ddns_zones, list)
                    self.assertIsInstance(fixture.expected_reverse_zones, list)


if __name__ == "__main__":
    unittest.main()
