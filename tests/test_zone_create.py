import os
import tempfile
import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_conf_exports():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindOperationError, module.BindServer, module.BindConfigurationManager


class TestZoneCreate(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_create_zone_archive_fixture_and_write(self) -> None:
        _, BindServer, BindConfigurationManager = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_zone_create",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"create-zone start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    domain_name = "dwlabbind-test.example"
                    dns_server_cidr = "10.200.30.40/24"
                    base_hostname = "ns1"
                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        result = manager.create_zone_and_write(
                            named_conf=str(fixture.named_conf),
                            domain_name=domain_name,
                            dns_server_cidr=dns_server_cidr,
                            base_hostname=base_hostname,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )

                    scenario = sample.scenario(6, "create-zone")
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    forward_zone_file = fixture.named_var / "dwlab" / "dwlabbind-test.example.zone"
                    reverse_zone_file = fixture.named_var / "dwlab" / "30.200.10.in-addr.arpa.zone"
                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "result": result,
                        "forward_zone_file": str(forward_zone_file),
                        "reverse_zone_file": str(reverse_zone_file),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "create-zone.log",
                        f"fixture={fixture_name} domain={domain_name} reverse_zone={result['reverse_zone']}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(result["domain"], domain_name)
                    self.assertEqual(result["reverse_zone"], "30.200.10.in-addr.arpa")
                    self.assertTrue(os.path.exists(result["xml"]))
                    self.assertTrue(os.path.exists(result["conf"]))
                    self.assertTrue(forward_zone_file.exists())
                    self.assertTrue(reverse_zone_file.exists())

        self.artifacts.write_summary(summary)

    def test_create_zone_minimal_adds_forward_and_reverse(self) -> None:
        _, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf = os.path.join(tmpdir, "named.conf")
            with open(named_conf, "w", encoding="utf-8") as handle:
                handle.write('options { recursion yes; };' + "\n")

            server = BindServer.fromConfFile(named_conf)
            result = server.create_zone_minimal(
                domain_name="example.com",
                dns_server_cidr="192.168.5.10/24",
                base_hostname="ns1",
            )

            self.assertEqual(result["domain"], "example.com")
            self.assertEqual(result["reverse_zone"], "5.168.192.in-addr.arpa")
            self.assertEqual(len(server._zone_files), 2)
            zone_names = {z.zone_name for z in server._zone_files}
            self.assertIn("example.com", zone_names)
            self.assertIn("5.168.192.in-addr.arpa", zone_names)

    def test_create_zone_minimal_rejects_existing_without_force(self) -> None:
        BindOperationError, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf = os.path.join(tmpdir, "named.conf")
            with open(named_conf, "w", encoding="utf-8") as handle:
                handle.write('options { recursion yes; };' + "\n")
            server = BindServer.fromConfFile(named_conf)
            server.create_zone_minimal("example.com", "192.168.5.10/24", "ns1")
            with self.assertRaises(BindOperationError) as exc:
                server.create_zone_minimal("example.com", "192.168.5.11/24", "ns1")
            self.assertEqual(exc.exception.code, "ZONE_ALREADY_EXISTS")


if __name__ == "__main__":
    unittest.main()
