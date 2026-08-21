import os
import tempfile
import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_layouts import write_base_host_layout
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_conf_exports():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindOperationError, module.BindServer, module.BindConfigurationManager


class TestAddFixedHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def _write_base_layout(self, tmpdir: str) -> tuple[str, str, str]:
        return write_base_host_layout(tmpdir)

    def test_add_fixed_host_archive_fixture_and_write(self) -> None:
        _, BindServer, BindConfigurationManager = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_add_fixed_host",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"add-fixed-host start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    fqdn = "dwlabbind-test-host-01.dw-lab.de"
                    ip_address = "10.100.0.250"
                    with (
                        mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None),
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                    ):
                        result = manager.add_fixed_host_and_write(
                            named_conf=str(fixture.named_conf),
                            fqdn=fqdn,
                            ip_address=ip_address,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )

                    scenario = sample.scenario(4, "add-fixed-host")
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    forward_fixed = fixture.named_var / "dwlab" / "dw-lab.de.zone.FixedHosts"
                    reverse_fixed = fixture.named_var / "dwlab" / "0.100.10.in-addr.arpa.zone.FixedHosts"
                    forward_text = forward_fixed.read_text(encoding="utf-8") if forward_fixed.exists() else ""
                    reverse_text = reverse_fixed.read_text(encoding="utf-8") if reverse_fixed.exists() else ""
                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "fqdn": fqdn,
                        "ip": ip_address,
                        "result": result,
                        "forward_fixed_hosts": str(forward_fixed),
                        "reverse_fixed_hosts": str(reverse_fixed),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "add-fixed-host.log",
                        f"fixture={fixture_name} fqdn={fqdn} ip={ip_address} forward_zone={result['forward_zone']} reverse_zone={result['reverse_zone']}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(os.path.exists(result["xml"]))
                    self.assertTrue(os.path.exists(result["conf"]))
                    self.assertTrue(forward_fixed.exists())
                    self.assertTrue(reverse_fixed.exists())
                    self.assertIn("10.100.0.250", forward_text)
                    self.assertIn("dwlabbind-test-host-01", forward_text)
                    self.assertIn("250", reverse_text)
                    self.assertIn("dwlabbind-test-host-01.dw-lab.de.", reverse_text)

        self.artifacts.write_summary(summary)

    def test_add_fixed_host_adds_forward_and_reverse_records(self) -> None:
        _, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, forward_zone_file, reverse_zone_file = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                result = server.add_fixed_host("host.example.com", "192.0.2.10")

            self.assertEqual(result["forward_zone"], "example.com")
            self.assertEqual(result["reverse_zone"], "2.0.192.in-addr.arpa")

            with open(forward_zone_file, "r", encoding="utf-8") as handle:
                forward_content = handle.read()
            with open(reverse_zone_file, "r", encoding="utf-8") as handle:
                reverse_content = handle.read()
            self.assertIn("$INCLUDE", forward_content)
            self.assertIn("$INCLUDE", reverse_content)

            with open(f"{forward_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_forward = handle.read()
            with open(f"{reverse_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_reverse = handle.read()
            self.assertIn("host IN A 192.0.2.10", fixed_forward)
            self.assertIn("10 IN PTR host.example.com.", fixed_reverse)

    def test_add_fixed_host_rejects_conflicting_duplicate(self) -> None:
        BindOperationError, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, _, _ = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                server.add_fixed_host("host.example.com", "192.0.2.10")
                with self.assertRaises(BindOperationError) as exc:
                    server.add_fixed_host("host.example.com", "192.0.2.11")
            self.assertEqual(exc.exception.code, "HOST_EXISTS")

    def test_add_fixed_host_migrates_exact_existing_zone_records_to_fixedhosts(self) -> None:
        _, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, forward_zone_file, reverse_zone_file = self._write_base_layout(tmpdir)
            with open(forward_zone_file, "a", encoding="utf-8") as handle:
                handle.write("host IN A 192.0.2.10\n")
            with open(reverse_zone_file, "a", encoding="utf-8") as handle:
                handle.write("10 IN PTR host.example.com.\n")

            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                server.add_fixed_host("host.example.com", "192.0.2.10")

            with open(forward_zone_file, "r", encoding="utf-8") as handle:
                forward_content = handle.read()
            with open(reverse_zone_file, "r", encoding="utf-8") as handle:
                reverse_content = handle.read()
            self.assertNotIn("host IN A 192.0.2.10\n", forward_content)
            self.assertNotIn("10 IN PTR host.example.com.\n", reverse_content)
            self.assertIn("$INCLUDE", forward_content)
            self.assertIn("$INCLUDE", reverse_content)

            with open(f"{forward_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_forward = handle.read()
            with open(f"{reverse_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_reverse = handle.read()
            self.assertIn("host IN A 192.0.2.10", fixed_forward)
            self.assertIn("10 IN PTR host.example.com.", fixed_reverse)

    def test_add_fixed_host_force_overwrites_existing_mapping(self) -> None:
        _, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, forward_zone_file, reverse_zone_file = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                server.add_fixed_host("host.example.com", "192.0.2.10")
                server.add_fixed_host("host.example.com", "192.0.2.11", force=True)

            with open(f"{forward_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_forward = handle.read()
            with open(f"{reverse_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_reverse = handle.read()
            self.assertIn("host IN A 192.0.2.11", fixed_forward)
            self.assertNotIn("host IN A 192.0.2.10", fixed_forward)
            self.assertIn("11 IN PTR host.example.com.", fixed_reverse)
            self.assertNotIn("10 IN PTR host.example.com.", fixed_reverse)

    def test_add_fixed_host_in_memory_only_does_not_write_zone_files(self) -> None:
        _, BindServer, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, forward_zone_file, reverse_zone_file = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            server.add_fixed_host("host.example.com", "192.0.2.10", persist=False)

            self.assertFalse(os.path.exists(f"{forward_zone_file}.FixedHosts"))
            self.assertFalse(os.path.exists(f"{reverse_zone_file}.FixedHosts"))
            zone = next(z for z in server._zone_files if z.zone_name == "example.com")
            self.assertTrue(any("IN A 192.0.2.10" in item.value for item in zone.fixed_host_statements))


if __name__ == "__main__":
    unittest.main()
