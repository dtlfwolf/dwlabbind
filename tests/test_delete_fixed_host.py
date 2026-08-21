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
    return module.BindOperationError, module.BindServer, module.BindConfigurationManager, module.ZoneResourceRecord


class TestDeleteFixedHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def _write_base_layout(self, tmpdir: str) -> tuple[str, str, str]:
        return write_base_host_layout(tmpdir)

    def test_delete_fixed_host_archive_fixture_and_write(self) -> None:
        _, BindServer, BindConfigurationManager, _ = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_delete_fixed_host",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"delete-fixed-host start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    fqdn = "dwlabbind-test-host-02.dw-lab.de"
                    ip_address = "10.100.0.251"
                    with (
                        mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None),
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                    ):
                        manager.add_fixed_host_and_write(
                            named_conf=str(fixture.named_conf),
                            fqdn=fqdn,
                            ip_address=ip_address,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )
                        result = manager.delete_fixed_host_and_write(
                            named_conf=str(fixture.named_conf),
                            fqdn=fqdn,
                            ip_address=ip_address,
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )

                    scenario = sample.scenario(5, "delete-fixed-host")
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
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "delete-fixed-host.log",
                        f"fixture={fixture_name} fqdn={fqdn} removed_forward={result['removed_forward_records']} removed_reverse={result['removed_reverse_records']}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(result["removed_forward_records"] >= 1)
                    self.assertTrue(result["removed_reverse_records"] >= 1)
                    self.assertNotIn("10.100.0.251", forward_text)
                    self.assertNotIn("dwlabbind-test-host-02", forward_text)
                    self.assertNotIn("251", reverse_text)
                    self.assertNotIn("dwlabbind-test-host-02.dw-lab.de.", reverse_text)

        self.artifacts.write_summary(summary)

    def test_delete_fixed_host_removes_forward_and_reverse_records(self) -> None:
        _, BindServer, _, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, forward_zone_file, reverse_zone_file = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                server.add_fixed_host("host.example.com", "192.0.2.10")
                result = server.delete_fixed_host("host.example.com", "192.0.2.10")

            self.assertEqual(result["removed_forward_records"], 1)
            self.assertEqual(result["removed_reverse_records"], 1)
            self.assertFalse(os.path.exists(f"{forward_zone_file}.FixedHosts"))
            self.assertFalse(os.path.exists(f"{reverse_zone_file}.FixedHosts"))

    def test_delete_fixed_host_without_ip_removes_all_forward_records(self) -> None:
        _, BindServer, _, ZoneResourceRecord = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, _, _ = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            zone = next(z for z in server._zone_files if z.zone_name == "example.com")
            zone.fixed_host_statements.extend(
                [
                    ZoneResourceRecord.fromText("host IN A 192.0.2.10"),
                    ZoneResourceRecord.fromText("host IN A 192.0.2.11"),
                ]
            )
            reverse_zone = next(z for z in server._zone_files if z.zone_name == "2.0.192.in-addr.arpa")
            reverse_zone.fixed_host_statements.extend(
                [
                    ZoneResourceRecord.fromText("10 IN PTR host.example.com."),
                    ZoneResourceRecord.fromText("11 IN PTR host.example.com."),
                ]
            )

            result = server.delete_fixed_host("host.example.com", persist=False)

            self.assertEqual(result["removed_forward_records"], 2)
            self.assertEqual(result["removed_reverse_records"], 2)
            self.assertFalse(
                any("host IN A " in stmt.value for stmt in zone.fixed_host_statements if hasattr(stmt, "value"))
            )

    def test_delete_fixed_host_raises_when_host_missing(self) -> None:
        BindOperationError, BindServer, _, _ = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, _, _ = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with self.assertRaises(BindOperationError) as exc:
                server.delete_fixed_host("missing.example.com", persist=False)
            self.assertEqual(exc.exception.code, "HOST_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
