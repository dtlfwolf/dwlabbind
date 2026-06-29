import tempfile
import unittest
from unittest import mock

from dwlabbind.bind_conf import BindOperationError, BindServer, ZoneResourceRecord
from tests.test_add_fixed_host import TestAddFixedHost


class TestDeleteFixedHost(unittest.TestCase):
    def _write_base_layout(self, tmpdir: str) -> tuple[str, str, str]:
        return TestAddFixedHost()._write_base_layout(tmpdir)

    def test_delete_fixed_host_removes_forward_and_reverse_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, forward_zone_file, reverse_zone_file = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                server.add_fixed_host("host.example.com", "192.0.2.10")
                result = server.delete_fixed_host("host.example.com", "192.0.2.10")

            self.assertEqual(result["removed_forward_records"], 1)
            self.assertEqual(result["removed_reverse_records"], 1)

            with open(f"{forward_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_forward = handle.read()
            with open(f"{reverse_zone_file}.FixedHosts", "r", encoding="utf-8") as handle:
                fixed_reverse = handle.read()
            self.assertNotIn("host IN A 192.0.2.10", fixed_forward)
            self.assertNotIn("10 IN PTR host.example.com.", fixed_reverse)

    def test_delete_fixed_host_without_ip_removes_all_forward_records(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, _, _ = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with self.assertRaises(BindOperationError) as exc:
                server.delete_fixed_host("missing.example.com", persist=False)
            self.assertEqual(exc.exception.code, "HOST_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
