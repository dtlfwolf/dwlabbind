import os
import tempfile
import unittest
from unittest import mock

from dwlabbind.bind_conf import BindOperationError, BindServer


class TestAddFixedHost(unittest.TestCase):
    def _write_base_layout(self, tmpdir: str) -> tuple[str, str, str]:
        named_conf = os.path.join(tmpdir, "named.conf")
        forward_zone_file = os.path.join(tmpdir, "db.example.com")
        reverse_zone_file = os.path.join(tmpdir, "db.2.0.192")
        with open(named_conf, "w", encoding="utf-8") as handle:
            handle.write(
                'options { recursion yes; };'
                "\n"
                f'zone "example.com" {{ type master; file "{forward_zone_file}"; }};'
                "\n"
                f'zone "2.0.192.in-addr.arpa" {{ type master; file "{reverse_zone_file}"; }};'
                "\n"
            )
        with open(forward_zone_file, "w", encoding="utf-8") as handle:
            handle.write(
                "$TTL 3600\n"
                "@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 1209600 3600\n"
                "@ IN NS ns1.example.com.\n"
            )
        with open(reverse_zone_file, "w", encoding="utf-8") as handle:
            handle.write(
                "$TTL 3600\n"
                "@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 1209600 3600\n"
                "@ IN NS ns1.example.com.\n"
            )
        return named_conf, forward_zone_file, reverse_zone_file

    def test_add_fixed_host_adds_forward_and_reverse_records(self) -> None:
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
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, _, _ = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                server.add_fixed_host("host.example.com", "192.0.2.10")
                with self.assertRaises(BindOperationError) as exc:
                    server.add_fixed_host("host.example.com", "192.0.2.11")
            self.assertEqual(exc.exception.code, "HOST_EXISTS")

    def test_add_fixed_host_migrates_exact_existing_zone_records_to_fixedhosts(self) -> None:
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
