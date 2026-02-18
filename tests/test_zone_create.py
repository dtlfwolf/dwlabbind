import os
import tempfile
import unittest

from dwlabbind.bind_conf import BindOperationError, BindServer


class TestZoneCreate(unittest.TestCase):
    def test_create_zone_minimal_adds_forward_and_reverse(self) -> None:
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
