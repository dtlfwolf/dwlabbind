import os
import tempfile
import unittest

from dwlabbind.importers import Bind9Importer, MsDnsImporter, PowerDnsImporter


class TestBind9Importer(unittest.TestCase):
    def test_import_bind9(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            zone_path = os.path.join(tmpdir, "db.example.com")
            with open(zone_path, "w", encoding="utf-8") as handle:
                handle.write(";")
            named_conf = os.path.join(tmpdir, "named.conf")
            with open(named_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    "options { recursion yes; dnssec-validation auto; };\n"
                    "zone \"example.com\" { type master; file \"db.example.com\"; };\n"
                )

            importer = Bind9Importer(named_conf)
            server = importer.import_server(name="ns1", ip="192.0.2.10")

            self.assertEqual(server.server_profile.server_type, "bind9")
            self.assertEqual(len(server.zones), 1)
            self.assertEqual(server.zones[0].name, "example.com")
            self.assertEqual(server.options.options.get("recursion"), "yes")
            self.assertEqual(server.options.options.get("dnssec-validation"), "auto")


class TestPowerDnsImporter(unittest.TestCase):
    def test_import_powerdns(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            zone_path = os.path.join(tmpdir, "db.example.com")
            with open(zone_path, "w", encoding="utf-8") as handle:
                handle.write(";")
            bind_conf = os.path.join(tmpdir, "named.conf")
            with open(bind_conf, "w", encoding="utf-8") as handle:
                handle.write("zone \"example.com\" { type master; file \"db.example.com\"; };")
            pdns_conf = os.path.join(tmpdir, "pdns.conf")
            with open(pdns_conf, "w", encoding="utf-8") as handle:
                handle.write(f"bind-config={bind_conf}\n")

            importer = PowerDnsImporter(pdns_conf)
            server = importer.import_server(name="pdns", ip="192.0.2.20")

            self.assertEqual(server.server_profile.server_type, "powerdns")
            self.assertEqual(len(server.zones), 1)
            self.assertEqual(server.zones[0].name, "example.com")


class TestMsDnsImporter(unittest.TestCase):
    def test_import_msdns_from_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            zone_path = os.path.join(tmpdir, "example.com.dns")
            with open(zone_path, "w", encoding="utf-8") as handle:
                handle.write(";")

            importer = MsDnsImporter(tmpdir)
            server = importer.import_server(name="msdns", ip="192.0.2.30")

            self.assertEqual(server.server_profile.server_type, "msdns")
            self.assertEqual(len(server.zones), 1)
            self.assertEqual(server.zones[0].name, "example.com")

    def test_import_msdns_from_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            zone_path = os.path.join(tmpdir, "example.com.dns")
            with open(zone_path, "w", encoding="utf-8") as handle:
                handle.write(";")
            list_path = os.path.join(tmpdir, "zones.list")
            with open(list_path, "w", encoding="utf-8") as handle:
                handle.write(f"example.com|{zone_path}|master|\n")

            importer = MsDnsImporter(list_path)
            server = importer.import_server(name="msdns", ip="192.0.2.30")

            self.assertEqual(len(server.zones), 1)
            self.assertEqual(server.zones[0].name, "example.com")


if __name__ == "__main__":
    unittest.main()
