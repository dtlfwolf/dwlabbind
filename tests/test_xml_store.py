import os
import tempfile
import unittest

from dwlabbind.models import BindServer, BindZone
from dwlabbind.xml_store import XmlConfigStore


class TestXmlStore(unittest.TestCase):
    def test_save_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "bind.xml")
            store = XmlConfigStore(path)
            server = BindServer(
                name="ns1",
                ip="192.0.2.10",
                zones=[BindZone(name="example.com", zone_type="master", file="db.example.com")],
            )

            store.save(server)
            loaded = store.load()

            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.name, "ns1")
            self.assertEqual(loaded.ip, "192.0.2.10")
            self.assertEqual(len(loaded.zones), 1)
            self.assertEqual(loaded.zones[0].name, "example.com")

    def test_load_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "missing.xml")
            store = XmlConfigStore(path)
            self.assertIsNone(store.load())


if __name__ == "__main__":
    unittest.main()
