import os
import tempfile
import unittest

from dwlabbind.bind_conf import BindServer, BindServerXmlSerializer
from tests.test_add_fixed_host import TestAddFixedHost


class TestXmlSerializer(unittest.TestCase):
    def _write_base_layout(self, tmpdir: str) -> tuple[str, str, str]:
        return TestAddFixedHost()._write_base_layout(tmpdir)

    def test_read_server_xml_roundtrip_preserves_zone_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            named_conf, _, _ = self._write_base_layout(tmpdir)
            server = BindServer.fromConfFile(named_conf)
            serializer = BindServerXmlSerializer()
            xml_path = os.path.join(tmpdir, "dwlabbind.xml")
            serializer.write_server_xml(server, xml_path)

            rebuilt = serializer.read_server_xml(xml_path)

            self.assertEqual(server.name, rebuilt.name)
            self.assertEqual(len(server._zone_files), len(rebuilt._zone_files))
            self.assertEqual(
                sorted(item.zone_name for item in server._zone_files),
                sorted(item.zone_name for item in rebuilt._zone_files),
            )


if __name__ == "__main__":
    unittest.main()
