import os
import tempfile
import unittest

from dwlabbind.bind_conf import BindServer


class TestBindConfImport(unittest.TestCase):
    def test_read_conf_with_include_and_zone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            main_conf = os.path.join(tmpdir, "named.conf")
            include_conf = os.path.join(tmpdir, "zones.conf")

            with open(include_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    'zone "example.com" {\\n'
                    '    type master;\\n'
                    '};\\n'
                )

            with open(main_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    'options { recursion yes; };\\n'
                    f'include "{include_conf}";\\n'
                )

            server = BindServer.readConf(main_conf)

            self.assertEqual(server.name, main_conf)
            self.assertEqual(len(server.zone_files), 1)
            self.assertEqual(server.zone_files[0].zone_name, "example.com")


if __name__ == "__main__":
    unittest.main()
