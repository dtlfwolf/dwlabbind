import os
import tempfile
import unittest
from datetime import datetime
from importlib import import_module
from pathlib import Path
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_layouts import write_base_host_layout
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_conf_exports():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindServer, module.BindServerXmlSerializer, module.ZoneResourceRecord


class TestXmlSerializer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def _write_base_layout(self, tmpdir: str) -> tuple[str, str, str]:
        return write_base_host_layout(tmpdir)

    def test_xml_serializer_archive_fixture_roundtrip(self) -> None:
        BindServer, BindServerXmlSerializer, _ = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_xml_serializer",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"xml-serializer start fixture={fixture_name}")

                    server = BindServer.fromConfFile(str(fixture.named_conf))
                    serializer = BindServerXmlSerializer()
                    xml_path = fixture.named_etc / "dwlabbind.xml"
                    serializer.write_server_xml(server, str(xml_path))
                    rebuilt = serializer.read_server_xml(str(xml_path))

                    scenario = sample.scenario(7, "xml-serializer")
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    scenario.copy_file(xml_path, "generated/dwlabbind.xml")
                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "zone_count": len(server._zone_files),
                        "xml": str(xml_path),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "xml-serializer.log",
                        f"fixture={fixture_name} zone_count={len(server._zone_files)} xml={xml_path}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(server.name, rebuilt.name)
                    self.assertEqual(len(server._zone_files), len(rebuilt._zone_files))
                    self.assertEqual(
                        sorted(item.zone_name for item in server._zone_files),
                        sorted(item.zone_name for item in rebuilt._zone_files),
                    )

        self.artifacts.write_summary(summary)

    def test_read_server_xml_roundtrip_preserves_zone_files(self) -> None:
        BindServer, BindServerXmlSerializer, _ = _bind_conf_exports()
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

    def test_xml_serializer_roundtrip_preserves_mutated_fixed_hosts(self) -> None:
        BindServer, BindServerXmlSerializer, ZoneResourceRecord = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.append_log("suite.log", f"xml-mutation start fixture={fixture_name}")

                    server = BindServer.fromConfFile(str(fixture.named_conf))
                    target_zone = next(
                        (
                            zone
                            for zone in server._zone_files
                            if not zone._is_reverse_zone() and not zone.externally_managed
                        ),
                        None,
                    )
                    self.assertIsNotNone(target_zone, "Expected at least one mutable forward zone in fixture")
                    assert target_zone is not None

                    mutation_name = "dwlabbind-test-node"
                    mutation_ip = "192.0.2.200"
                    target_zone.fixed_host_statements.append(
                        ZoneResourceRecord.fromText(f"{mutation_name} IN A {mutation_ip}")
                    )
                    target_zone._dedupe_fixed_host_statements()
                    update_result = server.update_zone_serial(target_zone.zone_name, persist=False)

                    serializer = BindServerXmlSerializer()
                    xml_path = fixture.named_etc / "dwlabbind-mutated.xml"
                    serializer.write_server_xml(server, str(xml_path))
                    rebuilt = serializer.read_server_xml(str(xml_path))
                    rebuilt_zone = next(zone for zone in rebuilt._zone_files if zone.zone_name == target_zone.zone_name)

                    scenario = sample.scenario(8, "xml-mutation-roundtrip")
                    scenario.copy_file(xml_path, "generated/dwlabbind-mutated.xml")
                    scenario.write_status(
                        {
                            "fixture": fixture_name,
                            "zone": target_zone.zone_name,
                            "old_serial": update_result["old_serial"],
                            "new_serial": update_result["new_serial"],
                            "mutated_host": mutation_name,
                            "mutated_ip": mutation_ip,
                            "status": "passed",
                        }
                    )

                    rebuilt_values = [
                        getattr(statement, "value", "")
                        for statement in rebuilt_zone.fixed_host_statements
                    ]
                    rebuilt_serial = rebuilt_zone.find_soa_record().serial if rebuilt_zone.find_soa_record() else None

                    self.assertIn(
                        f"{mutation_name} IN A {mutation_ip}",
                        rebuilt_values,
                    )
                    self.assertEqual(rebuilt_serial, update_result["new_serial"])
                    self.assertEqual(
                        rebuilt_zone.fixed_hosts_file_path,
                        target_zone.fixed_hosts_file_path,
                    )

    def test_xml_roundtrip_writeback_generates_fixedhosts_and_include_order(self) -> None:
        BindServer, BindServerXmlSerializer, _ = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.append_log("suite.log", f"xml-writeback start fixture={fixture_name}")

                    server = BindServer.fromConfFile(str(fixture.named_conf))
                    with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                        result = server.add_fixed_host(
                            "dwlabbind-xml-writeback.dw-lab.de",
                            "10.100.0.251",
                            persist=False,
                        )

                    serializer = BindServerXmlSerializer()
                    xml_path = fixture.named_etc / "dwlabbind-writeback.xml"
                    serializer.write_server_xml(server, str(xml_path))
                    rebuilt = serializer.read_server_xml(str(xml_path))

                    forward_zone = next(zone for zone in rebuilt._zone_files if zone.zone_name == result["forward_zone"])
                    reverse_zone = next(zone for zone in rebuilt._zone_files if zone.zone_name == result["reverse_zone"])
                    forward_zone.toFile()
                    reverse_zone.toFile()

                    forward_zone_text = Path(forward_zone.file_path).read_text(encoding="utf-8")
                    reverse_zone_text = Path(reverse_zone.file_path).read_text(encoding="utf-8")
                    forward_fixed_text = Path(forward_zone.fixed_hosts_file_path).read_text(encoding="utf-8")
                    reverse_fixed_text = Path(reverse_zone.fixed_hosts_file_path).read_text(encoding="utf-8")

                    scenario = sample.scenario(9, "xml-writeback-fixedhosts")
                    scenario.copy_file(xml_path, "generated/dwlabbind-writeback.xml")
                    scenario.copy_file(Path(forward_zone.file_path), f"generated/{Path(forward_zone.file_path).name}")
                    scenario.copy_file(Path(reverse_zone.file_path), f"generated/{Path(reverse_zone.file_path).name}")
                    scenario.copy_file(
                        Path(forward_zone.fixed_hosts_file_path),
                        f"generated/{Path(forward_zone.fixed_hosts_file_path).name}",
                    )
                    scenario.copy_file(
                        Path(reverse_zone.fixed_hosts_file_path),
                        f"generated/{Path(reverse_zone.fixed_hosts_file_path).name}",
                    )
                    scenario.write_status(
                        {
                            "fixture": fixture_name,
                            "forward_zone": result["forward_zone"],
                            "reverse_zone": result["reverse_zone"],
                            "fqdn": "dwlabbind-xml-writeback.dw-lab.de",
                            "ip": "10.100.0.251",
                            "status": "passed",
                        }
                    )

                    forward_lines = [line.strip() for line in forward_zone_text.splitlines() if line.strip()]
                    reverse_lines = [line.strip() for line in reverse_zone_text.splitlines() if line.strip()]
                    forward_include_index = next(i for i, line in enumerate(forward_lines) if "$INCLUDE" in line)
                    reverse_include_index = next(i for i, line in enumerate(reverse_lines) if "$INCLUDE" in line)
                    forward_soa_index = next(i for i, line in enumerate(forward_lines) if " SOA " in f" {line} ")
                    reverse_soa_index = next(i for i, line in enumerate(reverse_lines) if " SOA " in f" {line} ")
                    forward_first_a_index = next(i for i, line in enumerate(forward_lines) if " A " in f" {line} ")
                    reverse_first_ptr_index = next(i for i, line in enumerate(reverse_lines) if " PTR " in f" {line} ")

                    self.assertGreater(forward_include_index, forward_soa_index)
                    self.assertLess(forward_include_index, forward_first_a_index)
                    self.assertGreater(reverse_include_index, reverse_soa_index)
                    self.assertLess(reverse_include_index, reverse_first_ptr_index)
                    self.assertEqual(forward_zone_text.count(".FixedHosts"), 1)
                    self.assertEqual(reverse_zone_text.count(".FixedHosts"), 1)
                    self.assertIn('dw-lab.de.', forward_lines[forward_include_index])
                    self.assertIn('0.100.10.in-addr.arpa.', reverse_lines[reverse_include_index])
                    self.assertIn("dwlabbind-xml-writeback IN A 10.100.0.251", forward_fixed_text)
                    self.assertIn("251 IN PTR dwlabbind-xml-writeback.dw-lab.de.", reverse_fixed_text)


if __name__ == "__main__":
    unittest.main()
