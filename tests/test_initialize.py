import contextlib
import os
import shutil
import tempfile
import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_conf_exports():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindServer, module.initialize_named_conf


def _bind_conf_module():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        return import_module("dwlabbind.bind_conf")


class TestInitializeLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_initialize_archive_fixture_named_conf(self) -> None:
        BindServer, initialize_named_conf = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        env_validate = os.environ.get("DWLABBIND_TEST_VALIDATE")
        if env_validate is None:
            validate_enabled = False
        else:
            validate_enabled = env_validate.strip().lower() in {"1", "true", "yes", "on"}

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_initialize",
            "validation": "real" if validate_enabled else "mocked",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log(
                        "suite.log",
                        f"initialize start fixture={fixture_name} validation={'real' if validate_enabled else 'mocked'}",
                    )

                    scenario = sample.scenario(3, "initialize")
                    scenario.copy_file(fixture.named_conf, "input/named.conf.before")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)

                    validation_ctx = (
                        contextlib.nullcontext()
                        if validate_enabled
                        else mock.patch.object(BindServer, "_validate_layout", return_value=None)
                    )
                    with validation_ctx:
                        result = initialize_named_conf(
                            named_conf=str(fixture.named_conf),
                            backup_output=str(backup_tar),
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                            cleanup=False,
                        )

                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    generated_xml = fixture.named_etc / "dwlabbind.xml"
                    managed_conf_dir = fixture.named_etc / "dwlab"
                    managed_zone_dir = fixture.named_var / "dwlab"
                    named_conf_link = fixture.named_etc / "named.conf"
                    working_on = fixture.named_etc / "named.conf.working-on"

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "validation": "real" if validate_enabled else "mocked",
                        "named_conf": str(fixture.named_conf),
                        "named_etc": str(fixture.named_etc),
                        "named_var": str(fixture.named_var),
                        "result": result,
                        "artifacts": {
                            "generated_conf": str(generated_conf),
                            "generated_xml": str(generated_xml),
                            "managed_conf_dir": str(managed_conf_dir),
                            "managed_zone_dir": str(managed_zone_dir),
                        },
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "initialize.log",
                        f"fixture={fixture_name} xml={generated_xml} conf={generated_conf}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(backup_tar.exists())
                    self.assertEqual(result["archive"], str(backup_tar))
                    self.assertTrue(generated_xml.exists())
                    self.assertEqual(result["xml"], str(generated_xml))
                    self.assertTrue(generated_conf.exists())
                    self.assertEqual(result["conf"], str(generated_conf))
                    self.assertTrue(named_conf_link.is_symlink())
                    self.assertEqual(os.readlink(named_conf_link), str(generated_conf))
                    self.assertFalse(working_on.exists())
                    self.assertTrue((managed_conf_dir / "dwlabdns.options.conf").exists())
                    self.assertTrue(managed_zone_dir.exists())

        self.artifacts.write_summary(summary)

    def test_initialize_archive_fixture_rolls_back_on_write_failure(self) -> None:
        BindServer, initialize_named_conf = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_initialize_rollback",
            "fixtures": [],
        }

        def _failing_to_conf_file(self, named_etc="/etc/bind", named_var="/var/lib/bind", **kwargs):
            del kwargs
            named_conf = os.path.join(named_etc, "named.conf")
            working_on = os.path.join(named_etc, "named.conf.working-on")
            generated_conf = os.path.join(named_etc, "dwlab.named.conf")
            os.makedirs(os.path.join(named_etc, "dwlab"), exist_ok=True)
            os.makedirs(os.path.join(named_var, "dwlab"), exist_ok=True)
            if os.path.exists(named_conf):
                os.rename(named_conf, working_on)
            with open(generated_conf, "w", encoding="utf-8") as handle:
                handle.write("// synthetic managed config before failure\n")
            os.symlink(generated_conf, named_conf)
            with open(os.path.join(named_etc, "dwlab", "dwlabdns.options.conf"), "w", encoding="utf-8") as handle:
                handle.write("// synthetic options before failure\n")
            with open(os.path.join(named_var, "dwlab", "synthetic.zone"), "w", encoding="utf-8") as handle:
                handle.write("; synthetic zone before failure\n")
            raise RuntimeError("synthetic initialize failure")

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"initialize rollback start fixture={fixture_name}")

                    scenario = sample.scenario(12, "initialize-rollback")
                    scenario.copy_file(fixture.named_conf, "input/named.conf.before")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)
                    original_named_conf = fixture.named_conf.read_text(encoding="utf-8")
                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    generated_xml = fixture.named_etc / "dwlabbind.xml"
                    working_on = fixture.named_etc / "named.conf.working-on"
                    named_conf_link = fixture.named_etc / "named.conf"

                    with mock.patch.object(BindServer, "toConfFile", new=_failing_to_conf_file):
                        with self.assertRaises(RuntimeError) as exc:
                            initialize_named_conf(
                                named_conf=str(fixture.named_conf),
                                backup_output=str(backup_tar),
                                named_etc=str(fixture.named_etc),
                                named_var=str(fixture.named_var),
                                cleanup=False,
                            )

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")

                    restored_named_conf = fixture.named_conf.read_text(encoding="utf-8")
                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "exception": str(exc.exception),
                        "named_conf": str(fixture.named_conf),
                        "backup_archive": str(backup_tar),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "initialize-rollback.log",
                        f"fixture={fixture_name} exception={exc.exception} restored_named_conf={fixture.named_conf}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(str(exc.exception), "synthetic initialize failure")
                    self.assertTrue(backup_tar.exists())
                    self.assertEqual(restored_named_conf, original_named_conf)
                    self.assertTrue(named_conf_link.exists())
                    self.assertFalse(named_conf_link.is_symlink())
                    self.assertFalse(working_on.exists())
                    self.assertFalse(generated_conf.exists())
                    self.assertFalse(generated_xml.exists())

        self.artifacts.write_summary(summary)

    def test_initialize_archive_fixture_rolls_back_on_cleanup_failure(self) -> None:
        BindServer, initialize_named_conf = _bind_conf_exports()
        bind_conf_module = _bind_conf_module()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_initialize_cleanup_rollback",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"initialize cleanup rollback start fixture={fixture_name}")

                    scenario = sample.scenario(13, "initialize-cleanup-rollback")
                    scenario.copy_file(fixture.named_conf, "input/named.conf.before")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)
                    original_named_conf = fixture.named_conf.read_text(encoding="utf-8")
                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    generated_xml = fixture.named_etc / "dwlabbind.xml"
                    working_on = fixture.named_etc / "named.conf.working-on"
                    named_conf_path = fixture.named_etc / "named.conf"

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(
                            bind_conf_module.BindConfigurationManager,
                            "_remove_unreferenced_backed_up_files",
                            side_effect=RuntimeError("synthetic cleanup failure"),
                        ),
                    ):
                        with self.assertRaises(RuntimeError) as exc:
                            initialize_named_conf(
                                named_conf=str(fixture.named_conf),
                                backup_output=str(backup_tar),
                                named_etc=str(fixture.named_etc),
                                named_var=str(fixture.named_var),
                                cleanup=True,
                            )

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")

                    restored_named_conf = fixture.named_conf.read_text(encoding="utf-8")
                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "exception": str(exc.exception),
                        "named_conf": str(fixture.named_conf),
                        "backup_archive": str(backup_tar),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "initialize-cleanup-rollback.log",
                        f"fixture={fixture_name} exception={exc.exception} restored_named_conf={fixture.named_conf}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(str(exc.exception), "synthetic cleanup failure")
                    self.assertTrue(backup_tar.exists())
                    self.assertEqual(restored_named_conf, original_named_conf)
                    self.assertTrue(named_conf_path.exists())
                    self.assertFalse(named_conf_path.is_symlink())
                    self.assertFalse(working_on.exists())
                    self.assertFalse(generated_conf.exists())
                    self.assertFalse(generated_xml.exists())

        self.artifacts.write_summary(summary)

    def test_initialize_archive_fixture_uses_xml_input_source(self) -> None:
        BindServer, initialize_named_conf = _bind_conf_exports()
        bind_conf_module = _bind_conf_module()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_initialize_xml_input",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"initialize xml-input start fixture={fixture_name}")

                    scenario = sample.scenario(14, "initialize-xml-input")
                    scenario.copy_file(fixture.named_conf, "input/named.conf.before")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)
                    xml_input = scenario.root / "input" / "dwlabbind.source.xml"
                    xml_input.parent.mkdir(parents=True, exist_ok=True)

                    manager = bind_conf_module.BindConfigurationManager()
                    manager.import_named_conf(str(fixture.named_conf))
                    generated_xml = fixture.named_etc / "dwlabbind.xml"
                    shutil.copy2(generated_xml, xml_input)

                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        result = initialize_named_conf(
                            named_conf=str(fixture.named_conf),
                            xml_input=str(xml_input),
                            backup_output=str(backup_tar),
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                            cleanup=False,
                        )

                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    managed_conf_dir = fixture.named_etc / "dwlab"
                    managed_zone_dir = fixture.named_var / "dwlab"
                    named_conf_link = fixture.named_etc / "named.conf"
                    working_on = fixture.named_etc / "named.conf.working-on"

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "xml_input": str(xml_input),
                        "result": result,
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "initialize-xml-input.log",
                        f"fixture={fixture_name} xml_input={xml_input} conf={generated_conf}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(backup_tar.exists())
                    self.assertEqual(result["archive"], str(backup_tar))
                    self.assertTrue(generated_xml.exists())
                    self.assertEqual(result["xml"], str(generated_xml))
                    self.assertTrue(generated_conf.exists())
                    self.assertEqual(result["conf"], str(generated_conf))
                    self.assertTrue(named_conf_link.is_symlink())
                    self.assertEqual(os.readlink(named_conf_link), str(generated_conf))
                    self.assertFalse(working_on.exists())
                    self.assertTrue((managed_conf_dir / "dwlabdns.options.conf").exists())
                    self.assertTrue(managed_zone_dir.exists())

        self.artifacts.write_summary(summary)

    def test_initialize_archive_fixture_xml_input_mutation_drives_generated_layout(self) -> None:
        BindServer, initialize_named_conf = _bind_conf_exports()
        bind_conf_module = _bind_conf_module()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_initialize_xml_input_mutation",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"initialize xml-mutation start fixture={fixture_name}")

                    scenario = sample.scenario(15, "initialize-xml-input-mutation")
                    scenario.copy_file(fixture.named_conf, "input/named.conf.before")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)
                    xml_input = scenario.root / "input" / "dwlabbind.mutated.xml"
                    xml_input.parent.mkdir(parents=True, exist_ok=True)

                    manager = bind_conf_module.BindConfigurationManager()
                    manager.import_named_conf(str(fixture.named_conf))
                    generated_xml = fixture.named_etc / "dwlabbind.xml"

                    serializer = bind_conf_module.BindServerXmlSerializer()
                    server = serializer.read_server_xml(str(generated_xml))
                    with mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None):
                        server.add_fixed_host(
                            fqdn="dwlabbind-xml-init-01.dw-lab.de",
                            ip_address="10.100.0.241",
                            persist=False,
                            force=True,
                        )
                    serializer.write_server_xml(server, str(xml_input))

                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        result = initialize_named_conf(
                            named_conf=str(fixture.named_conf),
                            xml_input=str(xml_input),
                            backup_output=str(backup_tar),
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                            cleanup=False,
                        )

                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    forward_fixed_hosts = fixture.named_var / "dwlab" / "dw-lab.de.zone.FixedHosts"
                    reverse_fixed_hosts = fixture.named_var / "dwlab" / "0.100.10.in-addr.arpa.zone.FixedHosts"
                    forward_fixed_text = forward_fixed_hosts.read_text(encoding="utf-8")
                    reverse_fixed_text = reverse_fixed_hosts.read_text(encoding="utf-8")

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "xml_input": str(xml_input),
                        "result": result,
                        "forward_fixed_hosts": str(forward_fixed_hosts),
                        "reverse_fixed_hosts": str(reverse_fixed_hosts),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "initialize-xml-input-mutation.log",
                        f"fixture={fixture_name} xml_input={xml_input} forward_fixed={forward_fixed_hosts}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(backup_tar.exists())
                    self.assertTrue(generated_conf.exists())
                    self.assertTrue(forward_fixed_hosts.exists())
                    self.assertTrue(reverse_fixed_hosts.exists())
                    self.assertEqual(result["archive"], str(backup_tar))
                    self.assertEqual(result["conf"], str(generated_conf))
                    self.assertIn("dwlabbind-xml-init-01 IN A 10.100.0.241", forward_fixed_text)
                    self.assertIn("241 IN PTR dwlabbind-xml-init-01.dw-lab.de.", reverse_fixed_text)

        self.artifacts.write_summary(summary)

    def test_initialize_cleanup_removes_unreferenced_legacy_files(self) -> None:
        BindServer, initialize_named_conf = _bind_conf_exports()
        with tempfile.TemporaryDirectory() as run_dir:
            etc_bind = os.path.join(run_dir, "etc", "bind")
            var_bind = os.path.join(run_dir, "var", "lib", "bind")
            os.makedirs(etc_bind, exist_ok=True)
            os.makedirs(var_bind, exist_ok=True)

            named_conf = os.path.join(etc_bind, "named.conf")
            old_conf = os.path.join(etc_bind, "old.conf")
            backup_tar = os.path.join(run_dir, "backup.tar")
            with open(old_conf, "w", encoding="utf-8") as handle:
                handle.write('acl oldclients { 127.0.0.1; };\n')
            with open(named_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    f'include "{old_conf}";\n'
                    'options { recursion yes; };\n'
                    'controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; }; };\n'
                )

            with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                initialize_named_conf(
                    named_conf=named_conf,
                    backup_output=backup_tar,
                    named_etc=etc_bind,
                    named_var=var_bind,
                    cleanup=True,
                )

            self.assertFalse(os.path.exists(old_conf))
            self.assertTrue(os.path.islink(named_conf))


if __name__ == "__main__":
    unittest.main()
