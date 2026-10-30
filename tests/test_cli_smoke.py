import io
import os
import sys
import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _runner_module():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        return import_module("dwlabbind.runner")


def _cli_module():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        return import_module("dwlabbind.cli")


def _bind_server_class():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindServer


class TestCliSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_runner_archive_fixture_command_flow(self) -> None:
        runner = _runner_module()
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_cli_smoke_runner",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"runner smoke start fixture={fixture_name}")

                    scenario = sample.scenario(16, "runner-smoke")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)

                    with (
                        mock.patch.object(sys, "argv", [
                            "runner.py",
                            "import",
                            "--named-conf",
                            str(fixture.named_conf),
                        ]),
                        mock.patch("sys.stdout", new_callable=io.StringIO) as import_stdout,
                    ):
                        runner.main()
                    imported_xml = import_stdout.getvalue().strip()

                    with (
                        mock.patch.object(sys, "argv", [
                            "runner.py",
                            "list-zones",
                            "--named-conf",
                            str(fixture.named_conf),
                        ]),
                        mock.patch("sys.stdout", new_callable=io.StringIO) as list_stdout,
                    ):
                        runner.main()
                    list_output = list_stdout.getvalue()

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(sys, "argv", [
                            "runner.py",
                            "initialize",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--output",
                            str(backup_tar),
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                            "--nocleanup",
                        ]),
                    ):
                        runner.main()

                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    named_conf_link = fixture.named_etc / "named.conf"
                    generated_xml = fixture.named_etc / "dwlabbind.xml"

                    scenario.copy_file(fixture.named_conf, "input/named.conf.after")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")
                    scenario.write_text("stdout/import.txt", imported_xml + "\n")
                    scenario.write_text("stdout/list-zones.txt", list_output)

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "imported_xml": imported_xml,
                        "backup": str(backup_tar),
                        "generated_conf": str(generated_conf),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "runner-smoke.log",
                        f"fixture={fixture_name} imported_xml={imported_xml} backup={backup_tar}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(os.path.exists(imported_xml))
                    self.assertIn(fixture.expected_zones[0], list_output)
                    self.assertTrue(backup_tar.exists())
                    self.assertTrue(generated_xml.exists())
                    self.assertTrue(generated_conf.exists())
                    self.assertTrue(named_conf_link.is_symlink())
                    self.assertEqual(os.readlink(named_conf_link), str(generated_conf))

        self.artifacts.write_summary(summary)

    def test_local_cli_archive_fixture_command_flow(self) -> None:
        cli = _cli_module()
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_cli_smoke_local",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"local cli smoke start fixture={fixture_name}")

                    scenario = sample.scenario(17, "local-cli-smoke")
                    backup_tar = scenario.root / "backup" / "named.dwlab.conf.tar"
                    backup_tar.parent.mkdir(parents=True, exist_ok=True)

                    with (
                        mock.patch.object(sys, "argv", [
                            "cli.py",
                            "import",
                            "--named-conf",
                            str(fixture.named_conf),
                        ]),
                        mock.patch("sys.stdout", new_callable=io.StringIO) as import_stdout,
                    ):
                        cli.main()
                    imported_xml = import_stdout.getvalue().strip()

                    with (
                        mock.patch.object(sys, "argv", [
                            "cli.py",
                            "list-zones",
                            "--named-conf",
                            str(fixture.named_conf),
                        ]),
                        mock.patch("sys.stdout", new_callable=io.StringIO) as list_stdout,
                    ):
                        cli.main()
                    list_output = list_stdout.getvalue()

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(sys, "argv", [
                            "cli.py",
                            "initialize",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--output",
                            str(backup_tar),
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                            "--nocleanup",
                        ]),
                    ):
                        cli.main()

                    generated_conf = fixture.named_etc / "dwlab.named.conf"
                    named_conf_link = fixture.named_etc / "named.conf"
                    generated_xml = fixture.named_etc / "dwlabbind.xml"

                    scenario.copy_file(fixture.named_conf, "input/named.conf.after")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")
                    if backup_tar.exists():
                        scenario.copy_file(backup_tar, "generated/backup/named.dwlab.conf.tar")
                    scenario.write_text("stdout/import.txt", imported_xml + "\n")
                    scenario.write_text("stdout/list-zones.txt", list_output)

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "imported_xml": imported_xml,
                        "backup": str(backup_tar),
                        "generated_conf": str(generated_conf),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "local-cli-smoke.log",
                        f"fixture={fixture_name} imported_xml={imported_xml} backup={backup_tar}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(os.path.exists(imported_xml))
                    self.assertIn(fixture.expected_zones[0], list_output)
                    self.assertTrue(backup_tar.exists())
                    self.assertTrue(generated_xml.exists())
                    self.assertTrue(generated_conf.exists())
                    self.assertTrue(named_conf_link.is_symlink())
                    self.assertEqual(os.readlink(named_conf_link), str(generated_conf))

        self.artifacts.write_summary(summary)

    def test_runner_archive_fixture_add_fixed_host_flow(self) -> None:
        runner = _runner_module()
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_cli_smoke_runner_add_fixed_host",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"runner fixed-host-add smoke start fixture={fixture_name}")

                    scenario = sample.scenario(18, "runner-fixed-host-add-smoke")
                    fqdn = "dwlabbind-cli-runner-01.dw-lab.de"
                    ip_address = "10.100.0.242"

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None),
                        mock.patch.object(sys, "argv", [
                            "runner.py",
                            "fixed-host-add",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--fqdn",
                            fqdn,
                            "--ip",
                            ip_address,
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                        ]),
                    ):
                        runner.main()

                    forward_fixed = fixture.named_var / "dwlab" / "dw-lab.de.zone.FixedHosts"
                    reverse_fixed = fixture.named_var / "dwlab" / "0.100.10.in-addr.arpa.zone.FixedHosts"
                    forward_text = forward_fixed.read_text(encoding="utf-8")
                    reverse_text = reverse_fixed.read_text(encoding="utf-8")

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "fqdn": fqdn,
                        "ip": ip_address,
                        "forward_fixed": str(forward_fixed),
                        "reverse_fixed": str(reverse_fixed),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "runner-fixed-host-add-smoke.log",
                        f"fixture={fixture_name} fqdn={fqdn} ip={ip_address}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(forward_fixed.exists())
                    self.assertTrue(reverse_fixed.exists())
                    self.assertIn("dwlabbind-cli-runner-01 IN A 10.100.0.242", forward_text)
                    self.assertIn("242 IN PTR dwlabbind-cli-runner-01.dw-lab.de.", reverse_text)

        self.artifacts.write_summary(summary)

    def test_local_cli_archive_fixture_add_fixed_host_flow(self) -> None:
        cli = _cli_module()
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_cli_smoke_local_add_fixed_host",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"local cli fixed-host-add smoke start fixture={fixture_name}")

                    scenario = sample.scenario(19, "local-cli-fixed-host-add-smoke")
                    fqdn = "dwlabbind-cli-local-01.dw-lab.de"
                    ip_address = "10.100.0.243"

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None),
                        mock.patch.object(sys, "argv", [
                            "cli.py",
                            "fixed-host-add",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--fqdn",
                            fqdn,
                            "--ip",
                            ip_address,
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                        ]),
                    ):
                        cli.main()

                    forward_fixed = fixture.named_var / "dwlab" / "dw-lab.de.zone.FixedHosts"
                    reverse_fixed = fixture.named_var / "dwlab" / "0.100.10.in-addr.arpa.zone.FixedHosts"
                    forward_text = forward_fixed.read_text(encoding="utf-8")
                    reverse_text = reverse_fixed.read_text(encoding="utf-8")

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "fqdn": fqdn,
                        "ip": ip_address,
                        "forward_fixed": str(forward_fixed),
                        "reverse_fixed": str(reverse_fixed),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "local-cli-fixed-host-add-smoke.log",
                        f"fixture={fixture_name} fqdn={fqdn} ip={ip_address}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertTrue(forward_fixed.exists())
                    self.assertTrue(reverse_fixed.exists())
                    self.assertIn("dwlabbind-cli-local-01 IN A 10.100.0.243", forward_text)
                    self.assertIn("243 IN PTR dwlabbind-cli-local-01.dw-lab.de.", reverse_text)

        self.artifacts.write_summary(summary)

    def test_runner_archive_fixture_delete_fixed_host_flow(self) -> None:
        runner = _runner_module()
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_cli_smoke_runner_delete_fixed_host",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"runner fixed-host-delete smoke start fixture={fixture_name}")

                    scenario = sample.scenario(20, "runner-fixed-host-delete-smoke")
                    fqdn = "dwlabbind-cli-runner-del-01.dw-lab.de"
                    ip_address = "10.100.0.244"

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None),
                    ):
                        with mock.patch.object(sys, "argv", [
                            "runner.py",
                            "fixed-host-add",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--fqdn",
                            fqdn,
                            "--ip",
                            ip_address,
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                        ]):
                            runner.main()
                        with mock.patch.object(sys, "argv", [
                            "runner.py",
                            "fixed-host-delete",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--fqdn",
                            fqdn,
                            "--ip",
                            ip_address,
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                        ]):
                            runner.main()

                    forward_fixed = fixture.named_var / "dwlab" / "dw-lab.de.zone.FixedHosts"
                    reverse_fixed = fixture.named_var / "dwlab" / "0.100.10.in-addr.arpa.zone.FixedHosts"
                    forward_text = forward_fixed.read_text(encoding="utf-8") if forward_fixed.exists() else ""
                    reverse_text = reverse_fixed.read_text(encoding="utf-8") if reverse_fixed.exists() else ""

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "fqdn": fqdn,
                        "ip": ip_address,
                        "forward_fixed": str(forward_fixed),
                        "reverse_fixed": str(reverse_fixed),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "runner-fixed-host-delete-smoke.log",
                        f"fixture={fixture_name} fqdn={fqdn} ip={ip_address}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertNotIn("dwlabbind-cli-runner-del-01 IN A 10.100.0.244", forward_text)
                    self.assertNotIn("244 IN PTR dwlabbind-cli-runner-del-01.dw-lab.de.", reverse_text)

        self.artifacts.write_summary(summary)

    def test_local_cli_archive_fixture_delete_fixed_host_flow(self) -> None:
        cli = _cli_module()
        BindServer = _bind_server_class()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_cli_smoke_local_delete_fixed_host",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"local cli fixed-host-delete smoke start fixture={fixture_name}")

                    scenario = sample.scenario(21, "local-cli-fixed-host-delete-smoke")
                    fqdn = "dwlabbind-cli-local-del-01.dw-lab.de"
                    ip_address = "10.100.0.245"

                    with (
                        mock.patch.object(BindServer, "_validate_layout", return_value=None),
                        mock.patch.object(BindServer, "_validate_zone_file_record", return_value=None),
                    ):
                        with mock.patch.object(sys, "argv", [
                            "cli.py",
                            "fixed-host-add",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--fqdn",
                            fqdn,
                            "--ip",
                            ip_address,
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                        ]):
                            cli.main()
                        with mock.patch.object(sys, "argv", [
                            "cli.py",
                            "fixed-host-delete",
                            "--named-conf",
                            str(fixture.named_conf),
                            "--fqdn",
                            fqdn,
                            "--ip",
                            ip_address,
                            "--named-etc",
                            str(fixture.named_etc),
                            "--named-var",
                            str(fixture.named_var),
                        ]):
                            cli.main()

                    forward_fixed = fixture.named_var / "dwlab" / "dw-lab.de.zone.FixedHosts"
                    reverse_fixed = fixture.named_var / "dwlab" / "0.100.10.in-addr.arpa.zone.FixedHosts"
                    forward_text = forward_fixed.read_text(encoding="utf-8") if forward_fixed.exists() else ""
                    reverse_text = reverse_fixed.read_text(encoding="utf-8") if reverse_fixed.exists() else ""

                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "fqdn": fqdn,
                        "ip": ip_address,
                        "forward_fixed": str(forward_fixed),
                        "reverse_fixed": str(reverse_fixed),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "local-cli-fixed-host-delete-smoke.log",
                        f"fixture={fixture_name} fqdn={fqdn} ip={ip_address}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertNotIn("dwlabbind-cli-local-del-01 IN A 10.100.0.245", forward_text)
                    self.assertNotIn("245 IN PTR dwlabbind-cli-local-del-01.dw-lab.de.", reverse_text)

        self.artifacts.write_summary(summary)


if __name__ == "__main__":
    unittest.main()
