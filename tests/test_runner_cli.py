import io
import sys
import tempfile
import unittest
from importlib import import_module
from unittest import mock


def _runner_module():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        return import_module("dwlabbind.runner")


class TestRunnerCli(unittest.TestCase):
    def test_backup_prints_archive_path(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "backup",
                "--named-conf", "/etc/bind/named.conf",
                "--output", "/tmp/named.backup.tar",
            ]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            manager = manager_cls.return_value
            manager.backup_named_conf.return_value = "/tmp/named.backup.tar"

            runner.main()

            manager.backup_named_conf.assert_called_once_with("/etc/bind/named.conf", "/tmp/named.backup.tar")
            self.assertEqual(stdout.getvalue(), "/tmp/named.backup.tar\n")

    def test_import_prints_xml_path(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "import",
                "--named-conf", "/etc/bind/named.conf",
            ]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            manager = manager_cls.return_value
            manager.import_named_conf.return_value = "/etc/bind/dwlabbind.xml"

            runner.main()

            manager.import_named_conf.assert_called_once_with("/etc/bind/named.conf")
            self.assertEqual(stdout.getvalue(), "/etc/bind/dwlabbind.xml\n")

    def test_list_zones_prints_zone_lines(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "list-zones",
                "--named-conf", "/etc/bind/named.conf",
            ]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as stdout,
        ):
            manager = manager_cls.return_value
            manager.list_zones_from_conf.return_value = [
                {
                    "zone_name": "example.com",
                    "reverse": False,
                    "zone_type": "master",
                    "ddns_enabled": True,
                    "management_state": "managed",
                    "file_path": "/var/lib/bind/example.com.zone",
                }
            ]

            runner.main()

            self.assertIn(
                "example.com | forward | master | ddns | managed | /var/lib/bind/example.com.zone",
                stdout.getvalue(),
            )

    def test_initialize_dispatches_expected_flags(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(runner.logger, "info") as log_info,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "initialize",
                "--named-conf",
                "/etc/bind/named.conf",
                "--xml-input",
                "/etc/bind/dwlabbind.xml",
                "--output",
                "/tmp/backup.tar",
                "--named-etc",
                "/etc/bind",
                "--named-var",
                "/var/lib/bind",
                "--force",
                "--nocleanup",
                "--keep-stage-on-error",
            ]),
        ):
            manager = manager_cls.return_value
            manager.initialize_named_conf.return_value = {
                "archive": "/tmp/backup.tar",
                "xml": "/etc/bind/dwlabbind.xml",
                "conf": "/etc/bind/dwlab.named.conf",
            }

            runner.main()

            manager.initialize_named_conf.assert_called_once_with(
                named_conf="/etc/bind/named.conf",
                xml_input="/etc/bind/dwlabbind.xml",
                backup_output="/tmp/backup.tar",
                named_etc="/etc/bind",
                named_var="/var/lib/bind",
                force=True,
                cleanup=False,
                keep_stage_on_error=True,
            )
            log_info.assert_called()

    def test_update_zone_dispatches_expected_arguments(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "update-zone",
                "--named-conf",
                "/etc/bind/named.conf",
                "--zone-name",
                "example.com",
                "--named-etc",
                "/etc/bind",
                "--named-var",
                "/var/lib/bind",
            ]),
        ):
            manager = manager_cls.return_value
            manager.update_zone_serial_and_write.return_value = {
                "zone": "example.com",
                "old_serial": "2026010101",
                "new_serial": "2026010102",
                "xml": "/etc/bind/dwlabbind.xml",
                "conf": "/etc/bind/dwlab.named.conf",
            }

            runner.main()

            manager.update_zone_serial_and_write.assert_called_once_with(
                named_conf="/etc/bind/named.conf",
                zone_name="example.com",
                named_etc="/etc/bind",
                named_var="/var/lib/bind",
            )

    def test_restore_logs_success_context(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(runner.logger, "info") as log_info,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "restore",
                "--named-conf", "/etc/bind/named.conf",
                "--archive", "/tmp/named.dwlab.conf.tar",
                "--named-etc", "/etc/bind",
                "--named-var", "/var/lib/bind",
                "--force",
            ]),
        ):
            manager = manager_cls.return_value
            manager.restore_named_conf.return_value = {
                "named_conf": "/etc/bind/named.conf",
                "archive": "/tmp/named.dwlab.conf.tar",
                "xml": "/etc/bind/dwlabbind.xml",
            }

            runner.main()

            manager.restore_named_conf.assert_called_once_with(
                named_conf="/etc/bind/named.conf",
                archive_path="/tmp/named.dwlab.conf.tar",
                force=True,
                named_etc="/etc/bind",
                named_var="/var/lib/bind",
            )
            log_info.assert_called_with(
                "restore completed (named_conf=%s, archive=%s, xml=%s)",
                "/etc/bind/named.conf",
                "/tmp/named.dwlab.conf.tar",
                "/etc/bind/dwlabbind.xml",
            )

    def test_create_tsig_logs_success_context(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(runner.logger, "info") as log_info,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "create-tsig",
                "--named-conf", "/etc/bind/named.conf",
                "--key-name", "example.com",
                "--algorithm", "hmac-sha256",
                "--named-etc", "/etc/bind",
                "--named-var", "/var/lib/bind",
                "--force",
            ]),
        ):
            manager = manager_cls.return_value
            manager.create_tsig_key_and_write.return_value = {
                "action": "created",
                "key_name": "example.com",
                "algorithm": "hmac-sha256",
                "conf": "/etc/bind/dwlab.named.conf",
                "xml": "/etc/bind/dwlabbind.xml",
            }

            runner.main()

            manager.create_tsig_key_and_write.assert_called_once_with(
                named_conf="/etc/bind/named.conf",
                key_name="example.com",
                algorithm="hmac-sha256",
                force=True,
                named_etc="/etc/bind",
                named_var="/var/lib/bind",
            )
            log_info.assert_called_with(
                "tsig key %s and configuration written (key_name=%s, algorithm=%s, conf=%s, xml=%s)",
                "created",
                "example.com",
                "hmac-sha256",
                "/etc/bind/dwlab.named.conf",
                "/etc/bind/dwlabbind.xml",
            )

    def test_delete_fixed_host_logs_success_context(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(runner.logger, "info") as log_info,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "delete-fixed-host",
                "--named-conf", "/etc/bind/named.conf",
                "--fqdn", "host.example.com",
                "--ip", "192.0.2.10",
                "--named-etc", "/etc/bind",
                "--named-var", "/var/lib/bind",
                "--force",
            ]),
        ):
            manager = manager_cls.return_value
            manager.delete_fixed_host_and_write.return_value = {
                "fqdn": "host.example.com.",
                "ip": "192.0.2.10",
                "forward_zone": "example.com",
                "removed_forward_records": 1,
                "removed_reverse_records": 1,
                "xml": "/etc/bind/dwlabbind.xml",
                "conf": "/etc/bind/dwlab.named.conf",
            }

            runner.main()

            manager.delete_fixed_host_and_write.assert_called_once_with(
                named_conf="/etc/bind/named.conf",
                fqdn="host.example.com",
                ip_address="192.0.2.10",
                force=True,
                named_etc="/etc/bind",
                named_var="/var/lib/bind",
            )
            log_info.assert_called_with(
                "fixed host deleted and configuration written (named_conf=%s, fqdn=%s, ip=%s, forward_zone=%s, removed_forward=%s, removed_reverse=%s, xml=%s, conf=%s)",
                "/etc/bind/named.conf",
                "host.example.com.",
                "192.0.2.10",
                "example.com",
                1,
                1,
                "/etc/bind/dwlabbind.xml",
                "/etc/bind/dwlab.named.conf",
            )

    def test_bind_operation_error_exits_with_warning_and_code_2(self) -> None:
        runner = _runner_module()
        error = runner.BindOperationError(
            "HOST_EXISTS",
            "Host mapping already exists.",
            "Use --force to overwrite existing host/IP entries.",
        )
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(runner.logger, "warning") as log_warning,
            mock.patch.object(runner.logger, "error") as log_error,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "add-fixed-host",
                "--fqdn",
                "host.example.com",
                "--ip",
                "192.0.2.10",
            ]),
        ):
            manager = manager_cls.return_value
            manager.add_fixed_host_and_write.side_effect = error

            with self.assertRaises(SystemExit) as exc:
                runner.main()

            self.assertEqual(exc.exception.code, 2)
            log_warning.assert_any_call("Host/IP mapping already exists. Re-run with '--force' to overwrite.")
            log_warning.assert_any_call("Hint: %s", "Use --force to overwrite existing host/IP entries.")
            log_error.assert_called_with("[%s] %s", "HOST_EXISTS", "Host mapping already exists.")

    def test_runtime_lock_error_exits_with_code_2(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
            mock.patch.object(runner.logger, "warning") as log_warning,
            mock.patch.object(runner.logger, "error") as log_error,
            mock.patch.object(sys, "argv", ["runner.py", "initialize"]),
        ):
            manager = manager_cls.return_value
            manager.initialize_named_conf.side_effect = RuntimeError("named.conf.working-on already exists")

            with self.assertRaises(SystemExit) as exc:
                runner.main()

            self.assertEqual(exc.exception.code, 2)
            log_warning.assert_called_with(
                "Initialization aborted due to active lock file. If this is stale, rerun with '--force'."
            )
            log_error.assert_called_with("Command '%s' failed: %s", "initialize", "named.conf.working-on already exists")

    def test_create_tsig_requires_key_name(self) -> None:
        runner = _runner_module()
        with mock.patch.object(sys, "argv", ["runner.py", "create-tsig"]):
            with self.assertRaises(SystemExit) as exc:
                runner.main()
        self.assertEqual(exc.exception.code, 2)

    def test_zone_create_reads_inputs_from_yaml(self) -> None:
        runner = _runner_module()
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("base_hostname: ns1\n")
            handle.write("domain_name: example.com\n")
            handle.write("dns_server: 192.0.2.10/24\n")
            settings_path = handle.name
        try:
            with (
                mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
                mock.patch.object(sys, "argv", ["runner.py", "zone-create", "--yaml", settings_path]),
            ):
                manager = manager_cls.return_value
                manager.create_zone_and_write.return_value = {
                    "domain": "example.com",
                    "reverse_zone": "2.0.192.in-addr.arpa",
                    "conf": "/etc/bind/dwlab.named.conf",
                    "xml": "/etc/bind/dwlabbind.xml",
                }

                runner.main()

                manager.create_zone_and_write.assert_called_once_with(
                    named_conf="/etc/bind/named.conf",
                    domain_name="example.com",
                    dns_server_cidr="192.0.2.10/24",
                    base_hostname="ns1",
                    force=False,
                    named_etc=None,
                    named_var=None,
                    enable_allow_recursion=True,
                    enable_allow_update=True,
                )
        finally:
            import os
            os.unlink(settings_path)

    def test_zone_create_reads_inputs_from_xml(self) -> None:
        runner = _runner_module()
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
            handle.write("<root><base_hostname>ns1</base_hostname><domain_name>example.com</domain_name><dns_server>192.0.2.10/24</dns_server></root>")
            settings_path = handle.name
        try:
            with (
                mock.patch.object(runner, "BindConfigurationManager") as manager_cls,
                mock.patch.object(sys, "argv", ["runner.py", "zone-create", "--xml", settings_path]),
            ):
                manager = manager_cls.return_value
                manager.create_zone_and_write.return_value = {
                    "domain": "example.com",
                    "reverse_zone": "2.0.192.in-addr.arpa",
                    "conf": "/etc/bind/dwlab.named.conf",
                    "xml": "/etc/bind/dwlabbind.xml",
                }

                runner.main()

                manager.create_zone_and_write.assert_called_once_with(
                    named_conf="/etc/bind/named.conf",
                    domain_name="example.com",
                    dns_server_cidr="192.0.2.10/24",
                    base_hostname="ns1",
                    force=False,
                    named_etc=None,
                    named_var=None,
                    enable_allow_recursion=True,
                    enable_allow_update=True,
                )
        finally:
            import os
            os.unlink(settings_path)

    def test_dns_update_dispatches_expected_arguments(self) -> None:
        runner = _runner_module()
        with (
            mock.patch.object(runner, "handle_dynamic_dns_update") as update_handler,
            mock.patch.object(runner.logger, "info") as log_info,
            mock.patch.object(sys, "argv", [
                "runner.py",
                "dns-update",
                "add",
                "--settings", "/etc/dwlabbind/dynamic-dns.yaml",
                "--fqdn", "branch-office-01.ovpnprivate.example.internal",
                "--ip", "10.8.4.42",
            ]),
        ):
            update_handler.return_value = {
                "action": "add",
                "fqdn": "branch-office-01.ovpnprivate.example.internal",
                "ip_address": "10.8.4.42",
                "dns_zone": "ovpnprivate.example.internal",
            }

            runner.main()

            update_handler.assert_called_once_with(
                "add",
                settings_path="/etc/dwlabbind/dynamic-dns.yaml",
                fqdn="branch-office-01.ovpnprivate.example.internal",
                ip_address="10.8.4.42",
            )
            log_info.assert_called()


if __name__ == "__main__":
    unittest.main()
