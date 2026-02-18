import os
import re
import shutil
import contextlib
import unittest
from unittest import mock

from dwlabbind.bind_conf import BindServer, initialize_named_conf


def _next_testrun_dir(base_dir: str = "/tmp/dwlabbind") -> str:
    os.makedirs(base_dir, exist_ok=True)
    max_n = 0
    pattern = re.compile(r"^testrun(\d+)$")
    for entry in os.listdir(base_dir):
        match = pattern.match(entry)
        if not match:
            continue
        max_n = max(max_n, int(match.group(1)))
    run_dir = os.path.join(base_dir, f"testrun{max_n + 1}")
    os.makedirs(run_dir, exist_ok=False)
    return run_dir


class TestInitializeLayout(unittest.TestCase):
    def test_initialize_writes_to_requested_layout(self) -> None:
        run_dir = _next_testrun_dir()
        env_named_conf = os.environ.get("DWLABBIND_TEST_NAMED_CONF")
        env_named_etc = os.environ.get("DWLABBIND_TEST_NAMED_ETC")
        env_named_var = os.environ.get("DWLABBIND_TEST_NAMED_VAR")
        env_validate = os.environ.get("DWLABBIND_TEST_VALIDATE")

        etc_bind = env_named_etc or os.path.join(run_dir, "etc", "bind")
        var_bind = env_named_var or os.path.join(run_dir, "var", "lib", "bind")
        os.makedirs(etc_bind, exist_ok=True)
        os.makedirs(var_bind, exist_ok=True)

        named_conf = os.path.join(etc_bind, "named.conf")
        backup_tar = os.path.join(run_dir, "backup.tar")
        if not env_named_conf:
            with open(named_conf, "w", encoding="utf-8") as handle:
                handle.write(
                    'options { recursion yes; };'
                    "\n"
                    'controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; }; };'
                    "\n"
                )
        else:
            self.assertTrue(os.path.exists(env_named_conf), f"Configured named.conf not found: {env_named_conf}")
            # Keep initialize flow self-contained in test run directory.
            shutil.copy2(env_named_conf, named_conf)

        # Validation policy:
        # - real config scenario (DWLABBIND_TEST_NAMED_CONF set): run real named-checkconf/checkzone
        # - synthetic scenario: mock validation for deterministic test execution
        # - override with DWLABBIND_TEST_VALIDATE=1|0
        validate_enabled = bool(env_named_conf)
        if env_validate is not None:
            validate_enabled = env_validate.strip().lower() in {"1", "true", "yes", "on"}

        validation_ctx = (
            contextlib.nullcontext()
            if validate_enabled
            else mock.patch.object(BindServer, "_validate_layout", return_value=None)
        )
        with validation_ctx:
            result = initialize_named_conf(
                named_conf=named_conf,
                backup_output=backup_tar,
                named_etc=etc_bind,
                named_var=var_bind,
            )

        self.assertTrue(os.path.exists(result["archive"]))
        self.assertEqual(result["archive"], backup_tar)
        self.assertTrue(os.path.exists(result["xml"]))
        self.assertEqual(result["xml"], os.path.join(os.path.dirname(named_conf), "dwlabbind.xml"))
        self.assertTrue(os.path.exists(result["conf"]))
        self.assertEqual(result["conf"], os.path.join(etc_bind, "dwlab.named.conf"))

        named_conf_link = os.path.join(etc_bind, "named.conf")
        self.assertTrue(os.path.islink(named_conf_link))
        self.assertEqual(os.readlink(named_conf_link), os.path.join(etc_bind, "dwlab.named.conf"))
        self.assertFalse(os.path.exists(os.path.join(etc_bind, "named.conf.working-on")))
        self.assertTrue(os.path.exists(os.path.join(etc_bind, "dwlab", "dwlabdns.options.conf")))

        # Do not cleanup testrun directory by design; it is requested for inspection.
        self.assertTrue(os.path.isdir(run_dir))

    def test_initialize_cleanup_removes_unreferenced_legacy_files(self) -> None:
        run_dir = _next_testrun_dir()
        etc_bind = os.path.join(run_dir, "etc", "bind")
        var_bind = os.path.join(run_dir, "var", "lib", "bind")
        os.makedirs(etc_bind, exist_ok=True)
        os.makedirs(var_bind, exist_ok=True)

        named_conf = os.path.join(etc_bind, "named.conf")
        old_conf = os.path.join(etc_bind, "old.conf")
        backup_tar = os.path.join(run_dir, "backup.tar")
        with open(old_conf, "w", encoding="utf-8") as handle:
            handle.write('acl oldclients { 127.0.0.1; };' + "\n")
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
