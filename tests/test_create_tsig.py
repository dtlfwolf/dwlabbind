import os
import unittest
from datetime import datetime
from importlib import import_module
from unittest import mock

from helpers.bind_fixture import BindFixture
from helpers.test_run_artifacts import TestRunArtifacts


def _bind_conf_exports():
    with mock.patch("dwlabbasicpy.dwlabLogger.setup_logging", return_value=None):
        module = import_module("dwlabbind.bind_conf")
    return module.BindServer, module.BindConfigurationManager


class TestCreateTsig(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts = TestRunArtifacts.create()

    def test_create_tsig_archive_fixture_and_write(self) -> None:
        BindServer, BindConfigurationManager = _bind_conf_exports()
        fixture_names = BindFixture.discover()
        self.assertTrue(fixture_names, "No archive fixtures discovered in tests/fixtures/archives")

        summary: dict[str, object] = {
            "created_at": datetime.now().isoformat(),
            "test_module": "test_create_tsig",
            "fixtures": [],
        }

        for fixture_name in fixture_names:
            with self.subTest(fixture=fixture_name):
                with BindFixture.load(fixture_name) as fixture:
                    sample = self.artifacts.sample(fixture_name)
                    sample.write_fixture_metadata(fixture.manifest)
                    sample.copy_fixture_file(fixture.archive_path)
                    sample.copy_fixture_file(fixture.manifest_path)
                    sample.append_log("suite.log", f"create-tsig start fixture={fixture_name}")

                    manager = BindConfigurationManager()
                    key_name = "dwlabbind-test-tsig"
                    with mock.patch.object(BindServer, "_validate_layout", return_value=None):
                        result = manager.create_tsig_key_and_write(
                            named_conf=str(fixture.named_conf),
                            key_name=key_name,
                            algorithm="hmac-sha256",
                            named_etc=str(fixture.named_etc),
                            named_var=str(fixture.named_var),
                        )

                    scenario = sample.scenario(9, "create-tsig")
                    scenario.copy_file(fixture.named_conf, "input/named.conf")
                    if fixture.named_etc.exists():
                        scenario.copy_tree(fixture.named_etc, "generated/etc")
                    if fixture.named_var.exists():
                        scenario.copy_tree(fixture.named_var, "generated/var")

                    key_path = fixture.named_etc / "dwlab" / "keys" / "dwlabbind-test-tsig.key"
                    key_text = key_path.read_text(encoding="utf-8") if key_path.exists() else ""
                    status_payload = {
                        "fixture": fixture_name,
                        "status": "passed",
                        "result": result,
                        "key_path": str(key_path),
                    }
                    scenario.write_status(status_payload)
                    sample.append_log(
                        "create-tsig.log",
                        f"fixture={fixture_name} key_name={result['key_name']} action={result['action']}",
                    )
                    summary["fixtures"].append(status_payload)

                    self.assertEqual(result["key_name"], key_name)
                    self.assertEqual(result["algorithm"], "hmac-sha256")
                    self.assertTrue(key_path.exists())
                    self.assertIn('key "dwlabbind-test-tsig"', key_text)
                    self.assertIn("algorithm hmac-sha256;", key_text)
                    self.assertIn("secret ", key_text)
                    self.assertTrue(os.path.exists(result["xml"]))
                    self.assertTrue(os.path.exists(result["conf"]))

        self.artifacts.write_summary(summary)


if __name__ == "__main__":
    unittest.main()
