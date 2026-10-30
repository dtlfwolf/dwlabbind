from importlib import import_module
from unittest.mock import patch

import pytest

from dwlabbind.bind_conf import BindConfigurationManager, BindOperationError, BindServer


@pytest.mark.parametrize("mode", ["only", "first"])
def test_forward_zone_write_validates_and_round_trips(tmp_path, mode):
    etc, var = tmp_path / "etc", tmp_path / "var"
    etc.mkdir()
    main = etc / "named.conf"
    main.write_text("// existing configuration\n")
    result = BindConfigurationManager().create_forward_zone_and_write(
        str(main), "example.test", ["192.0.2.10", "2001:db8::10"],
        forward_mode=mode, named_etc=str(etc), named_var=str(var),
    )
    zone_text = (etc / "dwlab/example.test.conf").read_text()
    assert "type forward;" in zone_text
    assert f"forward {mode};" in zone_text
    assert "192.0.2.10;" in zone_text and "2001:db8::10;" in zone_text
    assert "file " not in zone_text
    assert not list(var.rglob("*.zone"))
    assert not list(etc.rglob("*.key"))
    assert (etc / "dwlabbind.xml").is_file()
    restored = BindServer.fromConfFile(str(main))
    assert restored._zone_names_in_use() == {"example.test"}
    assert "forwarders" in restored._find_zone_statement("example.test").toText()
    assert result["forward_mode"] == mode


def test_force_replaces_only_requested_zone():
    server = BindServer("test")
    server.create_zone_minimal("example.test", "192.0.2.10/24", "ns1")
    with pytest.raises(BindOperationError, match="already exists"):
        server.create_forward_zone("example.test", ["192.0.2.20"])
    server.create_forward_zone("example.test", ["192.0.2.20"], force=True)
    assert server._zone_names_in_use() == {"example.test", "2.0.192.in-addr.arpa"}
    assert server._find_zone_file_object("example.test") is None
    assert "forward only;" in server._find_zone_statement("example.test").toText()


@pytest.mark.parametrize("addresses,mode", [([], "only"), (["192.0.2.1/24"], "only"),
    (["dns.example.test"], "only"), (["2001:db8::zz"], "only"), (["192.0.2.1"], "invalid")])
def test_invalid_forwarding_input_preserves_existing_zone(addresses, mode):
    server = BindServer("test")
    server.create_forward_zone("example.test", ["192.0.2.10"])
    before = server._find_zone_statement("example.test").toText()
    with pytest.raises(BindOperationError):
        server.create_forward_zone("example.test", addresses, mode, force=True)
    assert server._find_zone_statement("example.test").toText() == before


@pytest.mark.parametrize("module_name", ["dwlabbind.cli", "dwlabbind.runner"])
def test_forward_cli_dispatch(module_name):
    module = import_module(module_name)
    with patch.object(module, "BindConfigurationManager") as manager, patch("sys.argv", [
        "dwlabbind", "zone-create", "--type", "forward", "--domain-name", "example.test",
        "--forwarder", "192.0.2.10", "--forwarder", "2001:db8::10",
    ]):
        module.main()
        manager.return_value.create_forward_zone_and_write.assert_called_once_with(
            named_conf="/etc/bind/named.conf", domain_name="example.test",
            forwarders=["192.0.2.10", "2001:db8::10"], forward_mode="only",
            force=False, named_etc=None, named_var=None,
        )
        manager.return_value.create_zone_and_write.assert_not_called()


@pytest.mark.parametrize("module_name", ["dwlabbind.cli", "dwlabbind.runner"])
@pytest.mark.parametrize("extra", [
    ["--dns-server", "192.0.2.10/24"], ["--base-hostname", "ns1"],
    ["--yaml", "settings.yaml"], ["--xml", "settings.xml"],
    ["--no-allow-recursion"], ["--no-allow-update"],
    ["--type", "primary"],
])
def test_incompatible_cli_options_do_not_write(module_name, extra):
    module = import_module(module_name)
    with patch.object(module, "BindConfigurationManager") as manager, patch("sys.argv", [
        "dwlabbind", "zone-create", "--type", "forward", "--domain-name", "example.test",
        "--forwarder", "192.0.2.10", *extra,
    ]), pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2
    assert not manager.return_value.method_calls
