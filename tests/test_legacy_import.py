from __future__ import annotations

from pathlib import Path

from dwlabbind.bind_conf import BindServer
from dwlabbind.legacy_import import LegacyXmlDesiredStateImporter


def test_legacy_import_preserves_zone_records_and_requires_policy_review(tmp_path: Path) -> None:
    named_conf = tmp_path / "named.conf"
    zone_file = tmp_path / "example.test.zone"
    zone_file.write_text(
        "\n".join(
            [
                "$TTL 300",
                "@ IN SOA ns1.example.test. hostmaster.example.test. ( 1 3600 600 86400 300 )",
                "@ IN NS ns1.example.test.",
                "ns1 IN A 192.0.2.53",
                "",
            ]
        ),
        encoding="utf-8",
    )
    named_conf.write_text(
        'zone "example.test" { type master; file "example.test.zone"; };\n',
        encoding="utf-8",
    )

    result = LegacyXmlDesiredStateImporter().from_server(BindServer.fromConfFile(str(named_conf)))

    assert result.desired_state.zones[0].name == "example.test"
    assert result.desired_state.zones[0].file == "zones/example.test.zone"
    assert "@ IN NS ns1.example.test." in result.desired_state.zones[0].records
    assert [issue.code for issue in result.issues] == ["RESOLVER_POLICY_REVIEW_REQUIRED"]


def test_legacy_import_expands_includes_and_makes_omitted_owner_explicit(tmp_path: Path) -> None:
    named_conf = tmp_path / "named.conf"
    zone_file = tmp_path / "2.0.192.in-addr.arpa.zone"
    fixed_hosts = Path(f"{zone_file}.FixedHosts")
    fixed_hosts.write_text("30 IN PTR dns.example.test.\n", encoding="utf-8")
    zone_file.write_text(
        "\n".join(
            [
                "$TTL 300",
                "@ IN SOA dns.example.test. hostmaster.example.test. ( 1 3600 600 86400 300 )",
                "\tIN NS dns.example.test.",
                f'$INCLUDE "{fixed_hosts}" 2.0.192.in-addr.arpa.',
                "102 PTR client.example.test.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    named_conf.write_text(
        f'zone "2.0.192.in-addr.arpa" {{ type master; file "{zone_file}"; }};\n',
        encoding="utf-8",
    )

    result = LegacyXmlDesiredStateImporter().from_server(BindServer.fromConfFile(str(named_conf)))

    records = result.desired_state.zones[0].records
    assert "@ IN NS dns.example.test." in records
    assert "30 IN PTR dns.example.test." in records
    assert "102 PTR client.example.test." in records
    assert not any(record.startswith("$INCLUDE") for record in records)


def test_legacy_import_normalizes_an_explicit_apex_from_root_origin(tmp_path: Path) -> None:
    named_conf = tmp_path / "named.conf"
    zone_file = tmp_path / "dw-lab.de.zone"
    zone_file.write_text(
        "\n".join(
            [
                "$ORIGIN .",
                "dw-lab.de. IN SOA ns1.dw-lab.de. hostmaster.dw-lab.de. ( 1 3600 600 86400 300 )",
                "    NS ns1.dw-lab.de.",
                "$ORIGIN dw-lab.de.",
                "ns1 A 192.0.2.53",
                "host A 192.0.2.10",
                "",
            ]
        ),
        encoding="utf-8",
    )
    named_conf.write_text(
        f'zone "dw-lab.de" {{ type master; file "{zone_file}"; }};\n',
        encoding="utf-8",
    )

    result = LegacyXmlDesiredStateImporter().from_server(BindServer.fromConfFile(str(named_conf)))

    assert "@ IN SOA ns1.dw-lab.de. hostmaster.dw-lab.de. (1 3600 600 86400 300)" in result.desired_state.zones[0].records
    assert "@ NS ns1.dw-lab.de." in result.desired_state.zones[0].records
