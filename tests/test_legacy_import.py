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
