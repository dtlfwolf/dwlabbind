"""Reusable synthetic BIND layouts for unit-level tests."""

from __future__ import annotations

import os


def write_base_host_layout(tmpdir: str) -> tuple[str, str, str]:
    """Create a minimal forward and reverse zone layout for host record tests."""
    named_conf = os.path.join(tmpdir, "named.conf")
    forward_zone_file = os.path.join(tmpdir, "db.example.com")
    reverse_zone_file = os.path.join(tmpdir, "db.2.0.192")
    with open(named_conf, "w", encoding="utf-8") as handle:
        handle.write(
            'options { recursion yes; };'
            "\n"
            f'zone "example.com" {{ type master; file "{forward_zone_file}"; }};'
            "\n"
            f'zone "2.0.192.in-addr.arpa" {{ type master; file "{reverse_zone_file}"; }};'
            "\n"
        )
    with open(forward_zone_file, "w", encoding="utf-8") as handle:
        handle.write(
            "$TTL 3600\n"
            "@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 1209600 3600\n"
            "@ IN NS ns1.example.com.\n"
        )
    with open(reverse_zone_file, "w", encoding="utf-8") as handle:
        handle.write(
            "$TTL 3600\n"
            "@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 1209600 3600\n"
            "@ IN NS ns1.example.com.\n"
        )
    return named_conf, forward_zone_file, reverse_zone_file
