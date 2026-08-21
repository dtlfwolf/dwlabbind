from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from dwlabbind.dynamic_dns import handle_dynamic_dns_update


def _write_settings(path: Path) -> None:
    path.write_text(
        "\n".join(
            [
                "dnsZone: ovpnprivate.example.internal",
                "dnsReverseZone: 4.8.10.in-addr.arpa",
                "dnsZonePrivateUpdateKey: /etc/bind/dwlab/keys/ovpnprivate.example.internal.key.key",
                "dnsHostIP: 10.8.4.1",
                "",
            ]
        ),
        encoding="utf-8",
    )


def test_handle_dynamic_dns_update_add_issues_forward_and_reverse_updates(tmp_path: Path) -> None:
    settings_path = tmp_path / "hook.yaml"
    _write_settings(settings_path)

    calls: list[tuple[list[str], str]] = []

    def fake_runner(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((list(args), str(kwargs.get("input", ""))))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    result = handle_dynamic_dns_update(
        "add",
        settings_path,
        fqdn="branch-office-01.ovpnprivate.example.internal",
        ip_address="10.8.4.42",
        runner=fake_runner,
    )

    assert result["fqdn"] == "branch-office-01.ovpnprivate.example.internal"
    assert result["reverse_pointer"] == "42.4.8.10.in-addr.arpa. 86400 PTR branch-office-01.ovpnprivate.example.internal."
    assert len(calls) == 2
    assert calls[0][0] == ["nsupdate", "-k", "/etc/bind/dwlab/keys/ovpnprivate.example.internal.key.key"]
    assert "update add branch-office-01.ovpnprivate.example.internal 86400 A 10.8.4.42" in calls[0][1]
    assert "update add 42.4.8.10.in-addr.arpa. 86400 PTR branch-office-01.ovpnprivate.example.internal." in calls[1][1]


def test_handle_dynamic_dns_update_delete_issues_forward_and_reverse_updates(tmp_path: Path) -> None:
    settings_path = tmp_path / "hook.yaml"
    _write_settings(settings_path)

    calls: list[str] = []

    def fake_runner(args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(str(kwargs.get("input", "")))
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    result = handle_dynamic_dns_update(
        "delete",
        settings_path,
        fqdn="branch-office-02.ovpnprivate.example.internal",
        ip_address="10.8.4.43",
        runner=fake_runner,
    )

    assert result["ip_address"] == "10.8.4.43"
    assert "update delete branch-office-02.ovpnprivate.example.internal A" in calls[0]
    assert "update delete 43.4.8.10.in-addr.arpa. 86400 PTR branch-office-02.ovpnprivate.example.internal." in calls[1]


def test_handle_dynamic_dns_update_rejects_unknown_action(tmp_path: Path) -> None:
    settings_path = tmp_path / "hook.yaml"
    _write_settings(settings_path)

    with pytest.raises(ValueError):
        handle_dynamic_dns_update(
            "rotate",
            settings_path,
            fqdn="branch-office-03.ovpnprivate.example.internal",
            ip_address="10.8.4.44",
        )
