from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from dwlabbasicpy import dwlabSettings


@dataclass
class DynamicDnsSettings:
    dns_zone: str
    dns_reverse_zone: str
    dns_zone_private_update_key: Path
    dns_host_ip: str

    @classmethod
    def from_file(cls, path: Path) -> "DynamicDnsSettings":
        raw = dwlabSettings.read_yaml(path)
        return cls(
            dns_zone=str(raw.get_variable("dnsZone") or "").strip().rstrip("."),
            dns_reverse_zone=str(raw.get_variable("dnsReverseZone") or "").strip().rstrip("."),
            dns_zone_private_update_key=Path(
                str(raw.get_variable("dnsZonePrivateUpdateKey") or "").strip()
            ),
            dns_host_ip=str(raw.get_variable("dnsHostIP") or "").strip(),
        )

    def validate(self) -> None:
        if not self.dns_zone:
            raise ValueError("dnsZone is required.")
        if not self.dns_reverse_zone:
            raise ValueError("dnsReverseZone is required.")
        if not self.dns_host_ip:
            raise ValueError("dnsHostIP is required.")
        if not str(self.dns_zone_private_update_key):
            raise ValueError("dnsZonePrivateUpdateKey is required.")


def reverse_pointer_entry(ip_address: str, fqdn: str) -> str:
    address = ipaddress.ip_address(ip_address)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 dynamic DNS updates are supported.")
    octets = str(address).split(".")
    owner = ".".join(reversed(octets)) + ".in-addr.arpa."
    return f"{owner} 86400 PTR {fqdn}."


def run_nsupdate(
    command: list[str],
    payload: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    run = runner or subprocess.run
    return run(
        command,
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )


def handle_dynamic_dns_update(
    action: str,
    settings_path: Path,
    *,
    fqdn: str,
    ip_address: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, object]:
    normalized_action = (action or "").strip().lower()
    if normalized_action not in {"add", "delete"}:
        raise ValueError(f"Unsupported DNS update action: {action}")

    resolved_fqdn = (fqdn or "").strip().rstrip(".")
    resolved_ip = (ip_address or "").strip()
    if not resolved_fqdn:
        raise ValueError("Missing FQDN.")
    if not resolved_ip:
        raise ValueError("Missing IP address.")

    settings = DynamicDnsSettings.from_file(settings_path)
    settings.validate()
    pointer_entry = reverse_pointer_entry(resolved_ip, resolved_fqdn)
    nsupdate_command = ["nsupdate", "-k", str(settings.dns_zone_private_update_key)]

    if normalized_action == "add":
        forward_payload = "\n".join(
            [
                f"server {settings.dns_host_ip}",
                f"zone {settings.dns_zone}",
                f"update add {resolved_fqdn} 86400 A {resolved_ip}",
                "send",
                "quit",
                "",
            ]
        )
        reverse_payload = "\n".join(
            [
                f"server {settings.dns_host_ip}",
                f"zone {settings.dns_reverse_zone}",
                f"update add {pointer_entry}",
                "send",
                "quit",
                "",
            ]
        )
    else:
        forward_payload = "\n".join(
            [
                f"server {settings.dns_host_ip}",
                f"zone {settings.dns_zone}",
                f"update delete {resolved_fqdn} A",
                "send",
                "quit",
                "",
            ]
        )
        reverse_payload = "\n".join(
            [
                f"server {settings.dns_host_ip}",
                f"zone {settings.dns_reverse_zone}",
                f"update delete {pointer_entry}",
                "send",
                "quit",
                "",
            ]
        )

    forward_result = run_nsupdate(nsupdate_command, forward_payload, runner=runner)
    if forward_result.returncode != 0:
        raise RuntimeError(
            forward_result.stderr.strip()
            or forward_result.stdout.strip()
            or "Forward DNS update failed."
        )

    reverse_result = run_nsupdate(nsupdate_command, reverse_payload, runner=runner)
    if reverse_result.returncode != 0:
        raise RuntimeError(
            reverse_result.stderr.strip()
            or reverse_result.stdout.strip()
            or "Reverse DNS update failed."
        )

    return {
        "action": normalized_action,
        "fqdn": resolved_fqdn,
        "ip_address": resolved_ip,
        "dns_zone": settings.dns_zone,
        "dns_reverse_zone": settings.dns_reverse_zone,
        "dns_host_ip": settings.dns_host_ip,
        "dns_zone_private_update_key": str(settings.dns_zone_private_update_key),
        "reverse_pointer": pointer_entry,
        "forward_stdout": forward_result.stdout,
        "reverse_stdout": reverse_result.stdout,
    }
