"""CLI runner for local management scripts."""

from __future__ import annotations

import argparse
import json
import sys

from .api import BindApiServer
from .importers import import_server_config
from .models import BindServer, BindZone, HAConfig, SecurityConfig
from .xml_store import XmlConfigStore


def _cmd_init(args: argparse.Namespace) -> None:
    store = XmlConfigStore(args.config)
    security = SecurityConfig(enabled=args.security_enabled)
    ha = HAConfig(enabled=args.ha_enabled, mode=args.ha_mode, peers=args.ha_peers)
    server = BindServer(
        name=args.name,
        ip=args.ip,
        port=args.port,
        role=args.role,
        security=security,
        high_availability=ha,
    )
    store.save(server)


def _cmd_show(args: argparse.Namespace) -> None:
    store = XmlConfigStore(args.config)
    server = store.load()
    if server is None:
        print("config not found", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(server.to_dict(), indent=2))


def _cmd_add_zone(args: argparse.Namespace) -> None:
    store = XmlConfigStore(args.config)
    server = store.load()
    if server is None:
        print("config not found", file=sys.stderr)
        sys.exit(1)
    zone = BindZone(
        name=args.name,
        zone_type=args.type,
        file=args.file,
        masters=args.masters,
        allow_update=args.allow_update,
    )
    server.add_zone(zone)
    store.save(server)


def _cmd_remove_zone(args: argparse.Namespace) -> None:
    store = XmlConfigStore(args.config)
    server = store.load()
    if server is None:
        print("config not found", file=sys.stderr)
        sys.exit(1)
    server.remove_zone(args.name)
    store.save(server)


def _cmd_serve_api(args: argparse.Namespace) -> None:
    store = XmlConfigStore(args.config)
    api = BindApiServer(store=store, host=args.host, port=args.port)
    api.start()


def _cmd_import(args: argparse.Namespace) -> None:
    store = XmlConfigStore(args.config)
    server = import_server_config(
        server_type=args.server_type,
        config_path=args.config_path,
        name=args.name,
        ip=args.ip,
        port=args.port,
        role=args.role,
        version=args.version,
    )
    store.save(server)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage BIND server configuration")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to XML config (defaults to OS-specific config directory)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Initialize a new config")
    init.add_argument("--name", required=True)
    init.add_argument("--ip", required=True)
    init.add_argument("--port", type=int, default=53)
    init.add_argument("--role", default="master")
    init.add_argument("--security-enabled", action="store_true")
    init.add_argument("--ha-enabled", action="store_true")
    init.add_argument("--ha-mode", default="active-passive")
    init.add_argument("--ha-peers", nargs="*", default=[])
    init.set_defaults(func=_cmd_init)

    show = subparsers.add_parser("show", help="Print current config")
    show.set_defaults(func=_cmd_show)

    add_zone = subparsers.add_parser("add-zone", help="Add a zone")
    add_zone.add_argument("--name", required=True)
    add_zone.add_argument("--type", required=True, choices=["master", "slave"])
    add_zone.add_argument("--file", required=True)
    add_zone.add_argument("--masters", nargs="*", default=[])
    add_zone.add_argument("--allow-update", action="store_true")
    add_zone.set_defaults(func=_cmd_add_zone)

    remove_zone = subparsers.add_parser("remove-zone", help="Remove a zone")
    remove_zone.add_argument("--name", required=True)
    remove_zone.set_defaults(func=_cmd_remove_zone)

    serve_api = subparsers.add_parser("serve-api", help="Serve REST API")
    serve_api.add_argument("--host", default="127.0.0.1")
    serve_api.add_argument("--port", type=int, default=8080)
    serve_api.set_defaults(func=_cmd_serve_api)

    import_config = subparsers.add_parser("import", help="Import existing DNS config")
    import_config.add_argument("--server-type", required=True, choices=["bind9", "powerdns", "msdns"])
    import_config.add_argument("--config-path", required=True, help="Path to server config or zone list")
    import_config.add_argument("--name", required=True)
    import_config.add_argument("--ip", required=True)
    import_config.add_argument("--port", type=int, default=53)
    import_config.add_argument("--role", default="master")
    import_config.add_argument("--version", default="")
    import_config.set_defaults(func=_cmd_import)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
