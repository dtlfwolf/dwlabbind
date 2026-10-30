"""Local script entry points for bindconf operations."""

from __future__ import annotations

import argparse
import logging

from dwlabbasicpy.dwlabSettings import dwlabSettings

from .api import serve
from .bind_conf import (
    BindConfigurationManager,
    BindOperationError,
)
from .dynamic_dns import handle_dynamic_dns_update

from dwlabbind.zone_create_options import add_zone_type_options, validate_zone_type_options

logger = logging.getLogger(__name__)


def _resolve_zone_create_inputs(args: argparse.Namespace) -> tuple[str, str, str]:
    settings_path = getattr(args, "yaml", None) or getattr(args, "xml", None)
    settings = None
    if getattr(args, "yaml", None):
        settings = dwlabSettings.read_yaml(args.yaml)
    elif getattr(args, "xml", None):
        settings = dwlabSettings.read_xml(args.xml)

    domain_name = (args.domain_name or "").strip()
    dns_server = (args.dns_server or "").strip()
    base_hostname = (args.base_hostname or "").strip()

    if settings is not None:
        domain_name = domain_name or str(settings.get_variable("domain_name") or "").strip()
        dns_server = dns_server or str(settings.get_variable("dns_server") or "").strip()
        base_hostname = base_hostname or str(settings.get_variable("base_hostname") or "").strip()

    if domain_name and dns_server and base_hostname:
        return domain_name, dns_server, base_hostname

    missing: list[str] = []
    if not domain_name:
        missing.append("domain_name")
    if not dns_server:
        missing.append("dns_server")
    if not base_hostname:
        missing.append("base_hostname")

    hint = (
        "Provide --domain-name/--dns-server/--base-hostname or use --yaml/--xml with "
        "domain_name, dns_server, and base_hostname."
    )
    if settings_path:
        hint = f"Missing {', '.join(missing)} in settings file {settings_path}. {hint}"

    raise BindOperationError(
        "MISSING_ZONE_CREATE_INPUT",
        f"Missing zone-create input(s): {', '.join(missing)}",
        hint=hint,
        status=400,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="dwlabbind local utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="Backup named.conf and referenced files")
    backup.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")
    backup.add_argument("--output", required=True, metavar="FILE", help="Full output archive path (e.g. /tmp/named.backup.tar)")

    imp = sub.add_parser("import", help="Import named.conf and write dwlabbind.xml")
    imp.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")

    list_zones = sub.add_parser("list-zones", help="List zones discovered from named.conf")
    list_zones.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")

    restore = sub.add_parser("restore", help="Restore named.conf and related files from backup")
    restore.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")
    restore.add_argument(
        "--archive",
        default=None,
        metavar="FILE",
        help="Optional backup archive path. If omitted, the newest named.dwlab.conf.*.tar beside --named-conf is used.",
    )
    restore.add_argument(
        "--named-etc",
        default=None,
        metavar="DIR",
        help="Target named configuration directory (default: directory of --named-conf)",
    )
    restore.add_argument(
        "--named-var",
        default=None,
        metavar="DIR",
        help="Target named zone-file directory root (default: /var/lib/bind)",
    )
    restore.add_argument(
        "--force",
        action="store_true",
        help="Ignore stale named.conf.working-on lock and force restore",
    )

    init = sub.add_parser("initialize", help="Backup, import, and write managed dwlab config")
    init.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")
    init.add_argument(
        "--xml-input",
        default=None,
        metavar="FILE",
        help="Optional dwlabbind XML input used as configuration source for initialize",
    )
    init.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Optional full backup archive path. If omitted: <named-conf-dir>/named.dwlab.conf.<timestamp>.tar",
    )
    init.add_argument(
        "--named-etc",
        default=None,
        metavar="DIR",
        help="Target named configuration directory (default: directory of --named-conf)",
    )
    init.add_argument(
        "--named-var",
        default=None,
        metavar="DIR",
        help="Target named zone-file directory root (default: /var/lib/bind)",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="Ignore stale named.conf.working-on lock and force overwrite/recovery",
    )
    init.add_argument(
        "--nocleanup",
        action="store_true",
        help="Disable post-initialize cleanup of unreferenced legacy backed-up files",
    )
    init.add_argument(
        "--keep-stage-on-error",
        action="store_true",
        help="Keep temporary stage directory when initialize fails validation",
    )

    api = sub.add_parser("serve-api", help="Serve REST API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)
    api.add_argument("--desired-state", default=None, metavar="FILE")
    api.add_argument("--api-token", default=None, metavar="TOKEN", help="Required when listening beyond loopback")
    api.add_argument("--managed-named-conf", default="/etc/bind/named.conf", metavar="FILE")
    api.add_argument("--managed-named-etc", default="/etc/bind", metavar="DIR")
    api.add_argument("--managed-named-var", default="/var/lib/bind", metavar="DIR")
    api.add_argument("--named-service", default="named", metavar="UNIT")

    add_host = sub.add_parser("fixed-host-add", help="Add static A/AAAA and PTR records into matching zones")
    add_host.add_argument(
        "--named-conf",
        default="/etc/bind/named.conf",
        metavar="FILE",
        help="Optional full path to named.conf (default: /etc/bind/named.conf)",
    )
    add_host.add_argument("--fqdn", required=True, metavar="FQDN", help="Host FQDN (e.g. host.example.com)")
    add_host.add_argument("--ip", required=True, metavar="IP", help="IPv4/IPv6 address")
    add_host.add_argument("--ttl", default=None, metavar="TTL", help="Optional TTL for generated records")
    add_host.add_argument(
        "--named-etc",
        default=None,
        metavar="DIR",
        help="Target named configuration directory (default: directory of --named-conf)",
    )
    add_host.add_argument(
        "--named-var",
        default=None,
        metavar="DIR",
        help="Target named zone-file directory root (default: /var/lib/bind)",
    )
    add_host.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing host/ip mappings if they already exist",
    )

    del_host = sub.add_parser("fixed-host-delete", help="Delete static host mapping from forward/reverse zones")
    del_host.add_argument(
        "--named-conf",
        default="/etc/bind/named.conf",
        metavar="FILE",
        help="Optional full path to named.conf (default: /etc/bind/named.conf)",
    )
    del_host.add_argument("--fqdn", required=True, metavar="FQDN", help="Host FQDN (e.g. host.example.com)")
    del_host.add_argument("--ip", default=None, metavar="IP", help="Optional IPv4/IPv6 to delete a specific mapping")
    del_host.add_argument(
        "--named-etc",
        default=None,
        metavar="DIR",
        help="Target named configuration directory (default: directory of --named-conf)",
    )
    del_host.add_argument(
        "--named-var",
        default=None,
        metavar="DIR",
        help="Target named zone-file directory root (default: /var/lib/bind)",
    )
    del_host.add_argument(
        "--force",
        action="store_true",
        help="Reserved flag for future delete conflict policies",
    )

    zone_create = sub.add_parser("zone-create", help="Create primary forward/reverse zones or a forwarding zone")
    add_zone_type_options(zone_create)
    zone_create.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Optional full path to named.conf (default: /etc/bind/named.conf)")
    zone_create.add_argument("--domain-name", default=None, metavar="DOMAIN", help="Domain name (e.g. example.com)")
    zone_create.add_argument("--dns-server", default=None, metavar="IP/PREFIX", help="DNS server IPv4 with /8,/16,/24 prefix (e.g. 192.168.5.10/24)")
    zone_create.add_argument("--base-hostname", default=None, metavar="HOST", help="Base hostname for NS/A records (e.g. ns1)")
    zone_create.add_argument("--yaml", default=None, metavar="FILE", help="Read base_hostname, domain_name, and dns_server from a YAML settings file")
    zone_create.add_argument("--xml", default=None, metavar="FILE", help="Read base_hostname, domain_name, and dns_server from an XML settings file")
    zone_create.add_argument("--named-etc", default=None, metavar="DIR", help="Target named configuration directory (default: directory of --named-conf)")
    zone_create.add_argument("--named-var", default=None, metavar="DIR", help="Target named zone-file directory root (default: /var/lib/bind)")
    zone_create.add_argument("--no-allow-recursion", action="store_true", help="Do not inject default allow-recursion setting")
    zone_create.add_argument("--no-allow-update", action="store_true", help="Do not inject allow-update/key defaults")
    zone_create.add_argument("--force", action="store_true", help="Replace existing forward/reverse zones when already present")

    zone_delete = sub.add_parser("zone-delete", help="Delete a managed zone and optionally linked reverse zone")
    zone_delete.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Optional full path to named.conf (default: /etc/bind/named.conf)")
    zone_delete.add_argument("--zone-name", required=True, metavar="ZONE", help="Forward or reverse zone name to delete")
    zone_delete.add_argument("--named-etc", default=None, metavar="DIR", help="Target named configuration directory (default: directory of --named-conf)")
    zone_delete.add_argument("--named-var", default=None, metavar="DIR", help="Target named zone-file directory root (default: /var/lib/bind)")
    zone_delete.add_argument("--remove-files", action="store_true", help="Also remove generated zone files and FixedHosts include files")
    zone_delete.add_argument("--no-delete-related", action="store_true", help="Delete only the requested zone and keep linked forward/reverse zones")
    zone_delete.add_argument("--force", action="store_true", help="Reserved flag for future delete conflict policies")

    zone_update = sub.add_parser("zone-update", help="Bump the SOA serial for a zone and rewrite the managed layout")
    zone_update.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Optional full path to named.conf (default: /etc/bind/named.conf)")
    zone_update.add_argument("--zone-name", required=True, metavar="ZONE", help="Zone name whose SOA serial should be bumped")
    zone_update.add_argument("--named-etc", default=None, metavar="DIR", help="Target named configuration directory (default: directory of --named-conf)")
    zone_update.add_argument("--named-var", default=None, metavar="DIR", help="Target named zone-file directory root (default: /var/lib/bind)")

    create_tsig = sub.add_parser("create-tsig", help="Create or replace a standalone TSIG key definition")
    create_tsig.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Optional full path to named.conf (default: /etc/bind/named.conf)")
    create_tsig.add_argument("--key-name", required=True, metavar="NAME", help="TSIG key name, typically a zone FQDN")
    create_tsig.add_argument("--algorithm", default="hmac-sha256", metavar="ALGO", help="TSIG algorithm (default: hmac-sha256)")
    create_tsig.add_argument("--named-etc", default=None, metavar="DIR", help="Target named configuration directory (default: directory of --named-conf)")
    create_tsig.add_argument("--named-var", default=None, metavar="DIR", help="Target named zone-file directory root (default: /var/lib/bind)")
    create_tsig.add_argument("--force", action="store_true", help="Replace an existing TSIG key definition with the same name")

    dns_update = sub.add_parser("dns-update", help="Apply generic dynamic DNS add/delete updates")
    dns_update.add_argument("action", choices=["add", "delete"], help="Dynamic DNS update action")
    dns_update.add_argument("--settings", required=True, metavar="FILE", help="YAML file with DNS update settings")
    dns_update.add_argument("--fqdn", required=True, metavar="FQDN", help="Fully qualified domain name to update")
    dns_update.add_argument("--ip", required=True, metavar="IP", help="IPv4 address for A/PTR update")

    args = parser.parse_args()
    manager = BindConfigurationManager()
    try:
        if args.command == "backup":
            path = manager.backup_named_conf(args.named_conf, args.output)
            print(path)
            return
        if args.command == "import":
            path = manager.import_named_conf(args.named_conf)
            print(path)
            return
        if args.command == "list-zones":
            zones = manager.list_zones_from_conf(args.named_conf)
            for zone in zones:
                status = zone.get("management_state") or ("package-managed" if zone.get("externally_managed") else "un-managed")
                direction = "reverse" if zone.get("reverse") else "forward"
                ddns = "ddns" if zone.get("ddns_enabled") else "static"
                print(
                    f"{zone.get('zone_name')} | {direction} | {zone.get('zone_type') or '-'} | {ddns} | {status} | {zone.get('file_path')}"
                )
            return
        if args.command == "restore":
            result = manager.restore_named_conf(
                named_conf=args.named_conf,
                archive_path=args.archive,
                force=args.force,
                named_etc=args.named_etc,
                named_var=args.named_var,
            )
            logger.info(
                "restore completed (named_conf=%s, archive=%s, xml=%s)",
                result.get("named_conf"),
                result.get("archive"),
                result.get("xml"),
            )
            return
        if args.command == "initialize":
            result = manager.initialize_named_conf(
                named_conf=args.named_conf,
                xml_input=args.xml_input,
                backup_output=args.output,
                named_etc=args.named_etc,
                named_var=args.named_var,
                force=args.force,
                cleanup=not args.nocleanup,
                keep_stage_on_error=args.keep_stage_on_error,
            )
            logger.info(
                "initialize completed (named_conf=%s, backup=%s, xml=%s, conf=%s)",
                args.named_conf,
                result.get("archive"),
                result.get("xml"),
                result.get("conf"),
            )
            return
        if args.command == "serve-api":
            serve(
                host=args.host,
                port=args.port,
                desired_state_path=args.desired_state,
                api_token=args.api_token,
                managed_named_conf=args.managed_named_conf,
                managed_named_etc=args.managed_named_etc,
                managed_named_var=args.managed_named_var,
                named_service=args.named_service,
            )
            return
        if args.command == "fixed-host-add":
            result = manager.add_fixed_host_and_write(
                named_conf=args.named_conf,
                fqdn=args.fqdn,
                ip_address=args.ip,
                ttl=args.ttl,
                force=args.force,
                named_etc=args.named_etc,
                named_var=args.named_var,
            )
            logger.info(
                "fixed host added and configuration written (named_conf=%s, fqdn=%s, ip=%s, forward_zone=%s, reverse_zone=%s, xml=%s, conf=%s)",
                args.named_conf,
                result.get("fqdn"),
                result.get("ip"),
                result.get("forward_zone"),
                result.get("reverse_zone"),
                result.get("xml"),
                result.get("conf"),
            )
            return
        if args.command == "fixed-host-delete":
            result = manager.delete_fixed_host_and_write(
                named_conf=args.named_conf,
                fqdn=args.fqdn,
                ip_address=args.ip,
                force=args.force,
                named_etc=args.named_etc,
                named_var=args.named_var,
            )
            logger.info(
                "fixed host deleted and configuration written (named_conf=%s, fqdn=%s, ip=%s, forward_zone=%s, removed_forward=%s, removed_reverse=%s, xml=%s, conf=%s)",
                args.named_conf,
                result.get("fqdn"),
                result.get("ip"),
                result.get("forward_zone"),
                result.get("removed_forward_records"),
                result.get("removed_reverse_records"),
                result.get("xml"),
                result.get("conf"),
            )
            return
        if args.command == "zone-create":
            validate_zone_type_options(args)
            if args.zone_type == "forward":
                result = manager.create_forward_zone_and_write(
                    named_conf=args.named_conf,
                    domain_name=args.domain_name,
                    forwarders=args.forwarder,
                    forward_mode=args.forward_mode or "only",
                    force=args.force,
                    named_etc=args.named_etc,
                    named_var=args.named_var,
                )
                logger.info("forwarding zone created (domain=%s, conf=%s, xml=%s)",
                            result.get("domain"), result.get("conf"), result.get("xml"))
                return
            domain_name, dns_server, base_hostname = _resolve_zone_create_inputs(args)
            result = manager.create_zone_and_write(
                named_conf=args.named_conf,
                domain_name=domain_name,
                dns_server_cidr=dns_server,
                base_hostname=base_hostname,
                force=args.force,
                named_etc=args.named_etc,
                named_var=args.named_var,
                enable_allow_recursion=not args.no_allow_recursion,
                enable_allow_update=not args.no_allow_update,
            )
            logger.info(
                "zone created and configuration written (domain=%s, reverse_zone=%s, conf=%s, xml=%s)",
                result.get("domain"),
                result.get("reverse_zone"),
                result.get("conf"),
                result.get("xml"),
            )
            return
        if args.command == "zone-delete":
            result = manager.delete_zone_and_write(
                named_conf=args.named_conf,
                zone_name=args.zone_name,
                force=args.force,
                named_etc=args.named_etc,
                named_var=args.named_var,
                remove_files=args.remove_files,
                delete_related=not args.no_delete_related,
            )
            logger.info(
                "zone deleted and configuration written (zone=%s, deleted_zones=%s, removed_files=%s, conf=%s, xml=%s)",
                args.zone_name,
                result.get("deleted_zones"),
                result.get("deleted_files"),
                result.get("conf"),
                result.get("xml"),
            )
            return
        if args.command == "zone-update":
            result = manager.update_zone_serial_and_write(
                named_conf=args.named_conf,
                zone_name=args.zone_name,
                named_etc=args.named_etc,
                named_var=args.named_var,
            )
            logger.info(
                "zone serial updated and configuration written (zone=%s, old_serial=%s, new_serial=%s, conf=%s, xml=%s)",
                result.get("zone"),
                result.get("old_serial"),
                result.get("new_serial"),
                result.get("conf"),
                result.get("xml"),
            )
            return
        if args.command == "create-tsig":
            result = manager.create_tsig_key_and_write(
                named_conf=args.named_conf,
                key_name=args.key_name,
                algorithm=args.algorithm,
                force=args.force,
                named_etc=args.named_etc,
                named_var=args.named_var,
            )
            logger.info(
                "tsig key %s and configuration written (key_name=%s, algorithm=%s, conf=%s, xml=%s)",
                result.get("action"),
                result.get("key_name"),
                result.get("algorithm"),
                result.get("conf"),
                result.get("xml"),
            )
            return
        if args.command == "dns-update":
            result = handle_dynamic_dns_update(
                args.action,
                settings_path=args.settings,
                fqdn=args.fqdn,
                ip_address=args.ip,
            )
            logger.info(
                "dns update handled (action=%s, fqdn=%s, ip=%s, dns_zone=%s)",
                result.get("action"),
                result.get("fqdn"),
                result.get("ip_address"),
                result.get("dns_zone"),
            )
            return
    except BindOperationError as exc:
        if exc.code == "LOCK_EXISTS":
            logger.warning("Lock detected. If stale, rerun with '--force'.")
        if exc.code == "HOST_EXISTS":
            logger.warning("Host/IP mapping already exists. Re-run with '--force' to overwrite.")
        if exc.code == "HOST_NOT_FOUND":
            logger.warning("No host mapping found for the provided fqdn/ip.")
        if exc.hint:
            logger.warning("Hint: %s", exc.hint)
        logger.error("[%s] %s", exc.code, str(exc))
        raise SystemExit(2)
    except RuntimeError as exc:
        msg = str(exc)
        if "named.conf.working-on already exists" in msg:
            logger.warning(
                "Initialization aborted due to active lock file. If this is stale, rerun with '--force'."
            )
        logger.error("Command '%s' failed: %s", args.command, msg)
        raise SystemExit(2)
    except Exception as exc:
        logger.error("Unexpected failure in command '%s': %s", args.command, exc)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
