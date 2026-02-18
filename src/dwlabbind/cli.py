"""Local script entry points for bindconf operations."""

from __future__ import annotations

import argparse
import logging

from .bind_conf import (
    BindOperationError,
    add_fixed_host_and_write,
    backup_named_conf,
    create_zone_and_write,
    import_named_conf,
    initialize_named_conf,
)

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="dwlabbind local utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="Backup named.conf and referenced files")
    backup.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")
    backup.add_argument("--output", required=True, metavar="FILE", help="Full output archive path (e.g. /tmp/named.backup.tar)")

    imp = sub.add_parser("import", help="Import named.conf and write dwlabbind.xml")
    imp.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")

    init = sub.add_parser("initialize", help="Backup, import, and write managed dwlab config")
    init.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Full path to named.conf")
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

    add_host = sub.add_parser("add-fixed-host", help="Add static A/AAAA and PTR records into matching zones")
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

    zone_create = sub.add_parser("zone-create", help="Create forward/reverse zone from minimal parameters")
    zone_create.add_argument("--named-conf", default="/etc/bind/named.conf", metavar="FILE", help="Optional full path to named.conf (default: /etc/bind/named.conf)")
    zone_create.add_argument("--domain-name", required=True, metavar="DOMAIN", help="Domain name (e.g. example.com)")
    zone_create.add_argument("--dns-server", required=True, metavar="IP/PREFIX", help="DNS server IPv4 with /8,/16,/24 prefix (e.g. 192.168.5.10/24)")
    zone_create.add_argument("--base-hostname", required=True, metavar="HOST", help="Base hostname for NS/A records (e.g. ns1)")
    zone_create.add_argument("--named-etc", default=None, metavar="DIR", help="Target named configuration directory (default: directory of --named-conf)")
    zone_create.add_argument("--named-var", default=None, metavar="DIR", help="Target named zone-file directory root (default: /var/lib/bind)")
    zone_create.add_argument("--no-allow-recursion", action="store_true", help="Do not inject default allow-recursion setting")
    zone_create.add_argument("--no-allow-update", action="store_true", help="Do not inject allow-update/key defaults")
    zone_create.add_argument("--force", action="store_true", help="Replace existing forward/reverse zones when already present")

    args = parser.parse_args()
    try:
        if args.command == "backup":
            path = backup_named_conf(args.named_conf, args.output)
            print(path)
            return
        if args.command == "import":
            path = import_named_conf(args.named_conf)
            print(path)
            return
        if args.command == "initialize":
            result = initialize_named_conf(
                named_conf=args.named_conf,
                backup_output=args.output,
                named_etc=args.named_etc,
                named_var=args.named_var,
                force=args.force,
                cleanup=not args.nocleanup,
            )
            logger.info(
                "initialize completed (named_conf=%s, backup=%s, xml=%s, conf=%s)",
                args.named_conf,
                result.get("archive"),
                result.get("xml"),
                result.get("conf"),
            )
            return
        if args.command == "add-fixed-host":
            result = add_fixed_host_and_write(
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
        if args.command == "zone-create":
            result = create_zone_and_write(
                named_conf=args.named_conf,
                domain_name=args.domain_name,
                dns_server_cidr=args.dns_server,
                base_hostname=args.base_hostname,
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
    except BindOperationError as exc:
        if exc.code == "LOCK_EXISTS":
            logger.warning("Lock detected. If stale, rerun with '--force'.")
        if exc.code == "HOST_EXISTS":
            logger.warning("Host/IP mapping already exists. Re-run with '--force' to overwrite.")
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
