"""Local script entry points for bindconf operations."""

from __future__ import annotations

import argparse

from .bind_conf import backup_named_conf, import_named_conf


def main() -> None:
    parser = argparse.ArgumentParser(description="dwlabbind local utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="Backup named.conf and referenced files")
    backup.add_argument("--named-conf", default="/etc/bind/named.conf")
    backup.add_argument("--output", required=True)

    imp = sub.add_parser("import", help="Import named.conf and write dwlabbind.xml")
    imp.add_argument("--named-conf", default="/etc/bind/named.conf")

    args = parser.parse_args()
    if args.command == "backup":
        path = backup_named_conf(args.named_conf, args.output)
        print(path)
        return
    if args.command == "import":
        path = import_named_conf(args.named_conf)
        print(path)
        return


if __name__ == "__main__":
    main()
