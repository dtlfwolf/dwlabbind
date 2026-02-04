"""Command-line entrypoint for dwlabbind."""

from __future__ import annotations

import argparse

from .api import serve
from .bind_conf import backup_named_conf, import_named_conf


def main() -> None:
    parser = argparse.ArgumentParser(description="dwlabbind runner")
    sub = parser.add_subparsers(dest="command", required=True)

    backup = sub.add_parser("backup", help="Backup named.conf and referenced files")
    backup.add_argument("--named-conf", default="/etc/bind/named.conf")
    backup.add_argument("--output", required=True)

    imp = sub.add_parser("import", help="Import named.conf and write dwlabbind.xml")
    imp.add_argument("--named-conf", default="/etc/bind/named.conf")

    api = sub.add_parser("serve-api", help="Serve REST API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)

    args = parser.parse_args()
    if args.command == "backup":
        path = backup_named_conf(args.named_conf, args.output)
        print(path)
        return
    if args.command == "import":
        path = import_named_conf(args.named_conf)
        print(path)
        return
    if args.command == "serve-api":
        serve(host=args.host, port=args.port)
        return


if __name__ == "__main__":
    main()
