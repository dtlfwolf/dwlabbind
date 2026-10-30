"""Shared forwarding-zone options for both CLI entry points."""

from .bind_conf import BindOperationError


def add_zone_type_options(parser):
    parser.add_argument("--type", choices=("primary", "forward"), default="primary", dest="zone_type")
    parser.add_argument("--forwarder", action="append", default=[], metavar="IP", help="Upstream IPv4/IPv6 address; repeat for multiple servers")
    parser.add_argument("--forward-mode", choices=("only", "first"), default=None, help="Forwarding policy (default: only)")


def validate_zone_type_options(args):
    if args.zone_type == "primary":
        invalid = args.forwarder or args.forward_mode is not None
        message = "--forwarder and --forward-mode require --type forward."
    else:
        invalid = any((args.dns_server is not None, args.base_hostname is not None,
                       args.yaml is not None, args.xml is not None,
                       args.no_allow_recursion, args.no_allow_update))
        message = ("--type forward does not accept --dns-server, --base-hostname, "
                   "--yaml, --xml, --no-allow-recursion, or --no-allow-update.")
        if not invalid and (not args.domain_name or not args.forwarder):
            raise BindOperationError("MISSING_ZONE_CREATE_INPUT", "Forward zones require --domain-name and at least one --forwarder.")
    if invalid:
        raise BindOperationError("INVALID_ZONE_CREATE_OPTIONS", message)
