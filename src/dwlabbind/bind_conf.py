"""Core BIND configuration containers (skeleton)."""

from __future__ import annotations

from typing import Dict, List, Optional
import sys
import os
import re
import tarfile
import ipaddress
import base64
from datetime import datetime
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import logging
from dwlabbasicpy import dwlabLogger
from dwlabbasicpy import dwlabSettings
dwlabLogger.setup_logging()
logger=logging.getLogger(__name__)
__PACKAGE_NAME__ = "bind_conf"

PACKAGE_MANAGED_ZONE_NAMES = {
    ".",
    "localhost",
    "127.in-addr.arpa",
    "0.in-addr.arpa",
    "255.in-addr.arpa",
}

PACKAGE_MANAGED_CONFIG_BASENAMES = {
    "named.conf.default-zones",
    "bind.keys",
}

PACKAGE_MANAGED_ZONE_BASENAMES = {
    "root.hints",
    "db.local",
    "db.127",
    "db.0",
    "db.255",
}


class BindOperationError(RuntimeError):
    def __init__(self, code: str, message: str, hint: Optional[str] = None, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.hint = hint
        self.status = status


def _statement_class_for_name(name: str):
    function_name = sys._getframe().f_code.co_name
    function_name=__PACKAGE_NAME__+"."+function_name
    logger.debug("Entering function "+str(function_name))

    safe = re.sub(r"[^0-9A-Za-z_]+", "_", name).strip("_")
    if not safe:
        logger.error(f"Invalid statement name '{name}'")
        raise AttributeError(f"Invalid statement name '{name}'")
    class_name = "".join(part.capitalize() for part in safe.split("_"))
    stmt_cls = globals().get(class_name)
    return stmt_cls
    

def _extract_statement_body(text: str) -> str:
    function_name = sys._getframe().f_code.co_name
    function_name=__PACKAGE_NAME__+"."+function_name
    logger.debug("Entering function "+str(function_name))

    if "{" in text and "}" in text:
        return text[text.find("{") + 1:text.rfind("}")].strip()
    return text


def _split_statement_texts(body: str) -> list[str]:
    function_name = sys._getframe().f_code.co_name
    function_name=__PACKAGE_NAME__+"."+function_name
    logger.debug("Entering function "+str(function_name))

    parts = []
    buf = []
    depth = 0
    in_quote = False
    escape = False
    for ch in body:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
            continue
        if not in_quote:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
            elif ch == ";" and depth == 0:
                chunk = "".join(buf).strip()
                if chunk:
                    parts.append(chunk)
                buf = []
                continue
        buf.append(ch)
    trailing = "".join(buf).strip()
    if trailing:
        parts.append(trailing)
    return parts


def _find_outer_block_start(text: str) -> int:
    function_name = sys._getframe().f_code.co_name
    function_name=__PACKAGE_NAME__+"."+function_name
    logger.debug("Entering function "+str(function_name))

    in_quote = False
    escape = False
    for idx, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == "{" and not in_quote:
            logger.debug("Leaving function "+str(function_name))
            return idx
    logger.debug("Leaving function "+str(function_name))
    return -1


def _collapse_singletons(value: object) -> object:
    if isinstance(value, list):
        mapped = [_collapse_singletons(item) for item in value]
        if len(mapped) == 1:
            return mapped[0]
        return mapped
    if isinstance(value, dict):
        return {k: _collapse_singletons(v) for k, v in value.items()}
    return value


class Statement:
    ALLOWED_STATEMENTS: List[str] = []

    def __init__(
        self,
        value: Optional[str] = None,
        statements: Optional[List[object]] = None,   
    ) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.value = value
        self._statements=statements or []

        logger.debug("Leaving function "+str(function_name))

    def set_value(self, value: Optional[str]) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.value = value

        logger.debug("Leaving function "+str(function_name))
    def grammar_check(self, text: str) -> bool:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        # Default: accept; subclasses can override with stricter validation.
        logger.debug("Leaving function "+str(function_name))
        return True
    @classmethod
    def allowed_statements(cls) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name="Statement"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Leaving function "+str(function_name))
        return list(cls.ALLOWED_STATEMENTS)

    def _statement_name(self, statement: object) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if isinstance(statement, str):
            logger.debug("Leaving function "+str(function_name))
            return statement
        name = getattr(statement, "statement_name", None)
        if not name:
            raise ValueError("Unknown statement object: missing statement_name")
        logger.debug("Leaving function "+str(function_name))
        return str(name)

    def _ensure_allowed(self, name: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if name not in self.ALLOWED_STATEMENTS:
            raise ValueError(f"Statement '{name}' not allowed for {self.__class__.__name__}")

        logger.debug("Leaving function "+str(function_name))
    def insert_statement(self, statement: object) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        self._statements.append(statement)

        logger.debug("Leaving function "+str(function_name))
    def update_statement(self, statement: object, index: int = 0) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        if index < 0 or index >= len(self._statements):
            raise IndexError("statement index out of range")
        self._statements[index] = statement

        logger.debug("Leaving function "+str(function_name))
    def delete_statement(self, statement: object, index: int = 0) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        if not self._statements:
            logger.debug("Leaving function "+str(function_name))
            return
        if index < 0 or index >= len(self._statements):
            raise IndexError("statement index out of range")
        self._statements.pop(index)

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="Statement"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        logger.debug("Receive text: " + text)
        cleaned = (text or "").strip()
        allowed = cls.allowed_statements()
        statements = []
        if allowed:
            body = _extract_statement_body(cleaned)
            scanner=BindStatementScanner(
                allowed=allowed,
                cleaned=body
            )
            statements = scanner.statements

        value = cleaned
        if hasattr(cls, "statement_name") and value.startswith(cls.statement_name):
            value = value[len(cls.statement_name):].strip()
        # Only trim to header for true block-style statements.
        # For statements with no allowed sub-statements, keep full trailing text as value.
        if allowed:
            block_start = _find_outer_block_start(value)
            if block_start >= 0:
                value = value[:block_start].strip()
        if value.endswith(";"):
            value = value[:-1].strip()
        if value == "":
            value = None

        if not cls().grammar_check(cleaned):
            logger.error(f"Grammar check failed for statement: {cleaned}")
        logger.debug("Leaving function "+str(function_name))
        return cls(value=value, statements=statements)

    def to_dict(self) -> dict:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        payload = {
            "statement": getattr(self, "statement_name", self.__class__.__name__.lower()),
        }
        if self.value is not None:
            payload["value"] = self.value
        if self._statements:
            nested: Dict[str, List[dict]] = {}
            for item in self._statements:
                if hasattr(item, "to_dict"):
                    item_payload = item.to_dict()
                    item_name = item_payload.get(
                        "statement",
                        getattr(item, "statement_name", item.__class__.__name__),
                    )
                    nested.setdefault(str(item_name), []).append(item_payload)
                else:
                    nested.setdefault("raw", []).append({"raw": str(item)})
            payload["statements"] = _collapse_singletons(nested)
        logger.debug("Leaving function "+str(function_name))
        return payload

    def toText(self, indent: int = 0, indent_step: int = 4) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        statement_name = getattr(self, "statement_name", self.__class__.__name__.lower())
        pad = " " * max(0, indent)
        value = (self.value or "").strip() if self.value is not None else ""
        children = getattr(self, "_statements", None) or []

        header = statement_name
        if value:
            header = f"{header} {value}"

        if not children:
            logger.debug("Leaving function "+str(function_name))
            return f"{pad}{header};"

        child_lines: List[str] = []
        for child in children:
            if hasattr(child, "toText"):
                child_lines.append(child.toText(indent=indent + indent_step, indent_step=indent_step))
            else:
                child_lines.append(" " * (indent + indent_step) + str(child).strip())

        rendered = f"{pad}{header} {{\n" + "\n".join(child_lines) + f"\n{pad}}};"
        logger.debug("Leaving function "+str(function_name))
        return rendered

    @classmethod
    def from_dict(cls, data: dict) -> "Statement":
        function_name = sys._getframe().f_code.co_name
        class_name="Statement"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if isinstance(data, str) or data is None:
            logger.debug("Leaving function "+str(function_name))
            return cls(value=data)
        logger.debug("Leaving function "+str(function_name))
        return cls(
            value=data.get("value"),
            statements=data.get("statements") if isinstance(data.get("statements"), list) else None,
        )

class Acl(Statement):
    statement_name = "acl"
    xml_tag = "acl"
class Algorithm(Statement):
    statement_name = "algorithm"
    xml_tag = "algorithm"
class AllPerSecond(Statement):
    statement_name = "all-per-second"
    xml_tag = "all_per_second"
class AllowNewZones(Statement):
    statement_name = "allow-new-zones"
    xml_tag = "allow_new_zones"
class AllowNotify(Statement):
    statement_name = "allow-notify"
    xml_tag = "allow_notify"
class AllowQuery(Statement):
    statement_name = "allow-query"
    xml_tag = "allow_query"
class AllowQueryCache(Statement):
    statement_name = "allow-query-cache"
    xml_tag = "allow_query_cache"
class AllowQueryCacheOn(Statement):
    statement_name = "allow-query-cache-on"
    xml_tag = "allow_query_cache_on"
class AllowQueryOn(Statement):
    statement_name = "allow-query-on"
    xml_tag = "allow_query_on"
class AllowRecursion(Statement):
    statement_name = "allow-recursion"
    xml_tag = "allow_recursion"
class AllowRecursionOn(Statement):
    statement_name = "allow-recursion-on"
    xml_tag = "allow_recursion_on"
class AllowTransfer(Statement):
    statement_name = "allow-transfer"
    xml_tag = "allow_transfer"
class AllowUpdate(Statement):
    statement_name = "allow-update"
    xml_tag = "allow_update"
    ALLOWED_STATEMENTS = [
        "key",
    ]

class AllowUpdateForwarding(Statement):
    statement_name = "allow-update-forwarding"
    xml_tag = "allow_update_forwarding"
class AlsoNotify(Statement):
    statement_name = "also-notify"
    xml_tag = "also_notify"
class AltTransferSource(Statement):
    statement_name = "alt-transfer-source"
    xml_tag = "alt_transfer_source"
class AltTransferSourceV6(Statement):
    statement_name = "alt-transfer-source-v6"
    xml_tag = "alt_transfer_source_v6"
class AnswerCookie(Statement):
    statement_name = "answer-cookie"
    xml_tag = "answer_cookie"
class AttachCache(Statement):
    statement_name = "attach-cache"
    xml_tag = "attach_cache"
class AuthNxdomain(Statement):
    statement_name = "auth-nxdomain"
    xml_tag = "auth_nxdomain"
class AutoDnssec(Statement):
    statement_name = "auto-dnssec"
    xml_tag = "auto_dnssec"
class AutomaticInterfaceScan(Statement):
    statement_name = "automatic-interface-scan"
    xml_tag = "automatic_interface_scan"
class AvoidV4UdpPorts(Statement):
    statement_name = "avoid-v4-udp-ports"
    xml_tag = "avoid_v4_udp_ports"
class AvoidV6UdpPorts(Statement):
    statement_name = "avoid-v6-udp-ports"
    xml_tag = "avoid_v6_udp_ports"
class BindkeysFile(Statement):
    statement_name = "bindkeys-file"
    xml_tag = "bindkeys_file"
class Blackhole(Statement):
    statement_name = "blackhole"
    xml_tag = "blackhole"
class Bogus(Statement):
    statement_name = "bogus"
    xml_tag = "bogus"
class BreakDnssec(Statement):
    statement_name = "break-dnssec"
    xml_tag = "break_dnssec"
class Buffered(Statement):
    statement_name = "buffered"
    xml_tag = "buffered"
class CaFile(Statement):
    statement_name = "ca-file"
    xml_tag = "ca_file"
class CatalogZones(Statement):
    statement_name = "catalog-zones"
    xml_tag = "catalog_zones"
class Category(Statement):
    statement_name = "category"
    xml_tag = "category"
class CertFile(Statement):
    statement_name = "cert-file"
    xml_tag = "cert_file"
class Channel(Statement):
    statement_name = "channel"
    xml_tag = "channel"
class CheckDupRecords(Statement):
    statement_name = "check-dup-records"
    xml_tag = "check_dup_records"
class CheckIntegrity(Statement):
    statement_name = "check-integrity"
    xml_tag = "check_integrity"
class CheckMx(Statement):
    statement_name = "check-mx"
    xml_tag = "check_mx"
class CheckMxCname(Statement):
    statement_name = "check-mx-cname"
    xml_tag = "check_mx_cname"
class CheckNames(Statement):
    statement_name = "check-names"
    xml_tag = "check_names"
class CheckSibling(Statement):
    statement_name = "check-sibling"
    xml_tag = "check_sibling"
class CheckSpf(Statement):
    statement_name = "check-spf"
    xml_tag = "check_spf"
class CheckSrvCname(Statement):
    statement_name = "check-srv-cname"
    xml_tag = "check_srv_cname"
class CheckWildcard(Statement):
    statement_name = "check-wildcard"
    xml_tag = "check_wildcard"
class Ciphers(Statement):
    statement_name = "ciphers"
    xml_tag = "ciphers"
class Clients(Statement):
    statement_name = "clients"
    xml_tag = "clients"
class ClientsPerQuery(Statement):
    statement_name = "clients-per-query"
    xml_tag = "clients_per_query"
class Controls(Statement):
    statement_name = "controls"
    ALLOWED_STATEMENTS = [
        "inet",
        "unix",
    ]
    xml_tag = "controls"
class CookieAlgorithm(Statement):
    statement_name = "cookie-algorithm"
    xml_tag = "cookie_algorithm"
class CookieSecret(Statement):
    statement_name = "cookie-secret"
    xml_tag = "cookie_secret"
class Coresize(Statement):
    statement_name = "coresize"
    xml_tag = "coresize"
class Database(Statement):
    statement_name = "database"
    xml_tag = "database"
class Datasize(Statement):
    statement_name = "datasize"
    xml_tag = "datasize"
class DelegationOnly(Statement):
    statement_name = "delegation-only"
    xml_tag = "delegation_only"
class DenyAnswerAddresses(Statement):
    statement_name = "deny-answer-addresses"
    xml_tag = "deny_answer_addresses"
class DenyAnswerAliases(Statement):
    statement_name = "deny-answer-aliases"
    xml_tag = "deny_answer_aliases"
class DhparamFile(Statement):
    statement_name = "dhparam-file"
    xml_tag = "dhparam_file"
class Dialup(Statement):
    statement_name = "dialup"
    xml_tag = "dialup"
class Directory(Statement):
    statement_name = "directory"
    xml_tag = "directory"
class DisableAlgorithms(Statement):
    statement_name = "disable-algorithms"
    xml_tag = "disable_algorithms"
class DisableDsDigests(Statement):
    statement_name = "disable-ds-digests"
    xml_tag = "disable_ds_digests"
class DisableEmptyZone(Statement):
    statement_name = "disable-empty-zone"
    xml_tag = "disable_empty_zone"
class Dlz(Statement):
    statement_name = "dlz"
    ALLOWED_STATEMENTS = [
        "database",
    ]

    xml_tag = "dlz"
class Dns64(Statement):
    statement_name = "dns64"
    xml_tag = "dns64"
class Dns64Contact(Statement):
    statement_name = "dns64-contact"
    xml_tag = "dns64_contact"
class Dns64Server(Statement):
    statement_name = "dns64-server"
    xml_tag = "dns64_server"
class DnskeySigValidity(Statement):
    statement_name = "dnskey-sig-validity"
    xml_tag = "dnskey_sig_validity"
class DnskeyTtl(Statement):
    statement_name = "dnskey-ttl"
    xml_tag = "dnskey_ttl"
class DnsrpsEnable(Statement):
    statement_name = "dnsrps-enable"
    xml_tag = "dnsrps_enable"
class DnsrpsOptions(Statement):
    statement_name = "dnsrps-options"
    xml_tag = "dnsrps_options"
class DnssecAcceptExpired(Statement):
    statement_name = "dnssec-accept-expired"
    xml_tag = "dnssec_accept_expired"
class DnssecDnskeyKskonly(Statement):
    statement_name = "dnssec-dnskey-kskonly"
    xml_tag = "dnssec_dnskey_kskonly"
class DnssecLoadkeysInterval(Statement):
    statement_name = "dnssec-loadkeys-interval"
    xml_tag = "dnssec_loadkeys_interval"
class DnssecMustBeSecure(Statement):
    statement_name = "dnssec-must-be-secure"
    xml_tag = "dnssec_must_be_secure"
class DnssecPolicy(Statement):
    statement_name = "dnssec-policy"
    ALLOWED_STATEMENTS = [
        "dnskey-ttl",
        "keys",
        "max-zone-ttl",
        "nsec3param",
        "parent-ds-ttl",
        "parent-propagation-delay",
        "publish-safety",
        "purge-keys",
        "retire-safety",
        "signatures-refresh",
        "signatures-validity",
        "signatures-validity-dnskey",
        "zone-propagation-delay",
    ]

    xml_tag = "dnssec_policy"
class DnssecSecureToInsecure(Statement):
    statement_name = "dnssec-secure-to-insecure"
    xml_tag = "dnssec_secure_to_insecure"
class DnssecUpdateMode(Statement):
    statement_name = "dnssec-update-mode"
    xml_tag = "dnssec_update_mode"
class DnssecValidation(Statement):
    statement_name = "dnssec-validation"
    xml_tag = "dnssec_validation"
class Dnstap(Statement):
    statement_name = "dnstap"
    xml_tag = "dnstap"
class DnstapIdentity(Statement):
    statement_name = "dnstap-identity"
    xml_tag = "dnstap_identity"
class DnstapOutput(Statement):
    statement_name = "dnstap-output"
    xml_tag = "dnstap_output"
class DnstapVersion(Statement):
    statement_name = "dnstap-version"
    xml_tag = "dnstap_version"
class Dscp(Statement):
    statement_name = "dscp"
    xml_tag = "dscp"
class DualStackServers(Statement):
    statement_name = "dual-stack-servers"
    xml_tag = "dual_stack_servers"
class DumpFile(Statement):
    statement_name = "dump-file"
    xml_tag = "dump_file"
class Dyndb(Statement):
    statement_name = "dyndb"
    xml_tag = "dyndb"
class Edns(Statement):
    statement_name = "edns"
    xml_tag = "edns"
class EdnsUdpSize(Statement):
    statement_name = "edns-udp-size"
    xml_tag = "edns_udp_size"
class EdnsVersion(Statement):
    statement_name = "edns-version"
    xml_tag = "edns_version"
class EmptyContact(Statement):
    statement_name = "empty-contact"
    xml_tag = "empty_contact"
class EmptyServer(Statement):
    statement_name = "empty-server"
    xml_tag = "empty_server"
class EmptyZonesEnable(Statement):
    statement_name = "empty-zones-enable"
    xml_tag = "empty_zones_enable"
class Endpoints(Statement):
    statement_name = "endpoints"
    xml_tag = "endpoints"
class ErrorsPerSecond(Statement):
    statement_name = "errors-per-second"
    xml_tag = "errors_per_second"
class Exclude(Statement):
    statement_name = "exclude"
    xml_tag = "exclude"
class ExemptClients(Statement):
    statement_name = "exempt-clients"
    xml_tag = "exempt_clients"
class FetchQuotaParams(Statement):
    statement_name = "fetch-quota-params"
    xml_tag = "fetch_quota_params"
class FetchesPerServer(Statement):
    statement_name = "fetches-per-server"
    xml_tag = "fetches_per_server"
class FetchesPerZone(Statement):
    statement_name = "fetches-per-zone"
    xml_tag = "fetches_per_zone"
class File(Statement):
    statement_name = "file"
    xml_tag = "file"
class Files(Statement):
    statement_name = "files"
    xml_tag = "files"
class FlushZonesOnShutdown(Statement):
    statement_name = "flush-zones-on-shutdown"
    xml_tag = "flush_zones_on_shutdown"
class Forward(Statement):
    statement_name = "forward"
    xml_tag = "forward"
class Forwarders(Statement):
    statement_name = "forwarders"
    xml_tag = "forwarders"
class FstrmSetBufferHint(Statement):
    statement_name = "fstrm-set-buffer-hint"
    xml_tag = "fstrm_set_buffer_hint"
class FstrmSetFlushTimeout(Statement):
    statement_name = "fstrm-set-flush-timeout"
    xml_tag = "fstrm_set_flush_timeout"
class FstrmSetInputQueueSize(Statement):
    statement_name = "fstrm-set-input-queue-size"
    xml_tag = "fstrm_set_input_queue_size"
class FstrmSetOutputNotifyThreshold(Statement):
    statement_name = "fstrm-set-output-notify-threshold"
    xml_tag = "fstrm_set_output_notify_threshold"
class FstrmSetOutputQueueModel(Statement):
    statement_name = "fstrm-set-output-queue-model"
    xml_tag = "fstrm_set_output_queue_model"
class FstrmSetOutputQueueSize(Statement):
    statement_name = "fstrm-set-output-queue-size"
    xml_tag = "fstrm_set_output_queue_size"
class FstrmSetReopenInterval(Statement):
    statement_name = "fstrm-set-reopen-interval"
    xml_tag = "fstrm_set_reopen_interval"
class GeoipDirectory(Statement):
    statement_name = "geoip-directory"
    xml_tag = "geoip_directory"
class GlueCache(Statement):
    statement_name = "glue-cache"
    xml_tag = "glue_cache"
class HeartbeatInterval(Statement):
    statement_name = "heartbeat-interval"
    xml_tag = "heartbeat_interval"
class Hostname(Statement):
    statement_name = "hostname"
    xml_tag = "hostname"
class Http(Statement):
    statement_name = "http"
    ALLOWED_STATEMENTS = [
        "endpoints",
        "listener-clients",
        "streams-per-connection",
    ]

    xml_tag = "http"
class HttpListenerClients(Statement):
    statement_name = "http-listener-clients"
    xml_tag = "http_listener_clients"
class HttpPort(Statement):
    statement_name = "http-port"
    xml_tag = "http_port"
class HttpStreamsPerConnection(Statement):
    statement_name = "http-streams-per-connection"
    xml_tag = "http_streams_per_connection"
class HttpsPort(Statement):
    statement_name = "https-port"
    xml_tag = "https_port"
class InView(Statement):
    statement_name = "in-view"
    xml_tag = "in_view"
class Inet(Statement):
    statement_name = "inet"
    xml_tag = "inet"
class InlineSigning(Statement):
    statement_name = "inline-signing"
    xml_tag = "inline_signing"
class InterfaceInterval(Statement):
    statement_name = "interface-interval"
    xml_tag = "interface_interval"
class Ipv4PrefixLength(Statement):
    statement_name = "ipv4-prefix-length"
    xml_tag = "ipv4_prefix_length"
class Ipv4onlyContact(Statement):
    statement_name = "ipv4only-contact"
    xml_tag = "ipv4only_contact"
class Ipv4onlyEnable(Statement):
    statement_name = "ipv4only-enable"
    xml_tag = "ipv4only_enable"
class Ipv4onlyServer(Statement):
    statement_name = "ipv4only-server"
    xml_tag = "ipv4only_server"
class Ipv6PrefixLength(Statement):
    statement_name = "ipv6-prefix-length"
    xml_tag = "ipv6_prefix_length"
class IxfrFromDifferences(Statement):
    statement_name = "ixfr-from-differences"
    xml_tag = "ixfr_from_differences"
class Journal(Statement):
    statement_name = "journal"
    xml_tag = "journal"
class KeepResponseOrder(Statement):
    statement_name = "keep-response-order"
    xml_tag = "keep_response_order"
class Key(Statement):
    statement_name = "key"
    ALLOWED_STATEMENTS = [
        "algorithm",
        "secret",
    ]

    xml_tag = "key"
class KeyDirectory(Statement):
    statement_name = "key-directory"
    xml_tag = "key_directory"
class KeyFile(Statement):
    statement_name = "key-file"
    xml_tag = "key_file"
class Keys(Statement):
    statement_name = "keys"
    xml_tag = "keys"
class LameTtl(Statement):
    statement_name = "lame-ttl"
    xml_tag = "lame_ttl"
class ListenOn(Statement):
    statement_name = "listen-on"
    xml_tag = "listen_on"
class ListenOnV6(Statement):
    statement_name = "listen-on-v6"
    xml_tag = "listen_on_v6"
class ListenerClients(Statement):
    statement_name = "listener-clients"
    xml_tag = "listener_clients"
class LmdbMapsize(Statement):
    statement_name = "lmdb-mapsize"
    xml_tag = "lmdb_mapsize"
class LockFile(Statement):
    statement_name = "lock-file"
    xml_tag = "lock_file"
class Logging(Statement):
    statement_name = "logging"
    xml_tag = "logging"
    ALLOWED_STATEMENTS = [
        "category",
        "channel",
    ]
class LogOnly(Statement):
    statement_name = "log-only"
    xml_tag = "log_only"
class ManagedKeys(Statement):
    statement_name = "managed-keys"
    xml_tag = "managed_keys"
class ManagedKeysDirectory(Statement):
    statement_name = "managed-keys-directory"
    xml_tag = "managed_keys_directory"
class Mapped(Statement):
    statement_name = "mapped"
    xml_tag = "mapped"
class MasterfileFormat(Statement):
    statement_name = "masterfile-format"
    xml_tag = "masterfile_format"
class MasterfileStyle(Statement):
    statement_name = "masterfile-style"
    xml_tag = "masterfile_style"
class MatchClients(Statement):
    statement_name = "match-clients"
    xml_tag = "match_clients"
class MatchDestinations(Statement):
    statement_name = "match-destinations"
    xml_tag = "match_destinations"
class MatchMappedAddresses(Statement):
    statement_name = "match-mapped-addresses"
    xml_tag = "match_mapped_addresses"
class MatchRecursiveOnly(Statement):
    statement_name = "match-recursive-only"
    xml_tag = "match_recursive_only"
class MaxCacheSize(Statement):
    statement_name = "max-cache-size"
    xml_tag = "max_cache_size"
class MaxCacheTtl(Statement):
    statement_name = "max-cache-ttl"
    xml_tag = "max_cache_ttl"
class MaxClientsPerQuery(Statement):
    statement_name = "max-clients-per-query"
    xml_tag = "max_clients_per_query"
class MaxIxfrRatio(Statement):
    statement_name = "max-ixfr-ratio"
    xml_tag = "max_ixfr_ratio"
class MaxJournalSize(Statement):
    statement_name = "max-journal-size"
    xml_tag = "max_journal_size"
class MaxNcacheTtl(Statement):
    statement_name = "max-ncache-ttl"
    xml_tag = "max_ncache_ttl"
class MaxRecords(Statement):
    statement_name = "max-records"
    xml_tag = "max_records"
class MaxRecursionDepth(Statement):
    statement_name = "max-recursion-depth"
    xml_tag = "max_recursion_depth"
class MaxRecursionQueries(Statement):
    statement_name = "max-recursion-queries"
    xml_tag = "max_recursion_queries"
class MaxRefreshTime(Statement):
    statement_name = "max-refresh-time"
    xml_tag = "max_refresh_time"
class MaxRetryTime(Statement):
    statement_name = "max-retry-time"
    xml_tag = "max_retry_time"
class MaxRsaExponentSize(Statement):
    statement_name = "max-rsa-exponent-size"
    xml_tag = "max_rsa_exponent_size"
class MaxStaleTtl(Statement):
    statement_name = "max-stale-ttl"
    xml_tag = "max_stale_ttl"
class MaxTableSize(Statement):
    statement_name = "max-table-size"
    xml_tag = "max_table_size"
class MaxTransferIdleIn(Statement):
    statement_name = "max-transfer-idle-in"
    xml_tag = "max_transfer_idle_in"
class MaxTransferIdleOut(Statement):
    statement_name = "max-transfer-idle-out"
    xml_tag = "max_transfer_idle_out"
class MaxTransferTimeIn(Statement):
    statement_name = "max-transfer-time-in"
    xml_tag = "max_transfer_time_in"
class MaxTransferTimeOut(Statement):
    statement_name = "max-transfer-time-out"
    xml_tag = "max_transfer_time_out"
class MaxUdpSize(Statement):
    statement_name = "max-udp-size"
    xml_tag = "max_udp_size"
class MaxZoneTtl(Statement):
    statement_name = "max-zone-ttl"
    xml_tag = "max_zone_ttl"
class Memstatistics(Statement):
    statement_name = "memstatistics"
    xml_tag = "memstatistics"
class MemstatisticsFile(Statement):
    statement_name = "memstatistics-file"
    xml_tag = "memstatistics_file"
class MessageCompression(Statement):
    statement_name = "message-compression"
    xml_tag = "message_compression"
class MinCacheTtl(Statement):
    statement_name = "min-cache-ttl"
    xml_tag = "min_cache_ttl"
class MinNcacheTtl(Statement):
    statement_name = "min-ncache-ttl"
    xml_tag = "min_ncache_ttl"
class MinRefreshTime(Statement):
    statement_name = "min-refresh-time"
    xml_tag = "min_refresh_time"
class MinRetryTime(Statement):
    statement_name = "min-retry-time"
    xml_tag = "min_retry_time"
class MinTableSize(Statement):
    statement_name = "min-table-size"
    xml_tag = "min_table_size"
class MinimalAny(Statement):
    statement_name = "minimal-any"
    xml_tag = "minimal_any"
class MinimalResponses(Statement):
    statement_name = "minimal-responses"
    xml_tag = "minimal_responses"
class MultiMaster(Statement):
    statement_name = "multi-master"
    xml_tag = "multi_master"
class NewZonesDirectory(Statement):
    statement_name = "new-zones-directory"
    xml_tag = "new_zones_directory"
class NoCaseCompress(Statement):
    statement_name = "no-case-compress"
    xml_tag = "no_case_compress"
class NocookieUdpSize(Statement):
    statement_name = "nocookie-udp-size"
    xml_tag = "nocookie_udp_size"
class NodataPerSecond(Statement):
    statement_name = "nodata-per-second"
    xml_tag = "nodata_per_second"
class Notify(Statement):
    statement_name = "notify"
    xml_tag = "notify"
class NotifyDelay(Statement):
    statement_name = "notify-delay"
    xml_tag = "notify_delay"
class NotifyRate(Statement):
    statement_name = "notify-rate"
    xml_tag = "notify_rate"
class NotifySource(Statement):
    statement_name = "notify-source"
    xml_tag = "notify_source"
class NotifySourceV6(Statement):
    statement_name = "notify-source-v6"
    xml_tag = "notify_source_v6"
class NotifyToSoa(Statement):
    statement_name = "notify-to-soa"
    xml_tag = "notify_to_soa"
class Nsec3param(Statement):
    statement_name = "nsec3param"
    xml_tag = "nsec3param"
class NtaLifetime(Statement):
    statement_name = "nta-lifetime"
    xml_tag = "nta_lifetime"
class NtaRecheck(Statement):
    statement_name = "nta-recheck"
    xml_tag = "nta_recheck"
class Null(Statement):
    statement_name = "null"
    xml_tag = "null"
class NxdomainRedirect(Statement):
    statement_name = "nxdomain-redirect"
    xml_tag = "nxdomain_redirect"
class NxdomainsPerSecond(Statement):
    statement_name = "nxdomains-per-second"
    xml_tag = "nxdomains_per_second"
class Options(Statement):
    statement_name = "options"
    xml_tag = "options"
    ALLOWED_STATEMENTS = [
        "allow-new-zones",
        "allow-notify",
        "allow-query",
        "allow-query-cache",
        "allow-query-cache-on",
        "allow-query-on",
        "allow-recursion",
        "allow-recursion-on",
        "allow-transfer",
        "allow-update",
        "allow-update-forwarding",
        "also-notify",
        "alt-transfer-source",
        "alt-transfer-source-v6",
        "answer-cookie",
        "attach-cache",
        "auth-nxdomain",
        "auto-dnssec",
        "automatic-interface-scan",
        "avoid-v4-udp-ports",
        "avoid-v6-udp-ports",
        "bindkeys-file",
        "blackhole",
        "check-dup-records",
        "check-integrity",
        "check-mx",
        "check-mx-cname",
        "check-names",
        "check-sibling",
        "check-spf",
        "check-srv-cname",
        "check-wildcard",
        "clients-per-query",
        "cookie-algorithm",
        "cookie-secret",
        "coresize",
        "datasize",
        "deny-answer-addresses",
        "deny-answer-aliases",
        "dialup",
        "directory",
        "disable-algorithms",
        "disable-ds-digests",
        "disable-empty-zone",
        "dns64",
        "dns64-contact",
        "dnskey-sig-validity",
        "dnsrps-enable",
        "dnsrps-options",
        "dnssec-accept-expired",
        "dnssec-dnskey-kskonly",
        "dnssec-loadkeys-interval",
        "dnssec-must-be-secure",
        "dnssec-policy",
        "dnssec-secure-to-insecure",
        "dnssec-update-mode",
        "dnssec-validation",
        "dnstap",
        "dnstap-identity",
        "dnstap-output",
        "dnstap-version",
        "dscp",
        "dual-stack-servers",
        "dump-file",
        "edns-udp-size",
        "empty-contact",
        "empty-server",
        "empty-zones-enable",
        "fetch-quota-params",
        "fetches-per-server",
        "fetches-per-zone",
        "files",
        "flush-zones-on-shutdown",
        "forward",
        "forwarders",
        "fstrm-set-flush-timeout",
        "fstrm-set-input-queue-size",
        "fstrm-set-output-notify-threshold",
        "fstrm-set-output-queue-model",
        "fstrm-set-output-queue-size",
        "fstrm-set-reopen-interval",
        "geoip-directory",
        "glue-cache",
        "heartbeat-interval",
        "hostname",
        "http-listener-clients",
        "http-port",
        "http-streams-per-connection",
        "https-port",
        "interface-interval",
        "ipv4only-contact",
        "ipv4only-enable",
        "ipv4only-server",
        "ixfr-from-differences",
        "keep-response-order",
        "key-directory",
        "lame-ttl",
        "listen-on",
        "listen-on-v6",
        "lmdb-mapsize",
        "lock-file",
        "managed-keys-directory",
        "masterfile-format",
        "masterfile-style",
        "match-mapped-addresses",
        "max-cache-size",
        "max-cache-ttl",
        "max-clients-per-query",
        "max-ixfr-ratio",
        "max-journal-size",
        "max-ncache-ttl",
        "max-records",
        "max-recursion-depth",
        "max-recursion-queries",
        "max-refresh-time",
        "max-retry-time",
        "max-rsa-exponent-size",
        "max-stale-ttl",
        "max-transfer-idle-in",
        "max-transfer-idle-out",
        "max-transfer-time-in",
        "max-transfer-time-out",
        "max-udp-size",
        "max-zone-ttl",
        "memstatistics",
        "memstatistics-file",
        "message-compression",
        "min-cache-ttl",
        "min-ncache-ttl",
        "min-refresh-time",
        "min-retry-time",
        "minimal-any",
        "minimal-responses",
        "multi-master",
        "new-zones-directory",
        "no-case-compress",
        "nocookie-udp-size",
        "notify",
        "notify-delay",
        "notify-rate",
        "notify-source",
        "notify-source-v6",
        "notify-to-soa",
        "nta-lifetime",
        "nta-recheck",
        "nxdomain-redirect",
        "parental-source",
        "parental-source-v6",
        "pid-file",
        "port",
        "preferred-glue",
        "prefetch",
        "provide-ixfr",
        "qname-minimization",
        "query-source",
        "query-source-v6",
        "querylog",
        "rate-limit",
        "recursing-file",
        "recursion",
        "recursive-clients",
        "request-expire",
        "request-ixfr",
        "request-nsid",
        "require-server-cookie",
        "reserved-sockets",
        "resolver-nonbackoff-tries",
        "resolver-query-timeout",
        "resolver-retry-interval",
        "response-padding",
        "response-policy",
        "reuseport",
        "root-delegation-only",
        "root-key-sentinel",
        "rrset-order",
        "secroots-file",
        "send-cookie",
        "serial-query-rate",
        "serial-update-method",
        "server-id",
        "servfail-ttl",
        "session-keyalg",
        "session-keyfile",
        "session-keyname",
        "sig-signing-nodes",
        "sig-signing-signatures",
        "sig-signing-type",
        "sig-validity-interval",
        "sortlist",
        "stacksize",
        "stale-answer-client-timeout",
        "stale-answer-enable",
        "stale-answer-ttl",
        "stale-cache-enable",
        "stale-refresh-time",
        "startup-notify-rate",
        "statistics-file",
        "synth-from-dnssec",
        "tcp-advertised-timeout",
        "tcp-clients",
        "tcp-idle-timeout",
        "tcp-initial-timeout",
        "tcp-keepalive-timeout",
        "tcp-listen-queue",
        "tcp-receive-buffer",
        "tcp-send-buffer",
        "tkey-dhkey",
        "tkey-domain",
        "tkey-gssapi-credential",
        "tkey-gssapi-keytab",
        "tls-port",
        "transfer-format",
        "transfer-message-size",
        "transfer-source",
        "transfer-source-v6",
        "transfers-in",
        "transfers-out",
        "transfers-per-ns",
        "trust-anchor-telemetry",
        "try-tcp-refresh",
        "udp-receive-buffer",
        "udp-send-buffer",
        "update-check-ksk",
        "update-quota",
        "use-alt-transfer-source",
        "use-v4-udp-ports",
        "use-v6-udp-ports",
        "v6-bias",
        "validate-except",
        "version",
        "zero-no-soa-ttl",
        "zero-no-soa-ttl-cache",
        "zone-statistics",
    ]
class Padding(Statement):
    statement_name = "padding"
    xml_tag = "padding"
class ParentDsTtl(Statement):
    statement_name = "parent-ds-ttl"
    xml_tag = "parent_ds_ttl"
class ParentPropagationDelay(Statement):
    statement_name = "parent-propagation-delay"
    xml_tag = "parent_propagation_delay"
class ParentalAgents(Statement):
    statement_name = "parental-agents"
    xml_tag = "parental_agents"
class ParentalSource(Statement):
    statement_name = "parental-source"
    xml_tag = "parental_source"
class ParentalSourceV6(Statement):
    statement_name = "parental-source-v6"
    xml_tag = "parental_source_v6"
class PidFile(Statement):
    statement_name = "pid-file"
    xml_tag = "pid_file"
class Plugin(Statement):
    statement_name = "plugin"
    xml_tag = "plugin"
class Port(Statement):
    statement_name = "port"
    xml_tag = "port"
class PreferServerCiphers(Statement):
    statement_name = "prefer-server-ciphers"
    xml_tag = "prefer_server_ciphers"
class PreferredGlue(Statement):
    statement_name = "preferred-glue"
    xml_tag = "preferred_glue"
class Prefetch(Statement):
    statement_name = "prefetch"
    xml_tag = "prefetch"
class Primaries(Statement):
    statement_name = "primaries"
    xml_tag = "primaries"
class PrintCategory(Statement):
    statement_name = "print-category"
    xml_tag = "print_category"
class PrintSeverity(Statement):
    statement_name = "print-severity"
    xml_tag = "print_severity"
class PrintTime(Statement):
    statement_name = "print-time"
    xml_tag = "print_time"
class Protocols(Statement):
    statement_name = "protocols"
    xml_tag = "protocols"
class ProvideIxfr(Statement):
    statement_name = "provide-ixfr"
    xml_tag = "provide_ixfr"
class PublishSafety(Statement):
    statement_name = "publish-safety"
    xml_tag = "publish_safety"
class PurgeKeys(Statement):
    statement_name = "purge-keys"
    xml_tag = "purge_keys"
class QnameMinimization(Statement):
    statement_name = "qname-minimization"
    xml_tag = "qname_minimization"
class QpsScale(Statement):
    statement_name = "qps-scale"
    xml_tag = "qps_scale"
class QuerySource(Statement):
    statement_name = "query-source"
    xml_tag = "query_source"
class QuerySourceV6(Statement):
    statement_name = "query-source-v6"
    xml_tag = "query_source_v6"
class Querylog(Statement):
    statement_name = "querylog"
    xml_tag = "querylog"
class RateLimit(Statement):
    statement_name = "rate-limit"
    xml_tag = "rate_limit"
class RecursingFile(Statement):
    statement_name = "recursing-file"
    xml_tag = "recursing_file"
class Recursion(Statement):
    statement_name = "recursion"
    xml_tag = "recursion"
class RecursiveClients(Statement):
    statement_name = "recursive-clients"
    xml_tag = "recursive_clients"
class RecursiveOnly(Statement):
    statement_name = "recursive-only"
    xml_tag = "recursive_only"
class ReferralsPerSecond(Statement):
    statement_name = "referrals-per-second"
    xml_tag = "referrals_per_second"
class RemoteHostname(Statement):
    statement_name = "remote-hostname"
    xml_tag = "remote_hostname"
class RequestExpire(Statement):
    statement_name = "request-expire"
    xml_tag = "request_expire"
class RequestIxfr(Statement):
    statement_name = "request-ixfr"
    xml_tag = "request_ixfr"
class RequestNsid(Statement):
    statement_name = "request-nsid"
    xml_tag = "request_nsid"
class RequireServerCookie(Statement):
    statement_name = "require-server-cookie"
    xml_tag = "require_server_cookie"
class ReservedSockets(Statement):
    statement_name = "reserved-sockets"
    xml_tag = "reserved_sockets"
class ResolverNonbackoffTries(Statement):
    statement_name = "resolver-nonbackoff-tries"
    xml_tag = "resolver_nonbackoff_tries"
class ResolverQueryTimeout(Statement):
    statement_name = "resolver-query-timeout"
    xml_tag = "resolver_query_timeout"
class ResolverRetryInterval(Statement):
    statement_name = "resolver-retry-interval"
    xml_tag = "resolver_retry_interval"
class ResponsePadding(Statement):
    statement_name = "response-padding"
    xml_tag = "response_padding"
class ResponsePolicy(Statement):
    statement_name = "response-policy"
    xml_tag = "response_policy"
class ResponsesPerSecond(Statement):
    statement_name = "responses-per-second"
    xml_tag = "responses_per_second"
class RetireSafety(Statement):
    statement_name = "retire-safety"
    xml_tag = "retire_safety"
class Reuseport(Statement):
    statement_name = "reuseport"
    xml_tag = "reuseport"
class RootDelegationOnly(Statement):
    statement_name = "root-delegation-only"
    xml_tag = "root_delegation_only"
class RootKeySentinel(Statement):
    statement_name = "root-key-sentinel"
    xml_tag = "root_key_sentinel"
class RrsetOrder(Statement):
    statement_name = "rrset-order"
    xml_tag = "rrset_order"
class Search(Statement):
    statement_name = "search"
    xml_tag = "search"
class Secret(Statement):
    statement_name = "secret"
    xml_tag = "secret"
class SecrootsFile(Statement):
    statement_name = "secroots-file"
    xml_tag = "secroots_file"
class SendCookie(Statement):
    statement_name = "send-cookie"
    xml_tag = "send_cookie"
class SerialQueryRate(Statement):
    statement_name = "serial-query-rate"
    xml_tag = "serial_query_rate"
class SerialUpdateMethod(Statement):
    statement_name = "serial-update-method"
    xml_tag = "serial_update_method"
class Server(Statement):
    statement_name = "server"
    ALLOWED_STATEMENTS = [
        "bogus",
        "edns",
        "edns-udp-size",
        "edns-version",
        "keys",
        "max-udp-size",
        "notify-source",
        "notify-source-v6",
        "padding",
        "provide-ixfr",
        "query-source",
        "query-source-v6",
        "request-expire",
        "request-ixfr",
        "request-nsid",
        "send-cookie",
        "tcp-keepalive",
        "tcp-only",
        "transfer-format",
        "transfer-source",
        "transfer-source-v6",
        "transfers",
    ]

    xml_tag = "server"
class ServerAddresses(Statement):
    statement_name = "server-addresses"
    xml_tag = "server_addresses"
class ServerId(Statement):
    statement_name = "server-id"
    xml_tag = "server_id"
class ServerNames(Statement):
    statement_name = "server-names"
    xml_tag = "server_names"
class ServfailTtl(Statement):
    statement_name = "servfail-ttl"
    xml_tag = "servfail_ttl"
class SessionKeyalg(Statement):
    statement_name = "session-keyalg"
    xml_tag = "session_keyalg"
class SessionKeyfile(Statement):
    statement_name = "session-keyfile"
    xml_tag = "session_keyfile"
class SessionKeyname(Statement):
    statement_name = "session-keyname"
    xml_tag = "session_keyname"
class SessionTickets(Statement):
    statement_name = "session-tickets"
    xml_tag = "session_tickets"
class Severity(Statement):
    statement_name = "severity"
    xml_tag = "severity"
class SigSigningNodes(Statement):
    statement_name = "sig-signing-nodes"
    xml_tag = "sig_signing_nodes"
class SigSigningSignatures(Statement):
    statement_name = "sig-signing-signatures"
    xml_tag = "sig_signing_signatures"
class SigSigningType(Statement):
    statement_name = "sig-signing-type"
    xml_tag = "sig_signing_type"
class SigValidityInterval(Statement):
    statement_name = "sig-validity-interval"
    xml_tag = "sig_validity_interval"
class SignaturesRefresh(Statement):
    statement_name = "signatures-refresh"
    xml_tag = "signatures_refresh"
class SignaturesValidity(Statement):
    statement_name = "signatures-validity"
    xml_tag = "signatures_validity"
class SignaturesValidityDnskey(Statement):
    statement_name = "signatures-validity-dnskey"
    xml_tag = "signatures_validity_dnskey"
class Slip(Statement):
    statement_name = "slip"
    xml_tag = "slip"
class Sortlist(Statement):
    statement_name = "sortlist"
    xml_tag = "sortlist"
class Stacksize(Statement):
    statement_name = "stacksize"
    xml_tag = "stacksize"
class StaleAnswerClientTimeout(Statement):
    statement_name = "stale-answer-client-timeout"
    xml_tag = "stale_answer_client_timeout"
class StaleAnswerEnable(Statement):
    statement_name = "stale-answer-enable"
    xml_tag = "stale_answer_enable"
class StaleAnswerTtl(Statement):
    statement_name = "stale-answer-ttl"
    xml_tag = "stale_answer_ttl"
class StaleCacheEnable(Statement):
    statement_name = "stale-cache-enable"
    xml_tag = "stale_cache_enable"
class StaleRefreshTime(Statement):
    statement_name = "stale-refresh-time"
    xml_tag = "stale_refresh_time"
class StartupNotifyRate(Statement):
    statement_name = "startup-notify-rate"
    xml_tag = "startup_notify_rate"
class StatisticsChannels(Statement):
    statement_name = "statistics-channels"
    ALLOWED_STATEMENTS = [
        "inet",
    ]

    xml_tag = "statistics_channels"
class StatisticsFile(Statement):
    statement_name = "statistics-file"
    xml_tag = "statistics_file"
class Stderr(Statement):
    statement_name = "stderr"
    xml_tag = "stderr"
class StreamsPerConnection(Statement):
    statement_name = "streams-per-connection"
    xml_tag = "streams_per_connection"
class Suffix(Statement):
    statement_name = "suffix"
    xml_tag = "suffix"
class SynthFromDnssec(Statement):
    statement_name = "synth-from-dnssec"
    xml_tag = "synth_from_dnssec"
class Syslog(Statement):
    statement_name = "syslog"
    xml_tag = "syslog"
class TcpAdvertisedTimeout(Statement):
    statement_name = "tcp-advertised-timeout"
    xml_tag = "tcp_advertised_timeout"
class TcpClients(Statement):
    statement_name = "tcp-clients"
    xml_tag = "tcp_clients"
class TcpIdleTimeout(Statement):
    statement_name = "tcp-idle-timeout"
    xml_tag = "tcp_idle_timeout"
class TcpInitialTimeout(Statement):
    statement_name = "tcp-initial-timeout"
    xml_tag = "tcp_initial_timeout"
class TcpKeepalive(Statement):
    statement_name = "tcp-keepalive"
    xml_tag = "tcp_keepalive"
class TcpKeepaliveTimeout(Statement):
    statement_name = "tcp-keepalive-timeout"
    xml_tag = "tcp_keepalive_timeout"
class TcpListenQueue(Statement):
    statement_name = "tcp-listen-queue"
    xml_tag = "tcp_listen_queue"
class TcpOnly(Statement):
    statement_name = "tcp-only"
    xml_tag = "tcp_only"
class TcpReceiveBuffer(Statement):
    statement_name = "tcp-receive-buffer"
    xml_tag = "tcp_receive_buffer"
class TcpSendBuffer(Statement):
    statement_name = "tcp-send-buffer"
    xml_tag = "tcp_send_buffer"
class TkeyDhkey(Statement):
    statement_name = "tkey-dhkey"
    xml_tag = "tkey_dhkey"
class TkeyDomain(Statement):
    statement_name = "tkey-domain"
    xml_tag = "tkey_domain"
class TkeyGssapiCredential(Statement):
    statement_name = "tkey-gssapi-credential"
    xml_tag = "tkey_gssapi_credential"
class TkeyGssapiKeytab(Statement):
    statement_name = "tkey-gssapi-keytab"
    xml_tag = "tkey_gssapi_keytab"
class Tls(Statement):
    statement_name = "tls"
    ALLOWED_STATEMENTS = [
        "ca-file",
        "cert-file",
        "ciphers",
        "dhparam-file",
        "key-file",
        "prefer-server-ciphers",
        "protocols",
        "remote-hostname",
        "session-tickets",
    ]

    xml_tag = "tls"
class TlsPort(Statement):
    statement_name = "tls-port"
    xml_tag = "tls_port"
class TransferFormat(Statement):
    statement_name = "transfer-format"
    xml_tag = "transfer_format"
class TransferMessageSize(Statement):
    statement_name = "transfer-message-size"
    xml_tag = "transfer_message_size"
class TransferSource(Statement):
    statement_name = "transfer-source"
    xml_tag = "transfer_source"
class TransferSourceV6(Statement):
    statement_name = "transfer-source-v6"
    xml_tag = "transfer_source_v6"
class Transfers(Statement):
    statement_name = "transfers"
    xml_tag = "transfers"
class TransfersIn(Statement):
    statement_name = "transfers-in"
    xml_tag = "transfers_in"
class TransfersOut(Statement):
    statement_name = "transfers-out"
    xml_tag = "transfers_out"
class TransfersPerNs(Statement):
    statement_name = "transfers-per-ns"
    xml_tag = "transfers_per_ns"
class TrustAnchorTelemetry(Statement):
    statement_name = "trust-anchor-telemetry"
    xml_tag = "trust_anchor_telemetry"
class TrustAnchors(Statement):
    statement_name = "trust-anchors"
    xml_tag = "trust_anchors"
class TrustedKeys(Statement):
    statement_name = "trusted-keys"
    xml_tag = "trusted_keys"
class TryTcpRefresh(Statement):
    statement_name = "try-tcp-refresh"
    xml_tag = "try_tcp_refresh"
class Type(Statement):
    statement_name = "type"
    xml_tag = "type"
class TypeDelegationOnly(Statement):
    statement_name = "type delegation-only"
    xml_tag = "type delegation_only"
class TypeForward(Statement):
    statement_name = "type forward"
    xml_tag = "type forward"
class TypeHint(Statement):
    statement_name = "type hint"
    xml_tag = "type hint"
class TypeMirror(Statement):
    statement_name = "type mirror"
    xml_tag = "type mirror"
class TypePrimary(Statement):
    statement_name = "type primary"
    xml_tag = "type primary"
class TypeRedirect(Statement):
    statement_name = "type redirect"
    xml_tag = "type redirect"
class TypeSecondary(Statement):
    statement_name = "type secondary"
    xml_tag = "type secondary"
class TypeStaticStub(Statement):
    statement_name = "type static-stub"
    xml_tag = "type static_stub"
class TypeStub(Statement):
    statement_name = "type stub"
    xml_tag = "type stub"
class UdpReceiveBuffer(Statement):
    statement_name = "udp-receive-buffer"
    xml_tag = "udp_receive_buffer"
class UdpSendBuffer(Statement):
    statement_name = "udp-send-buffer"
    xml_tag = "udp_send_buffer"
class Unix(Statement):
    statement_name = "unix"
    xml_tag = "unix"
class UpdateCheckKsk(Statement):
    statement_name = "update-check-ksk"
    xml_tag = "update_check_ksk"
class UpdatePolicy(Statement):
    statement_name = "update-policy"
    xml_tag = "update_policy"
class UpdateQuota(Statement):
    statement_name = "update-quota"
    xml_tag = "update_quota"
class UseAltTransferSource(Statement):
    statement_name = "use-alt-transfer-source"
    xml_tag = "use_alt_transfer_source"
class UseV4UdpPorts(Statement):
    statement_name = "use-v4-udp-ports"
    xml_tag = "use_v4_udp_ports"
class UseV6UdpPorts(Statement):
    statement_name = "use-v6-udp-ports"
    xml_tag = "use_v6_udp_ports"
class V6Bias(Statement):
    statement_name = "v6-bias"
    xml_tag = "v6_bias"
class ValidateExcept(Statement):
    statement_name = "validate-except"
    xml_tag = "validate_except"
class Version(Statement):
    statement_name = "version"
    xml_tag = "version"
class View(Statement):
    statement_name = "view"
    ALLOWED_STATEMENTS = [
        "allow-new-zones",
        "allow-notify",
        "allow-query",
        "allow-query-cache",
        "allow-query-cache-on",
        "allow-query-on",
        "allow-recursion",
        "allow-recursion-on",
        "allow-transfer",
        "allow-update",
        "allow-update-forwarding",
        "also-notify",
        "alt-transfer-source",
        "alt-transfer-source-v6",
        "attach-cache",
        "auth-nxdomain",
        "auto-dnssec",
        "check-dup-records",
        "check-integrity",
        "check-mx",
        "check-mx-cname",
        "check-names",
        "check-sibling",
        "check-spf",
        "check-srv-cname",
        "check-wildcard",
        "clients-per-query",
        "deny-answer-addresses",
        "deny-answer-aliases",
        "dialup",
        "disable-algorithms",
        "disable-ds-digests",
        "disable-empty-zone",
        "dns64",
        "dns64-contact",
        "dnskey-sig-validity",
        "dnsrps-enable",
        "dnsrps-options",
        "dnssec-accept-expired",
        "dnssec-dnskey-kskonly",
        "dnssec-loadkeys-interval",
        "dnssec-must-be-secure",
        "dnssec-policy",
        "dnssec-secure-to-insecure",
        "dnssec-update-mode",
        "dnssec-validation",
        "dnstap",
        "dual-stack-servers",
        "edns-udp-size",
        "empty-contact",
        "empty-server",
        "empty-zones-enable",
        "fetch-quota-params",
        "fetches-per-server",
        "fetches-per-zone",
        "forward",
        "forwarders",
        "glue-cache",
        "ipv4only-contact",
        "ipv4only-enable",
        "ipv4only-server",
        "ixfr-from-differences",
        "key",
        "key-directory",
        "lame-ttl",
        "lmdb-mapsize",
        "managed-keys",
        "masterfile-format",
        "masterfile-style",
        "match-clients",
        "match-destinations",
        "match-recursive-only",
        "max-cache-size",
        "max-cache-ttl",
        "max-clients-per-query",
        "max-ixfr-ratio",
        "max-journal-size",
        "max-ncache-ttl",
        "max-records",
        "max-recursion-depth",
        "max-recursion-queries",
        "max-refresh-time",
        "max-retry-time",
        "max-stale-ttl",
        "max-transfer-idle-in",
        "max-transfer-idle-out",
        "max-transfer-time-in",
        "max-transfer-time-out",
        "max-udp-size",
        "max-zone-ttl",
        "message-compression",
        "min-cache-ttl",
        "min-ncache-ttl",
        "min-refresh-time",
        "min-retry-time",
        "minimal-any",
        "minimal-responses",
        "multi-master",
        "new-zones-directory",
        "no-case-compress",
        "nocookie-udp-size",
        "notify",
        "notify-delay",
        "notify-source",
        "notify-source-v6",
        "notify-to-soa",
        "nta-lifetime",
        "nta-recheck",
        "nxdomain-redirect",
        "parental-source",
        "parental-source-v6",
        "preferred-glue",
        "prefetch",
        "provide-ixfr",
        "qname-minimization",
        "query-source",
        "query-source-v6",
        "rate-limit",
        "recursion",
        "request-expire",
        "request-ixfr",
        "request-nsid",
        "require-server-cookie",
        "resolver-nonbackoff-tries",
        "resolver-query-timeout",
        "resolver-retry-interval",
        "response-padding",
        "response-policy",
        "root-delegation-only",
        "root-key-sentinel",
        "rrset-order",
        "send-cookie",
        "serial-update-method",
        "server",
        "servfail-ttl",
        "sig-signing-nodes",
        "sig-signing-signatures",
        "sig-signing-type",
        "sig-validity-interval",
        "sortlist",
        "stale-answer-client-timeout",
        "stale-answer-enable",
        "stale-answer-ttl",
        "stale-cache-enable",
        "stale-refresh-time",
        "synth-from-dnssec",
        "transfer-format",
        "transfer-source",
        "transfer-source-v6",
        "trust-anchor-telemetry",
        "trust-anchors",
        "trusted-keys",
        "try-tcp-refresh",
        "update-check-ksk",
        "use-alt-transfer-source",
        "v6-bias",
        "validate-except",
        "zero-no-soa-ttl",
        "zero-no-soa-ttl-cache",
        "zone",
        "zone-statistics",
    ]

    xml_tag = "view"
class Window(Statement):
    statement_name = "window"
    xml_tag = "window"
class ZeroNoSoaTtl(Statement):
    statement_name = "zero-no-soa-ttl"
    xml_tag = "zero_no_soa_ttl"
class ZeroNoSoaTtlCache(Statement):
    statement_name = "zero-no-soa-ttl-cache"
    xml_tag = "zero_no_soa_ttl_cache"

class Zone (Statement):
    ALLOWED_STATEMENTS: List[str] = []
    statement_name= "zone"
    xml_tag = "zone"

    @classmethod
    def fromText(cls, text: str):
        # If called on a concrete subtype, use base Statement parsing directly.
        if cls is not Zone:
            return Statement.fromText.__func__(cls, text)

        cleaned = (text or "").strip()
        body = _extract_statement_body(cleaned)
        type_match = re.search(r"\btype\s+([A-Za-z-]+)\s*;", body)
        zone_type = type_match.group(1).strip().lower() if type_match else ""
        zone_cls_map = {
            "primary": ZonePrimary,
            "master": ZoneMaster,
            "secondary": ZoneSecondary,
            "slave": ZoneSlave,
            "mirror": ZoneMirror,
            "hint": ZoneHint,
            "stub": ZoneStub,
            "static-stub": ZoneStaticStub,
            "forward": ZoneForward,
            "redirect": ZoneRedirect,
            "delegation-only": ZoneDelegationOnly,
            "in-view": ZoneInView,
        }
        target_cls = zone_cls_map.get(zone_type, Zone)
        if target_cls is Zone:
            return Statement.fromText.__func__(Zone, text)
        return Statement.fromText.__func__(target_cls, text)

class ZonePrimary(Zone):
    zone_type = "primary"
    ALLOWED_STATEMENTS = [
        "type",
        "allow-query",
        "allow-query-on",
        "allow-transfer",
        "allow-update",
        "also-notify",
        "alt-transfer-source",
        "alt-transfer-source-v6",
        "auto-dnssec",
        "check-dup-records",
        "check-integrity",
        "check-mx",
        "check-mx-cname",
        "check-names",
        "check-sibling",
        "check-spf",
        "check-srv-cname",
        "check-wildcard",
        "database",
        "dialup",
        "dlz",
        "dnskey-sig-validity",
        "dnssec-dnskey-kskonly",
        "dnssec-loadkeys-interval",
        "dnssec-policy",
        "dnssec-secure-to-insecure",
        "dnssec-update-mode",
        "file",
        "forward",
        "forwarders",
        "inline-signing",
        "ixfr-from-differences",
        "journal",
        "key-directory",
        "masterfile-format",
        "masterfile-style",
        "max-ixfr-ratio",
        "max-journal-size",
        "max-records",
        "max-transfer-idle-out",
        "max-transfer-time-out",
        "max-zone-ttl",
        "notify",
        "notify-delay",
        "notify-source",
        "notify-source-v6",
        "notify-to-soa",
        "nsec3-test-zone",
        "parental-agents",
        "parental-source",
        "parental-source-v6",
        "serial-update-method",
        "sig-signing-nodes",
        "sig-signing-signatures",
        "sig-signing-type",
        "sig-validity-interval",
        "update-check-ksk",
        "update-policy",
        "zero-no-soa-ttl",
        "zone-statistics",
    ]

class ZoneMaster(Zone):
    zone_type = "master"
    ALLOWED_STATEMENTS = ZonePrimary.ALLOWED_STATEMENTS

class ZoneSecondary(Zone):
    zone_type = "secondary"
    ALLOWED_STATEMENTS = [
        "type",
        "allow-notify",
        "allow-query",
        "allow-query-on",
        "allow-transfer",
        "allow-update-forwarding",
        "also-notify",
        "alt-transfer-source",
        "alt-transfer-source-v6",
        "auto-dnssec",
        "check-names",
        "database",
        "dialup",
        "dlz",
        "dnskey-sig-validity",
        "dnssec-dnskey-kskonly",
        "dnssec-loadkeys-interval",
        "dnssec-policy",
        "dnssec-update-mode",
        "file",
        "forward",
        "forwarders",
        "inline-signing",
        "ixfr-from-differences",
        "journal",
        "key-directory",
        "masterfile-format",
        "masterfile-style",
        "max-ixfr-ratio",
        "max-journal-size",
        "max-records",
        "max-refresh-time",
        "max-retry-time",
        "max-transfer-idle-in",
        "max-transfer-idle-out",
        "max-transfer-time-in",
        "max-transfer-time-out",
        "min-refresh-time",
        "min-retry-time",
        "multi-master",
        "notify",
        "notify-delay",
        "notify-source",
        "notify-source-v6",
        "notify-to-soa",
        "nsec3-test-zone",
        "parental-agents",
        "parental-source",
        "parental-source-v6",
        "primaries",
        "request-expire",
        "request-ixfr",
        "sig-signing-nodes",
        "sig-signing-signatures",
        "sig-signing-type",
        "sig-validity-interval",
        "transfer-source",
        "transfer-source-v6",
        "try-tcp-refresh",
        "update-check-ksk",
        "use-alt-transfer-source",
        "zero-no-soa-ttl",
        "zone-statistics",
    ]

class ZoneSlave(Zone):
    zone_type = "slave"
    ALLOWED_STATEMENTS = ZoneSecondary.ALLOWED_STATEMENTS

class ZoneMirror(Zone):
    zone_type = "mirror"
    ALLOWED_STATEMENTS = [
        "type",
        "allow-notify",
        "allow-query",
        "allow-query-on",
        "allow-transfer",
        "allow-update-forwarding",
        "also-notify",
        "alt-transfer-source",
        "alt-transfer-source-v6",
        "check-names",
        "database",
        "file",
        "ixfr-from-differences",
        "journal",
        "masterfile-format",
        "masterfile-style",
        "max-ixfr-ratio",
        "max-journal-size",
        "max-records",
        "max-refresh-time",
        "max-retry-time",
        "max-transfer-idle-in",
        "max-transfer-idle-out",
        "max-transfer-time-in",
        "max-transfer-time-out",
        "min-refresh-time",
        "min-retry-time",
        "multi-master",
        "notify",
        "notify-delay",
        "notify-source",
        "notify-source-v6",
        "primaries",
        "request-expire",
        "request-ixfr",
        "transfer-source",
        "transfer-source-v6",
        "try-tcp-refresh",
        "use-alt-transfer-source",
        "zero-no-soa-ttl",
        "zone-statistics",
    ]

class ZoneHint(Zone):
    zone_type = "hint"
    ALLOWED_STATEMENTS = [
        "type",
        "check-names",
        "delegation-only",
        "file",
    ]

class ZoneStub(Zone):
    zone_type = "stub"
    ALLOWED_STATEMENTS = [
        "type",
        "allow-query",
        "allow-query-on",
        "check-names",
        "database",
        "delegation-only",
        "dialup",
        "file",
        "forward",
        "forwarders",
        "masterfile-format",
        "masterfile-style",
        "max-records",
        "max-refresh-time",
        "max-retry-time",
        "max-transfer-idle-in",
        "max-transfer-time-in",
        "min-refresh-time",
        "min-retry-time",
        "multi-master",
        "primaries",
        "transfer-source",
        "transfer-source-v6",
        "use-alt-transfer-source",
        "zone-statistics",
    ]

class ZoneStaticStub(Zone):
    zone_type = "static-stub"
    ALLOWED_STATEMENTS = [
        "type",
        "allow-query",
        "allow-query-on",
        "forward",
        "forwarders",
        "max-records",
        "server-addresses",
        "server-names",
        "zone-statistics",
    ]

class ZoneForward(Zone):
    zone_type = "forward"
    ALLOWED_STATEMENTS = [
        "type",
        "delegation-only",
        "forward",
        "forwarders",
    ]

class ZoneRedirect(Zone):
    zone_type = "redirect"
    ALLOWED_STATEMENTS = [
        "type",
        "allow-query",
        "allow-query-on",
        "dlz",
        "file",
        "masterfile-format",
        "masterfile-style",
        "max-records",
        "max-zone-ttl",
        "primaries",
        "zone-statistics",
    ]

class ZoneDelegationOnly(Zone):
    zone_type = "delegation-only"
    ALLOWED_STATEMENTS = [
        "type",
    ]

class ZoneInView(Zone):
    zone_type = "in-view"
    ALLOWED_STATEMENTS = [
        "in-view",
        "forward",
        "forwarders",
    ]

class ZonePropagationDelay(Statement):
    statement_name = "zone-propagation-delay"
    xml_tag = "zone_propagation_delay"

class ZoneStatistics(Statement):
    statement_name = "zone-statistics"
    xml_tag = "zone_statistics"

class ZoneFileStatement:
    statement_name = "raw"
    ALLOWED_STATEMENTS: List[str] = []

    def __init__(self, value: str, statements: Optional[List[object]] = None) -> None:
        self.value = value
        self._statements = statements or []

    @classmethod
    def allowed_statements(cls) -> List[str]:
        return list(cls.ALLOWED_STATEMENTS)

    @classmethod
    def fromText(cls, text: str) -> "ZoneFileStatement":
        cleaned = (text or "").rstrip()
        return cls(value=cleaned)

    def to_dict(self) -> dict:
        payload = {
            "statement": self.statement_name,
            "value": self.value,
        }
        if self._statements:
            payload["statements"] = [
                item.to_dict() if hasattr(item, "to_dict") else {"raw": str(item)}
                for item in self._statements
            ]
        return payload


class ZoneDirectiveOrigin(ZoneFileStatement):
    statement_name = "$ORIGIN"


class ZoneDirectiveTtl(ZoneFileStatement):
    statement_name = "$TTL"

    @classmethod
    def fromText(cls, text: str) -> "ZoneDirectiveTtl":
        cleaned = (text or "").strip()
        value = cleaned
        upper = cleaned.upper()
        if upper.startswith("$TTL"):
            value = cleaned[4:].strip()
        return cls(value=value)


class ZoneDirectiveInclude(ZoneFileStatement):
    statement_name = "$INCLUDE"


class ZoneDirectiveGenerate(ZoneFileStatement):
    statement_name = "$GENERATE"


class ZoneResourceRecord(ZoneFileStatement):
    statement_name = "rr"
    RR_TYPES = {
        "A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME",
        "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO",
        "HIP", "HTTPS", "IPSECKEY", "KEY", "KX", "LOC", "MX", "NAPTR", "NS", "NSEC",
        "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR", "RP", "RRSIG", "SIG", "SMIMEA",
        "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", "TXT",
        "URI", "ZONEMD",
    }
    DNS_CLASSES = {"IN", "CH", "HS", "NONE", "ANY"}

    def __init__(
        self,
        value: str,
        owner: Optional[str] = None,
        ttl: Optional[str] = None,
        dns_class: Optional[str] = None,
        rr_type: Optional[str] = None,
        rdata: Optional[str] = None,
        statements: Optional[List[object]] = None,
    ) -> None:
        super().__init__(value=value, statements=statements)
        self.owner = owner
        self.ttl = ttl
        self.dns_class = dns_class
        self.rr_type = rr_type
        self.rdata = rdata

    @classmethod
    def _is_ttl_token(cls, token: str) -> bool:
        return bool(re.fullmatch(r"[0-9]+[wdhmsWDHMS]*", token))

    @classmethod
    def _tokenize(cls, text: str) -> List[str]:
        return text.replace("(", " ").replace(")", " ").split()

    @classmethod
    def fromText(cls, text: str) -> "ZoneResourceRecord":
        # Keep leading whitespace: it carries "owner omitted" semantics in zone files.
        cleaned = (text or "").rstrip()
        tokens = cls._tokenize(cleaned)
        rr_index = -1
        rr_type = None
        for idx, token in enumerate(tokens):
            upper = token.upper()
            if upper in cls.RR_TYPES:
                rr_index = idx
                rr_type = upper
                break

        if rr_index < 0 or rr_type is None:
            return cls(value=cleaned)

        owner = None
        ttl = None
        dns_class = None
        pre_tokens = tokens[:rr_index]

        # Disambiguate numeric owner labels (common in reverse zones), e.g.
        # "1 IN PTR host.example." where "1" is owner, not TTL.
        if (
            len(pre_tokens) >= 2
            and re.fullmatch(r"[0-9]+", pre_tokens[0] or "")
            and pre_tokens[1].upper() in cls.DNS_CLASSES
        ):
            owner = pre_tokens[0]
            dns_class = pre_tokens[1].upper()
            pre_tokens = pre_tokens[2:]

        for token in pre_tokens:
            upper = token.upper()
            if dns_class is None and upper in cls.DNS_CLASSES:
                dns_class = upper
                continue
            if ttl is None and cls._is_ttl_token(token):
                ttl = token
                continue
            if owner is None:
                owner = token

        rdata_tokens = tokens[rr_index + 1:]
        rdata = " ".join(rdata_tokens) if rdata_tokens else None

        # SOA gets dedicated parsing based on BIND zone-file format.
        if rr_type == "SOA":
            return ZoneResourceRecordSOA.from_components(
                value=cleaned,
                owner=owner,
                ttl=ttl,
                dns_class=dns_class,
                rr_type=rr_type,
                rdata_tokens=rdata_tokens,
            )

        return cls(
            value=cleaned,
            owner=owner,
            ttl=ttl,
            dns_class=dns_class,
            rr_type=rr_type,
            rdata=rdata,
        )

    def to_dict(self) -> dict:
        payload = super().to_dict()
        if self.owner is not None:
            payload["owner"] = self.owner
        if self.ttl is not None:
            payload["ttl"] = self.ttl
        if self.dns_class is not None:
            payload["class"] = self.dns_class
        if self.rr_type is not None:
            payload["rr_type"] = self.rr_type
        if self.rdata is not None:
            payload["rdata"] = self.rdata
        return payload


class ZoneResourceRecordSOA(ZoneResourceRecord):
    statement_name = "soa"

    def __init__(
        self,
        value: str,
        owner: Optional[str] = None,
        ttl: Optional[str] = None,
        dns_class: Optional[str] = None,
        rr_type: Optional[str] = "SOA",
        rdata: Optional[str] = None,
        mname: Optional[str] = None,
        rname: Optional[str] = None,
        serial: Optional[str] = None,
        refresh: Optional[str] = None,
        retry: Optional[str] = None,
        expire: Optional[str] = None,
        minimum: Optional[str] = None,
    ) -> None:
        super().__init__(
            value=value,
            owner=owner,
            ttl=ttl,
            dns_class=dns_class,
            rr_type=rr_type,
            rdata=rdata,
        )
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    @classmethod
    def from_components(
        cls,
        value: str,
        owner: Optional[str],
        ttl: Optional[str],
        dns_class: Optional[str],
        rr_type: str,
        rdata_tokens: List[str],
    ) -> "ZoneResourceRecordSOA":
        mname = rname = serial = refresh = retry = expire = minimum = None
        if len(rdata_tokens) >= 7:
            mname = rdata_tokens[0]
            rname = rdata_tokens[1]
            serial = rdata_tokens[2]
            refresh = rdata_tokens[3]
            retry = rdata_tokens[4]
            expire = rdata_tokens[5]
            minimum = rdata_tokens[6]
        rdata = " ".join(rdata_tokens) if rdata_tokens else None
        return cls(
            value=value,
            owner=owner,
            ttl=ttl,
            dns_class=dns_class,
            rr_type=rr_type,
            rdata=rdata,
            mname=mname,
            rname=rname,
            serial=serial,
            refresh=refresh,
            retry=retry,
            expire=expire,
            minimum=minimum,
        )

    def to_dict(self) -> dict:
        payload = super().to_dict()
        payload.update(
            {
                "mname": self.mname,
                "rname": self.rname,
                "serial": self.serial,
                "refresh": self.refresh,
                "retry": self.retry,
                "expire": self.expire,
                "minimum": self.minimum,
            }
        )
        return payload


class ZoneFileStatementScanner:
    ALLOWED_STATEMENTS = {"$ORIGIN", "$TTL", "$INCLUDE", "$GENERATE", "rr"}
    DIRECTIVE_CLASSES = {
        "$ORIGIN": ZoneDirectiveOrigin,
        "$TTL": ZoneDirectiveTtl,
        "$INCLUDE": ZoneDirectiveInclude,
        "$GENERATE": ZoneDirectiveGenerate,
    }

    def __init__(self, text: str) -> None:
        self._text = text or ""
        self._statements: List[ZoneFileStatement] = []
        for raw in self._scan_statements(self._text):
            stmt = self._statement_from_text(raw)
            if stmt is not None:
                self._statements.append(stmt)

    @property
    def statements(self) -> List[ZoneFileStatement]:
        return self._statements

    def _scan_statements(self, text: str) -> List[str]:
        results: List[str] = []
        current: List[str] = []
        paren_depth = 0
        for line in text.splitlines():
            cleaned_line = self._strip_zone_comment(line).rstrip()
            if not cleaned_line.strip():
                continue
            current.append(cleaned_line)
            paren_depth += cleaned_line.count("(") - cleaned_line.count(")")
            if paren_depth > 0:
                continue
            first = current[0].rstrip()
            rest = [part.strip() for part in current[1:]]
            statement_text = first
            if rest:
                statement_text = statement_text + " " + " ".join(rest)
            current = []
            if statement_text:
                results.append(statement_text)
        if current:
            first = current[0].rstrip()
            rest = [part.strip() for part in current[1:]]
            statement_text = first
            if rest:
                statement_text = statement_text + " " + " ".join(rest)
            if statement_text:
                results.append(statement_text)
        return results

    def _strip_zone_comment(self, line: str) -> str:
        in_quote = False
        escape = False
        out: List[str] = []
        for ch in line:
            if escape:
                out.append(ch)
                escape = False
                continue
            if ch == "\\":
                out.append(ch)
                escape = True
                continue
            if ch == "\"":
                in_quote = not in_quote
                out.append(ch)
                continue
            if ch == ";" and not in_quote:
                break
            out.append(ch)
        return "".join(out)

    def _statement_from_text(self, statement_text: str) -> Optional[ZoneFileStatement]:
        if not statement_text:
            return None
        stripped = statement_text.lstrip()
        if stripped.startswith("$"):
            directive = stripped.split(None, 1)[0].upper()
            if directive not in self.ALLOWED_STATEMENTS:
                return None
            stmt_cls = self.DIRECTIVE_CLASSES.get(directive, ZoneFileStatement)
            return stmt_cls.fromText(stripped)
        if "rr" not in self.ALLOWED_STATEMENTS:
            return None
        return ZoneResourceRecord.fromText(statement_text)

class BindZoneFile:
    NON_RR_ZONE_TYPES = {"forward", "delegation-only", "in-view"}

    def __init__(
        self,
        zone_name: str,
        file_path: str,
        statements: Optional[List[ZoneFileStatement]] = None,
        zone_type: Optional[str] = None,
        ddns_enabled: bool = False,
        externally_managed: bool = False,
    ) -> None:
        self.zone_name = zone_name
        self.file_path = file_path
        self.zone_file_statements = statements or []
        self.zone_type = (zone_type or "").strip().lower()
        self.ddns_enabled = ddns_enabled
        self.externally_managed = externally_managed
        self.fixed_hosts_file_path = f"{self.file_path}.FixedHosts"
        self.fixed_host_statements: List[ZoneFileStatement] = []
        self._fixed_hosts_insert_index: Optional[int] = None
        self._split_fixed_hosts()

    def to_dict(self) -> dict:
        include_origin = self._include_origin()
        include_value = f"\"{self.fixed_hosts_file_path}\""
        if include_origin:
            include_value = f"{include_value} {include_origin}"
        return {
            "zone_name": self.zone_name,
            "file_path": self.file_path,
            "zone_type": self.zone_type,
            "ddns_enabled": self.ddns_enabled,
            "externally_managed": self.externally_managed,
            "statements": [item.to_dict() for item in self.zone_file_statements],
            "fixed_hosts_file_path": self.fixed_hosts_file_path,
            "static_hosts_include": {
                "statement": "$INCLUDE",
                "value": include_value,
                "generated": True,
            },
            "FixedHosts": [item.to_dict() for item in self.fixed_host_statements],
        }

    def set_file_path(self, file_path: str) -> None:
        self.file_path = file_path
        self.fixed_hosts_file_path = f"{self.file_path}.FixedHosts"

    def _is_reverse_zone(self) -> bool:
        name = (self.zone_name or "").strip(".").lower()
        return name.endswith("in-addr.arpa") or name.endswith("ip6.arpa")

    def _include_origin(self) -> str:
        zone = (self.zone_name or "").strip()
        if not zone:
            return ""
        if zone == ".":
            return "."
        return f"{zone.rstrip('.')}."

    def _is_fixed_host_rr(self, statement: ZoneFileStatement) -> bool:
        if not isinstance(statement, ZoneResourceRecord):
            return False
        rr_type = (getattr(statement, "rr_type", None) or "").upper()
        if self._is_reverse_zone():
            return rr_type == "PTR"
        return rr_type in {"A", "AAAA"}

    def _split_fixed_hosts(self) -> None:
        # DDNS-enabled zones keep all RRs in the discovered zone file.
        if self.ddns_enabled:
            return
        # Some zone types do not carry host RRs in a normal zone-file pattern.
        if self.zone_type in self.NON_RR_ZONE_TYPES:
            return

        kept: List[ZoneFileStatement] = []
        fixed: List[ZoneFileStatement] = []
        first_fixed_index: Optional[int] = None
        for idx, stmt in enumerate(self.zone_file_statements):
            if self._is_fixed_host_rr(stmt):
                if first_fixed_index is None:
                    first_fixed_index = idx
                fixed.append(stmt)
            else:
                kept.append(stmt)

        self.zone_file_statements = kept
        self.fixed_host_statements = fixed
        self._fixed_hosts_insert_index = first_fixed_index

    def _serialize_statement(self, statement: ZoneFileStatement) -> str:
        raw_value = (getattr(statement, "value", "") or "")
        if isinstance(statement, ZoneResourceRecord):
            # Preserve leading whitespace for owner-omitted RR lines.
            return raw_value.rstrip()
        value = raw_value.strip()
        if isinstance(statement, ZoneDirectiveTtl):
            if value.upper().startswith("$TTL"):
                return value
            return f"$TTL {value}".strip()
        if isinstance(statement, ZoneDirectiveOrigin):
            if value.upper().startswith("$ORIGIN"):
                return value
            return f"$ORIGIN {value}".strip()
        if isinstance(statement, ZoneDirectiveInclude):
            if value.upper().startswith("$INCLUDE"):
                return value
            return f"$INCLUDE {value}".strip()
        if isinstance(statement, ZoneDirectiveGenerate):
            if value.upper().startswith("$GENERATE"):
                return value
            return f"$GENERATE {value}".strip()
        return value

    def toFile(self, path: Optional[str] = None) -> str:
        output_path = path or self.file_path
        if not output_path:
            raise ValueError("No output path provided for zone file")
        directory = os.path.dirname(output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        lines: List[str] = []
        seen_soa = False
        default_ttl_written = False
        include_inserted = False
        include_line = None
        if self.fixed_host_statements:
            include_line = f'$INCLUDE "{self.fixed_hosts_file_path}"'
            include_origin = self._include_origin()
            if include_origin:
                include_line = f"{include_line} {include_origin}"

        insert_idx: Optional[int] = None
        if include_line is not None:
            soa_idx: Optional[int] = None
            first_host_rr_idx: Optional[int] = None
            for idx, stmt in enumerate(self.zone_file_statements):
                if isinstance(stmt, ZoneResourceRecord):
                    rr_type = (getattr(stmt, "rr_type", None) or "").upper()
                    if rr_type == "SOA" and soa_idx is None:
                        soa_idx = idx
                    if rr_type in {"A", "AAAA", "PTR"} and first_host_rr_idx is None:
                        first_host_rr_idx = idx
            if soa_idx is not None and first_host_rr_idx is not None and first_host_rr_idx > soa_idx:
                insert_idx = first_host_rr_idx
            elif soa_idx is not None:
                insert_idx = soa_idx + 1
            elif first_host_rr_idx is not None:
                insert_idx = first_host_rr_idx
            else:
                insert_idx = len(self.zone_file_statements)

        for idx, statement in enumerate(self.zone_file_statements):
            if (
                include_line is not None
                and not include_inserted
                and insert_idx is not None
                and idx >= insert_idx
            ):
                lines.append(include_line)
                include_inserted = True
            if isinstance(statement, ZoneResourceRecord) and getattr(statement, "rr_type", None) == "SOA":
                seen_soa = True
            if isinstance(statement, ZoneDirectiveTtl) and not seen_soa and not default_ttl_written:
                default_ttl_written = True
            rendered = self._serialize_statement(statement)
            if rendered:
                lines.append(rendered)
        if include_line is not None and not include_inserted:
            lines.append(include_line)

        content = "\n".join(lines)
        if content and not content.endswith("\n"):
            content += "\n"
        with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)

        if self.fixed_host_statements:
            fixed_lines: List[str] = []
            for statement in self.fixed_host_statements:
                rendered = self._serialize_statement(statement)
                if rendered:
                    fixed_lines.append(rendered)
            fixed_content = "\n".join(fixed_lines)
            if fixed_content and not fixed_content.endswith("\n"):
                fixed_content += "\n"
            with open(self.fixed_hosts_file_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(fixed_content)
        return output_path

class BindServer:
    TOP_LEVEL_STATEMENTS = [
        "acl",
        "controls",
        "key",
        "logging",
        "parental-agents",
        "primaries",
        "options",
        "server",
        "statistics-channels",
        "tls",
        "http",
        "trust-anchors",
        "dnssec-policy",
        "managed-keys",
        "trusted-keys",
        "view",
        "zone",
    ]

    def __init__(
        self,
        name: str,
        statements: Optional[Statement] = None,
    ) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.name = name
        self._statements=statements or []
        self.source_path: Optional[str] = None
        self._source_files: List[str] = []
        self._zone_files: List[BindZoneFile] = []
        logger.debug("Leaving function "+str(function_name))

    @classmethod
    def fromConfFile(cls, filename: Optional[str] = None) -> "BindServer":
        function_name = sys._getframe().f_code.co_name
        class_name=cls.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        path = filename or "/etc/bind/named.conf"
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        server = cls(name=path)
        server.source_path = path
        server._parse_named_conf(path)

        logger.debug("Leaving function "+str(function_name))
        return server

    def to_dict(self) -> dict:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        statements_by_name: Dict[str, List[dict]] = {}
        for stmt in self._statements:
            stmt_payload = stmt.to_dict() if hasattr(stmt, "to_dict") else {"raw": str(stmt)}
            stmt_name = stmt_payload.get(
                "statement",
                getattr(stmt, "statement_name", stmt.__class__.__name__),
            )
            statements_by_name.setdefault(str(stmt_name), []).append(stmt_payload)

        payload = {
            "name": self.name,
            "source_path": self.source_path,
            "source_files": list(self._source_files),
            "statements": _collapse_singletons(statements_by_name),
            "zone_files": [zone_file.to_dict() for zone_file in self._zone_files],
        }

        logger.debug("Leaving function "+str(function_name))
        return payload

    def backup(self, output_tar: str) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        if not self.source_path:
            raise ValueError("source_path not set")
        files = self._collect_referenced_files()
        os.makedirs(os.path.dirname(output_tar) or ".", exist_ok=True)
        with tarfile.open(output_tar, "w") as tar:
            for file_path in files:
                if os.path.exists(file_path):
                    tar.add(file_path, arcname=os.path.relpath(file_path, "/"))

        logger.debug("Leaving function "+str(function_name))
        return output_tar

    def _parse_named_conf(self, path: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        base_dir = os.path.dirname(path)
        files = self._collect_config_files(path, base_dir=base_dir)
        self._parse_files(files, base_dir=base_dir)
        self._load_zone_files(base_dir=base_dir)

        logger.debug("Leaving function "+str(function_name))

    def _collect_config_files(self, path: str, base_dir: str) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        files: List[str] = []
        seen: set[str] = set()
        queue: List[str] = [os.path.abspath(path)]
        while queue:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            if not os.path.exists(current):
                continue
            files.append(current)
            try:
                raw = self._read_file(current, seen_files=set())
            except Exception:
                continue
            cleaned = self._strip_comments(raw)
            for include_path in self._extract_includes(cleaned, base_dir):
                if not os.path.isabs(include_path):
                    include_path = os.path.join(base_dir, include_path)
                queue.append(os.path.abspath(include_path))

        logger.debug("Leaving function "+str(function_name))
        return files

    def _parse_files(self, files: List[str], base_dir: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        for path in files:
            logger.debug(f"Handling file: {path}")
            text = self._read_file(path, seen_files=set())
            if path not in self._source_files:
                self._source_files.append(path)
            cleaned = self._strip_comments(text)
            scanner = BindStatementScanner(
                allowed=set(self.TOP_LEVEL_STATEMENTS),
                cleaned=cleaned
            )
            self._statements.extend(scanner.statements)

        logger.debug("Leaving function "+str(function_name))

    def _read_file(self, path: str, seen_files: set[str]) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        real = os.path.abspath(path)
        if real in seen_files:
            logger.debug(f"File {real} has already been handled before")
            fileContent=""
        else:
            seen_files.add(real)
            with open(real, "r", encoding="utf-8") as handle:
                fileContent=handle.read()

        logger.debug("Leaving function "+str(function_name))
        return fileContent

    def _strip_comments(self, text: str) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//.*?$", "", text, flags=re.M)
        text = re.sub(r"#.*?$", "", text, flags=re.M)

        logger.debug("Leaving function "+str(function_name))
        return text

    def _extract_includes(self, text: str, base_dir: str) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        includes = []
        for match in re.finditer(r'include\s+"([^"]+)"\s*;', text, re.I):
            include_path = match.group(1)
            if not os.path.isabs(include_path):
                include_path = os.path.join(base_dir, include_path)
            includes.append(include_path)

        logger.debug("Leaving function "+str(function_name))
        return includes

    def _collect_referenced_files(self) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        files: List[str] = []
        if self.source_path:
            files.append(self.source_path)
        for path in self._source_files:
            if path not in files:
                files.append(path)
        for zone_file in self._zone_files:
            if zone_file.file_path not in files:
                files.append(zone_file.file_path)
        
        logger.debug("Leaving function "+str(function_name))
        return files

    def _load_zone_files(self, base_dir: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self._zone_files = []
        seen_paths: set[str] = set()
        for stmt in self._statements:
            if getattr(stmt, "statement_name", "") != "zone":
                continue
            zone_name = self._normalize_zone_name(getattr(stmt, "value", None))
            zone_type = self._extract_zone_type(stmt)
            ddns_enabled = self._zone_has_ddns_updates(stmt)
            zone_path = self._extract_zone_file_path(stmt)
            if not zone_path:
                continue
            if not os.path.isabs(zone_path):
                zone_path = os.path.abspath(os.path.join(base_dir, zone_path))
            if zone_path in seen_paths:
                continue
            seen_paths.add(zone_path)
            if not os.path.exists(zone_path):
                logger.warning(f"Zone file not found: {zone_path}")
                continue
            try:
                raw = self._read_file(zone_path, seen_files=set())
            except Exception:
                logger.warning(f"Failed to read zone file: {zone_path}")
                continue
            statements = self._parse_zone_file_statements(raw)
            externally_managed = self._is_package_managed_zone(zone_name, zone_path)
            self._zone_files.append(
                BindZoneFile(
                    zone_name=zone_name,
                    file_path=zone_path,
                    statements=statements,
                    zone_type=zone_type,
                    ddns_enabled=ddns_enabled,
                    externally_managed=externally_managed,
                )
            )

        logger.debug("Leaving function "+str(function_name))

    def _extract_zone_file_path(self, zone_stmt: Statement) -> Optional[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        for child in getattr(zone_stmt, "_statements", []):
            if getattr(child, "statement_name", "") != "file":
                continue
            value = getattr(child, "value", None)
            if not value:
                continue
            cleaned = str(value).strip()
            if cleaned.endswith(";"):
                cleaned = cleaned[:-1].strip()
            if cleaned.startswith('"') and cleaned.endswith('"') and len(cleaned) >= 2:
                cleaned = cleaned[1:-1]
            logger.debug("Leaving function "+str(function_name))
            return cleaned
        logger.debug("Leaving function "+str(function_name))
        return None

    def _normalize_zone_name(self, value: Optional[str]) -> str:
        if value is None:
            return ""
        cleaned = str(value).strip()
        if cleaned.startswith('"') and cleaned.endswith('"') and len(cleaned) >= 2:
            cleaned = cleaned[1:-1]
        return cleaned

    def _extract_zone_type(self, zone_stmt: Statement) -> str:
        for child in getattr(zone_stmt, "_statements", []):
            if getattr(child, "statement_name", "") != "type":
                continue
            value = (getattr(child, "value", None) or "").strip().lower()
            if value.endswith(";"):
                value = value[:-1].strip()
            return value
        return ""

    def _zone_has_ddns_updates(self, zone_stmt: Statement) -> bool:
        for child in getattr(zone_stmt, "_statements", []):
            child_name = getattr(child, "statement_name", "")
            if child_name in {"allow-update", "update-policy"}:
                return True
        return False

    def _parse_zone_file_statements(self, text: str) -> List[ZoneFileStatement]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        scanner = ZoneFileStatementScanner(text=text)
        results = scanner.statements

        logger.debug("Leaving function "+str(function_name))
        return results

    def _normalize_name_for_filename(self, value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip())
        cleaned = cleaned.strip("._")
        return cleaned or "unnamed"

    def _extract_allow_update_key_names(self, zone_stmt: Statement) -> List[str]:
        keys: List[str] = []
        for child in getattr(zone_stmt, "_statements", []):
            if getattr(child, "statement_name", "") != "allow-update":
                continue
            for nested in getattr(child, "_statements", []):
                if getattr(nested, "statement_name", "") != "key":
                    continue
                value = (getattr(nested, "value", None) or "").strip()
                if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                    value = value[1:-1]
                if value:
                    keys.append(value)
        return keys

    def _set_zone_file_statement_path(self, zone_stmt: Statement, new_path: str) -> None:
        for child in getattr(zone_stmt, "_statements", []):
            if getattr(child, "statement_name", "") == "file":
                child.value = f"\"{new_path}\""
                return

    def _find_zone_file_object(self, zone_name: str) -> Optional[BindZoneFile]:
        for zone_file in self._zone_files:
            if self._normalize_zone_name(zone_file.zone_name) == zone_name:
                return zone_file
        return None

    def _normalize_fqdn(self, fqdn: str) -> str:
        cleaned = (fqdn or "").strip().rstrip(".").lower()
        if not cleaned:
            raise BindOperationError("INVALID_FQDN", "FQDN is required.", "Provide a non-empty hostname, e.g. host.example.com")
        labels = cleaned.split(".")
        label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        for label in labels:
            if not label_re.fullmatch(label):
                raise BindOperationError(
                    "INVALID_FQDN",
                    f"Invalid FQDN '{fqdn}'.",
                    "Use DNS labels with letters, digits, and '-' only.",
                )
        return cleaned

    def _normalized_zone_name(self, zone_name: str) -> str:
        return (zone_name or "").strip().strip(".").lower()

    def _zone_name_fits(self, record_name: str, zone_name: str) -> bool:
        if zone_name == "":
            return True
        return record_name == zone_name or record_name.endswith("." + zone_name)

    def _zone_name_score(self, zone_name: str) -> int:
        if not zone_name:
            return 0
        return len(zone_name.split("."))

    def _best_matching_zone(self, record_name: str, reverse: bool) -> Optional[BindZoneFile]:
        best: Optional[BindZoneFile] = None
        best_score = -1
        for zone in self._zone_files:
            if zone._is_reverse_zone() != reverse:
                continue
            if zone.zone_type in zone.NON_RR_ZONE_TYPES:
                continue
            normalized_zone = self._normalized_zone_name(zone.zone_name)
            if not self._zone_name_fits(record_name, normalized_zone):
                continue
            score = self._zone_name_score(normalized_zone)
            if score > best_score:
                best = zone
                best_score = score
        return best

    def _owner_for_zone(self, record_name: str, zone_name: str) -> str:
        if zone_name == "":
            return record_name + "."
        if record_name == zone_name:
            return "@"
        suffix = "." + zone_name
        if record_name.endswith(suffix):
            relative = record_name[: -len(suffix)]
            return relative or "@"
        raise BindOperationError(
            "ZONE_MISMATCH",
            f"Record '{record_name}' is outside zone '{zone_name}'.",
        )

    def _rr_owner_fqdn(self, owner: Optional[str], zone_name: str) -> Optional[str]:
        if owner is None:
            return None
        text = owner.strip()
        if not text:
            return None
        zone_abs = self._normalized_zone_name(zone_name)
        if text == "@":
            return zone_abs
        if text.endswith("."):
            return text.rstrip(".").lower()
        if zone_abs:
            return f"{text}.{zone_abs}".lower()
        return text.lower()

    def _rr_target_normalized(self, rr_type: str, rdata: Optional[str]) -> str:
        text = (rdata or "").strip()
        if not text:
            return ""
        first_token = text.split()[0]
        if rr_type in {"PTR"}:
            return first_token.rstrip(".").lower()
        return first_token.lower()

    def _record_exists(
        self,
        zone_file: BindZoneFile,
        owner_fqdn: str,
        rr_type: str,
        target_normalized: str,
    ) -> bool:
        for source in (zone_file.zone_file_statements, zone_file.fixed_host_statements):
            for stmt in source:
                if not isinstance(stmt, ZoneResourceRecord):
                    continue
                current_type = (stmt.rr_type or "").upper()
                if current_type != rr_type:
                    continue
                current_owner = self._rr_owner_fqdn(stmt.owner, zone_file.zone_name)
                if (current_owner or "") != owner_fqdn:
                    continue
                current_target = self._rr_target_normalized(current_type, stmt.rdata)
                if current_target == target_normalized:
                    return True
        return False

    def _collect_host_conflicts(
        self,
        zone_file: BindZoneFile,
        fqdn_abs: str,
        ip_text: str,
        reverse_name: str,
    ) -> List[dict]:
        conflicts: List[dict] = []
        ip_norm = ip_text.lower()
        for attr_name in ("zone_file_statements", "fixed_host_statements"):
            source = getattr(zone_file, attr_name)
            for idx, stmt in enumerate(source):
                if not isinstance(stmt, ZoneResourceRecord):
                    continue
                rr_type = (stmt.rr_type or "").upper()
                if rr_type not in {"A", "AAAA", "PTR"}:
                    continue
                owner_fqdn = self._rr_owner_fqdn(stmt.owner, zone_file.zone_name) or ""
                target_norm = self._rr_target_normalized(rr_type, stmt.rdata)
                if rr_type in {"A", "AAAA"}:
                    if owner_fqdn == fqdn_abs or target_norm == ip_norm:
                        conflicts.append(
                            {
                                "zone_id": id(zone_file),
                                "zone": zone_file.zone_name,
                                "rr_type": rr_type,
                                "owner_fqdn": owner_fqdn,
                                "target": target_norm,
                                "value": stmt.value,
                                "source_attr": attr_name,
                                "source_file": (
                                    zone_file.file_path
                                    if attr_name == "zone_file_statements"
                                    else zone_file.fixed_hosts_file_path
                                ),
                                "index": idx,
                            }
                        )
                elif rr_type == "PTR":
                    if owner_fqdn == reverse_name or target_norm == fqdn_abs:
                        conflicts.append(
                            {
                                "zone_id": id(zone_file),
                                "zone": zone_file.zone_name,
                                "rr_type": rr_type,
                                "owner_fqdn": owner_fqdn,
                                "target": target_norm,
                                "value": stmt.value,
                                "source_attr": attr_name,
                                "source_file": (
                                    zone_file.file_path
                                    if attr_name == "zone_file_statements"
                                    else zone_file.fixed_hosts_file_path
                                ),
                                "index": idx,
                            }
                        )
        return conflicts

    def _remove_conflicts(self, zone_file: BindZoneFile, conflicts: List[dict]) -> None:
        per_source: Dict[str, List[int]] = {}
        for item in conflicts:
            per_source.setdefault(item["source_attr"], []).append(item["index"])
        for attr_name, indexes in per_source.items():
            source = getattr(zone_file, attr_name)
            for idx in sorted(set(indexes), reverse=True):
                if 0 <= idx < len(source):
                    source.pop(idx)

    def _validate_zone_file_record(self, zone_file: BindZoneFile) -> None:
        check_zone_types = {"master", "primary", "slave", "secondary", "mirror", "stub", "static-stub", "redirect"}
        zone_type = (zone_file.zone_type or "").lower()
        if zone_type and zone_type not in check_zone_types:
            return
        if not os.path.exists(zone_file.file_path):
            raise BindOperationError(
                "ZONE_FILE_MISSING",
                f"Zone file not found: {zone_file.file_path}",
                status=404,
            )
        named_checkzone = shutil.which("named-checkzone")
        if not named_checkzone:
            raise BindOperationError(
                "VALIDATION_TOOL_MISSING",
                "named-checkzone not found on this system.",
                "Install bind9utils (or distribution equivalent) and retry.",
                status=500,
            )
        zone_name = self._normalized_zone_name(zone_file.zone_name)
        if zone_name == "":
            zone_name = "."
        proc = subprocess.run(
            [named_checkzone, zone_name, zone_file.file_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            details = proc.stderr.strip() or proc.stdout.strip()
            raise BindOperationError(
                "ZONE_VALIDATION_FAILED",
                f"named-checkzone failed for {zone_name}: {details}",
                status=422,
            )

    def _restore_file_snapshots(self, snapshots: Dict[str, Optional[bytes]]) -> None:
        for path, content in snapshots.items():
            if content is None:
                if os.path.lexists(path):
                    os.remove(path)
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(content)

    def _write_and_validate_zone_files(self, zone_files: List[BindZoneFile]) -> None:
        snapshots: Dict[str, Optional[bytes]] = {}
        unique_paths: List[str] = []
        for zone_file in zone_files:
            for path in (zone_file.file_path, zone_file.fixed_hosts_file_path):
                if path in snapshots:
                    continue
                unique_paths.append(path)
                if os.path.exists(path):
                    with open(path, "rb") as handle:
                        snapshots[path] = handle.read()
                else:
                    snapshots[path] = None
        try:
            for zone_file in zone_files:
                zone_file.toFile()
            for zone_file in zone_files:
                self._validate_zone_file_record(zone_file)
        except Exception:
            self._restore_file_snapshots(snapshots)
            raise

    def add_fixed_host(
        self,
        fqdn: str,
        ip_address: str,
        ttl: Optional[str] = None,
        force: bool = False,
        persist: bool = True,
    ) -> dict:
        fqdn_abs = self._normalize_fqdn(fqdn)
        fqdn_target = fqdn_abs + "."
        try:
            ip_obj = ipaddress.ip_address((ip_address or "").strip())
        except ValueError:
            raise BindOperationError(
                "INVALID_IP_ADDRESS",
                f"Invalid IP address '{ip_address}'.",
                "Use a valid IPv4 or IPv6 address.",
            )

        ttl_text = None
        if ttl is not None:
            ttl_text = ttl.strip()
            if ttl_text and not re.fullmatch(r"[0-9]+[wdhmsWDHMS]*", ttl_text):
                raise BindOperationError(
                    "INVALID_TTL",
                    f"Invalid TTL '{ttl}'.",
                    "Use a numeric TTL or BIND-style duration (e.g. 3600, 1h, 2d).",
                )

        forward_zone = self._best_matching_zone(record_name=fqdn_abs, reverse=False)
        if forward_zone is None:
            raise BindOperationError(
                "FORWARD_ZONE_NOT_FOUND",
                f"No matching forward zone found for '{fqdn_abs}'.",
                "Create/import a matching zone first.",
                status=404,
            )
        forward_zone_name = self._normalized_zone_name(forward_zone.zone_name)
        forward_owner = self._owner_for_zone(fqdn_abs, forward_zone_name)
        rr_type = "A" if ip_obj.version == 4 else "AAAA"
        forward_target = str(ip_obj)
        ttl_part = f"{ttl_text} " if ttl_text else ""
        forward_text = f"{forward_owner} {ttl_part}IN {rr_type} {forward_target}".strip()
        forward_stmt = ZoneResourceRecord.fromText(forward_text)

        reverse_name = ip_obj.reverse_pointer.lower()
        reverse_zone = self._best_matching_zone(record_name=reverse_name, reverse=True)
        if reverse_zone is None:
            raise BindOperationError(
                "REVERSE_ZONE_NOT_FOUND",
                f"No matching reverse zone found for '{ip_obj}'.",
                "Create/import a matching reverse zone first.",
                status=404,
            )
        reverse_zone_name = self._normalized_zone_name(reverse_zone.zone_name)
        reverse_owner = self._owner_for_zone(reverse_name, reverse_zone_name)
        reverse_text = f"{reverse_owner} {ttl_part}IN PTR {fqdn_target}".strip()
        reverse_stmt = ZoneResourceRecord.fromText(reverse_text)

        zone_targets = [forward_zone]
        if reverse_zone is not forward_zone:
            zone_targets.append(reverse_zone)
        snapshots = {
            id(zone): {
                "zone_file_statements": list(zone.zone_file_statements),
                "fixed_host_statements": list(zone.fixed_host_statements),
            }
            for zone in zone_targets
        }

        conflicts: List[dict] = []
        for zone in zone_targets:
            conflicts.extend(
                self._collect_host_conflicts(
                    zone_file=zone,
                    fqdn_abs=fqdn_abs,
                    ip_text=forward_target,
                    reverse_name=reverse_name,
                )
            )
        ip_norm = forward_target.lower()
        short_host = fqdn_abs.split(".", 1)[0]
        reverse_target_aliases = {fqdn_abs, short_host}
        exact_conflicts: List[dict] = []
        other_conflicts: List[dict] = []
        for item in conflicts:
            is_exact_forward = (
                item.get("rr_type") == rr_type
                and item.get("owner_fqdn") == fqdn_abs
                and item.get("target") == ip_norm
            )
            is_exact_reverse = (
                item.get("rr_type") == "PTR"
                and item.get("owner_fqdn") == reverse_name
                and item.get("target") in reverse_target_aliases
            )
            if is_exact_forward or is_exact_reverse:
                exact_conflicts.append(item)
            else:
                other_conflicts.append(item)

        if other_conflicts and not force:
            conflict_preview = "; ".join(
                f"{item['zone']}:{item['rr_type']}@{item.get('source_file', 'unknown')} ({item['value']})"
                for item in other_conflicts[:5]
            )
            raise BindOperationError(
                "HOST_EXISTS",
                f"Host mapping already exists for name or IP. Conflicts: {conflict_preview}",
                "Use --force to overwrite existing host/IP entries.",
                status=409,
            )

        # If exactly the same mapping already exists, migrate it to FixedHosts.
        if exact_conflicts and not force:
            for zone in zone_targets:
                zone_conflicts = [item for item in exact_conflicts if item.get("zone_id") == id(zone)]
                if zone_conflicts:
                    self._remove_conflicts(zone, zone_conflicts)

        if conflicts and force:
            for zone in zone_targets:
                zone_conflicts = [item for item in conflicts if item.get("zone_id") == id(zone)]
                if zone_conflicts:
                    self._remove_conflicts(zone, zone_conflicts)

        forward_zone.fixed_host_statements.append(forward_stmt)
        if reverse_zone is forward_zone:
            forward_zone.fixed_host_statements.append(reverse_stmt)
        else:
            reverse_zone.fixed_host_statements.append(reverse_stmt)
        if persist:
            try:
                self._write_and_validate_zone_files(zone_targets)
            except Exception:
                for zone in zone_targets:
                    snap = snapshots[id(zone)]
                    zone.zone_file_statements = list(snap["zone_file_statements"])
                    zone.fixed_host_statements = list(snap["fixed_host_statements"])
                raise

        return {
            "fqdn": fqdn_target,
            "ip": str(ip_obj),
            "forward_zone": forward_zone.zone_name,
            "reverse_zone": reverse_zone.zone_name,
            "forward_rr": forward_text,
            "reverse_rr": reverse_text,
            "force": force,
            "persist": persist,
        }

    def _zone_group_name(self, zone_stmt: Statement, zone_name: str) -> str:
        keys = self._extract_allow_update_key_names(zone_stmt)
        if keys:
            return keys[0]
        return zone_name

    def _is_package_managed_zone(self, zone_name: str, zone_path: str) -> bool:
        normalized_zone = self._normalize_zone_name(zone_name)
        basename = os.path.basename(zone_path or "")
        if normalized_zone in PACKAGE_MANAGED_ZONE_NAMES:
            return True
        if basename in PACKAGE_MANAGED_ZONE_BASENAMES:
            return True
        if os.path.abspath(zone_path or "").startswith("/usr/share/dns/"):
            return True
        return False

    def _normalize_domain_name(self, domain_name: str) -> str:
        return self._normalize_fqdn(domain_name)

    def _normalize_label(self, label: str, field_name: str) -> str:
        cleaned = (label or "").strip().lower().rstrip(".")
        if not cleaned:
            raise BindOperationError("INVALID_INPUT", f"{field_name} is required.")
        if "." in cleaned:
            raise BindOperationError("INVALID_INPUT", f"{field_name} must be a single DNS label.")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", cleaned):
            raise BindOperationError("INVALID_INPUT", f"Invalid {field_name}: '{label}'.")
        return cleaned

    def _zone_names_in_use(self) -> set[str]:
        names: set[str] = set()
        for stmt in self._statements:
            if getattr(stmt, "statement_name", "") != "zone":
                continue
            names.add(self._normalize_zone_name(getattr(stmt, "value", None)))
        return names

    def _remove_zone_definition(self, zone_name: str) -> None:
        target = self._normalize_zone_name(zone_name)
        self._statements = [
            stmt
            for stmt in self._statements
            if not (
                getattr(stmt, "statement_name", "") == "zone"
                and self._normalize_zone_name(getattr(stmt, "value", None)) == target
            )
        ]
        self._zone_files = [
            zone_file
            for zone_file in self._zone_files
            if self._normalize_zone_name(zone_file.zone_name) != target
        ]

    def _find_first_options(self) -> Optional[Statement]:
        for stmt in self._statements:
            if getattr(stmt, "statement_name", "") == "options":
                return stmt
        return None

    def _ensure_allow_recursion_default(self) -> None:
        options_stmt = self._find_first_options()
        if options_stmt is None:
            options_stmt = Options(statements=[])
            self._statements.append(options_stmt)
        for child in getattr(options_stmt, "_statements", []):
            if getattr(child, "statement_name", "") == "allow-recursion":
                return
        options_stmt._statements.append(AllowRecursion(value="{ localhost; }"))

    def _ensure_update_key(self, key_name: str) -> None:
        key_value = f"\"{key_name}\""
        for stmt in self._statements:
            if getattr(stmt, "statement_name", "") != "key":
                continue
            if (getattr(stmt, "value", None) or "").strip() == key_value:
                return
        secret = base64.b64encode(os.urandom(32)).decode("ascii")
        key_stmt = Key(
            value=key_value,
            statements=[
                Algorithm(value="hmac-sha256"),
                Secret(value=f"\"{secret}\""),
            ],
        )
        self._statements.append(key_stmt)

    def _reverse_zone_from_ipv4(self, iface: ipaddress.IPv4Interface) -> tuple[str, str]:
        prefix = int(iface.network.prefixlen)
        if prefix not in {8, 16, 24}:
            raise BindOperationError(
                "UNSUPPORTED_PREFIX",
                f"Unsupported prefix '/{prefix}'. Only /8, /16, /24 are supported.",
                status=400,
            )
        octets = str(iface.ip).split(".")
        a, b, c, d = octets
        if prefix == 24:
            return (f"{c}.{b}.{a}.in-addr.arpa", d)
        if prefix == 16:
            return (f"{b}.{a}.in-addr.arpa", f"{d}.{c}")
        return (f"{a}.in-addr.arpa", f"{d}.{c}.{b}")

    def create_zone_minimal(
        self,
        domain_name: str,
        dns_server_cidr: str,
        base_hostname: str,
        force: bool = False,
        enable_allow_recursion: bool = True,
        enable_allow_update: bool = True,
    ) -> dict:
        domain = self._normalize_domain_name(domain_name)
        base_host = self._normalize_label(base_hostname, "base hostname")
        try:
            iface = ipaddress.ip_interface((dns_server_cidr or "").strip())
        except ValueError:
            raise BindOperationError(
                "INVALID_IP_PREFIX",
                f"Invalid DNS server IP/prefix '{dns_server_cidr}'.",
                "Use IPv4 with /8, /16, or /24 (e.g. 192.168.5.10/24).",
                status=400,
            )
        if not isinstance(iface, ipaddress.IPv4Interface):
            raise BindOperationError(
                "UNSUPPORTED_IP_VERSION",
                "Only IPv4 is supported for zone create right now.",
                status=400,
            )
        reverse_zone, reverse_owner = self._reverse_zone_from_ipv4(iface)
        zone_names = {domain, reverse_zone}
        existing = self._zone_names_in_use()
        collisions = sorted(zone_names.intersection(existing))
        if collisions and not force:
            raise BindOperationError(
                "ZONE_ALREADY_EXISTS",
                f"Zone(s) already exist: {', '.join(collisions)}",
                "Use --force to replace existing zone definitions.",
                status=409,
            )
        if collisions and force:
            for zone_name in collisions:
                self._remove_zone_definition(zone_name)

        if enable_allow_recursion:
            self._ensure_allow_recursion_default()

        key_name = f"{domain}.key"
        if enable_allow_update:
            self._ensure_update_key(key_name=key_name)

        ns_fqdn = f"{base_host}.{domain}."
        serial = datetime.utcnow().strftime("%Y%m%d01")
        soa_text = f"@ IN SOA {ns_fqdn} hostmaster.{domain}. {serial} 3600 600 1209600 3600"
        ns_text = f"@ IN NS {ns_fqdn}"
        a_text = f"{base_host} IN A {iface.ip}"
        ptr_text = f"{reverse_owner} IN PTR {ns_fqdn}"

        zone_children = [Type(value="master"), File(value="\"placeholder\"")]
        reverse_children = [Type(value="master"), File(value="\"placeholder\"")]
        if enable_allow_update:
            allow_update = AllowUpdate(statements=[Key(value=f"\"{key_name}\"")])
            zone_children.append(allow_update)
            reverse_children.append(AllowUpdate(statements=[Key(value=f"\"{key_name}\"")]))

        forward_zone_stmt = ZoneMaster(value=f"\"{domain}\"", statements=zone_children)
        reverse_zone_stmt = ZoneMaster(value=f"\"{reverse_zone}\"", statements=reverse_children)
        self._statements.append(forward_zone_stmt)
        self._statements.append(reverse_zone_stmt)

        self._zone_files.append(
            BindZoneFile(
                zone_name=domain,
                file_path=os.path.join("/tmp", f"{domain}.zone"),
                statements=[
                    ZoneDirectiveTtl(value="3600"),
                    ZoneResourceRecord.fromText(soa_text),
                    ZoneResourceRecord.fromText(ns_text),
                    ZoneResourceRecord.fromText(a_text),
                ],
                zone_type="master",
                ddns_enabled=enable_allow_update,
            )
        )
        self._zone_files.append(
            BindZoneFile(
                zone_name=reverse_zone,
                file_path=os.path.join("/tmp", f"{reverse_zone}.zone"),
                statements=[
                    ZoneDirectiveTtl(value="3600"),
                    ZoneResourceRecord.fromText(soa_text),
                    ZoneResourceRecord.fromText(ns_text),
                    ZoneResourceRecord.fromText(ptr_text),
                ],
                zone_type="master",
                ddns_enabled=enable_allow_update,
            )
        )

        return {
            "domain": domain,
            "reverse_zone": reverse_zone,
            "dns_server_ip": str(iface.ip),
            "prefix": int(iface.network.prefixlen),
            "base_hostname": base_host,
            "allow_recursion": enable_allow_recursion,
            "allow_update": enable_allow_update,
            "key_name": key_name if enable_allow_update else None,
        }

    def _render_statements_text(self, statements: List[Statement]) -> str:
        lines: List[str] = []
        for stmt in statements:
            if hasattr(stmt, "toText"):
                lines.append(stmt.toText())
            else:
                lines.append(str(stmt))
        content = "\n\n".join(lines).strip()
        if content:
            content += "\n"
        return content

    def _build_layout(self, named_etc: str, named_var: str) -> dict:
        dwlab_etc = os.path.join(named_etc, "dwlab")
        keys_dir = os.path.join(dwlab_etc, "keys")
        zones_dir = os.path.join(named_var, "dwlab")
        main_conf = os.path.join(named_etc, "dwlab.named.conf")
        options_conf = os.path.join(dwlab_etc, "dwlabdns.options.conf")
        global_conf = os.path.join(dwlab_etc, "global.conf")

        controls: List[Statement] = []
        options: List[Statement] = []
        keys: List[Statement] = []
        zones: List[Statement] = []
        others: List[Statement] = []
        for stmt in self._statements:
            name = getattr(stmt, "statement_name", "")
            if name == "controls":
                controls.append(stmt)
            elif name == "options":
                options.append(stmt)
            elif name == "key":
                keys.append(stmt)
            elif name == "zone":
                zones.append(stmt)
            else:
                others.append(stmt)

        group_to_zones: Dict[str, List[Statement]] = {}
        zone_checks: List[dict] = []
        zone_include_paths: set[str] = set()
        for zone_stmt in zones:
            zone_name = self._normalize_zone_name(getattr(zone_stmt, "value", None))
            if not zone_name:
                continue
            zone_obj = self._find_zone_file_object(zone_name)
            zone_file_path = os.path.join(zones_dir, f"{self._normalize_name_for_filename(zone_name)}.zone")
            if zone_obj is not None and zone_obj.externally_managed:
                zone_file_path = zone_obj.file_path
            else:
                if zone_obj is not None:
                    zone_obj.set_file_path(zone_file_path)
                self._set_zone_file_statement_path(zone_stmt, zone_file_path)
            group_name = self._zone_group_name(zone_stmt, zone_name)
            group_to_zones.setdefault(group_name, []).append(zone_stmt)
            zone_include_paths.add(os.path.join(dwlab_etc, f"{self._normalize_name_for_filename(group_name)}.conf"))
            zone_type = self._extract_zone_type(zone_stmt)
            zone_checks.append(
                {
                    "zone_name": zone_name,
                    "zone_type": zone_type,
                    "zone_file_path": zone_file_path,
                }
            )

        key_name_to_path: Dict[str, str] = {}
        for key_stmt in keys:
            key_name = (getattr(key_stmt, "value", None) or "").strip()
            if key_name.startswith('"') and key_name.endswith('"') and len(key_name) >= 2:
                key_name = key_name[1:-1]
            if not key_name:
                continue
            key_path = os.path.join(keys_dir, f"{self._normalize_name_for_filename(key_name)}.key")
            key_name_to_path[key_name] = key_path

        files_to_write: Dict[str, str] = {}
        if options:
            files_to_write[options_conf] = self._render_statements_text(options)
        else:
            files_to_write[options_conf] = ""

        global_header = (
            "// dwlabbind: global.conf stores top-level named.conf statements\n"
            "// that are not managed in dedicated files (controls/options/key/zone).\n"
        )
        if others:
            files_to_write[global_conf] = global_header + "\n" + self._render_statements_text(others)
        else:
            files_to_write[global_conf] = global_header

        for key_stmt in keys:
            key_name = (getattr(key_stmt, "value", None) or "").strip()
            if key_name.startswith('"') and key_name.endswith('"') and len(key_name) >= 2:
                key_name = key_name[1:-1]
            if not key_name:
                continue
            key_path = key_name_to_path.get(key_name)
            if not key_path:
                continue
            files_to_write[key_path] = key_stmt.toText() + "\n"

        for group_name, zone_list in group_to_zones.items():
            group_path = os.path.join(dwlab_etc, f"{self._normalize_name_for_filename(group_name)}.conf")
            files_to_write[group_path] = self._render_statements_text(zone_list)

        main_lines: List[str] = []
        if controls:
            for ctrl in controls:
                main_lines.append(ctrl.toText())
            main_lines.append("")
        main_lines.append(f'include "{options_conf}";')
        if os.path.exists(global_conf) or global_conf in files_to_write:
            main_lines.append(f'include "{global_conf}";')
        for key_name in sorted(key_name_to_path):
            main_lines.append(f'include "{key_name_to_path[key_name]}";')
        for include_path in sorted(zone_include_paths):
            main_lines.append(f'include "{include_path}";')
        files_to_write[main_conf] = "\n".join([line for line in main_lines if line is not None]).strip() + "\n"

        return {
            "main_conf": main_conf,
            "files": files_to_write,
            "zone_checks": zone_checks,
            "zones_dir": zones_dir,
        }

    def _write_layout_to_disk(self, layout: dict) -> None:
        for path, content in layout["files"].items():
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content or "")

        for zone_file in self._zone_files:
            if zone_file.externally_managed:
                continue
            zone_file.toFile()

    def _validate_layout(self, layout: dict) -> None:
        named_checkconf = shutil.which("named-checkconf")
        named_checkzone = shutil.which("named-checkzone")
        if not named_checkconf:
            raise RuntimeError("named-checkconf not found")
        if not named_checkzone:
            raise RuntimeError("named-checkzone not found")

        conf_proc = subprocess.run(
            [named_checkconf, layout["main_conf"]],
            capture_output=True,
            text=True,
            check=False,
        )
        if conf_proc.returncode != 0:
            raise RuntimeError(f"named-checkconf failed: {conf_proc.stderr.strip() or conf_proc.stdout.strip()}")

        # `hint` zones (e.g. root hints) intentionally do not contain SOA records,
        # so running named-checkzone on them produces false failures.
        check_zone_types = {"master", "primary", "slave", "secondary", "mirror", "stub", "static-stub", "redirect"}
        for entry in layout["zone_checks"]:
            zone_type = (entry.get("zone_type") or "").lower()
            zone_name = entry.get("zone_name")
            zone_file_path = entry.get("zone_file_path")
            if zone_type and zone_type not in check_zone_types:
                continue
            if not zone_name or not zone_file_path or not os.path.exists(zone_file_path):
                continue
            proc = subprocess.run(
                [named_checkzone, zone_name, zone_file_path],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"named-checkzone failed for {zone_name}: {proc.stderr.strip() or proc.stdout.strip()}"
                )

    def toConfFile(
        self,
        named_etc: str = "/etc/bind",
        named_var: str = "/var/lib/bind",
        force: bool = False,
    ) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        stage_root = tempfile.mkdtemp(prefix="dwlabbind-stage-")
        stage_etc = os.path.join(stage_root, "etc")
        stage_var = os.path.join(stage_root, "var")

        original_zone_paths = {id(z): z.file_path for z in self._zone_files}
        original_fixed_paths = {id(z): z.fixed_hosts_file_path for z in self._zone_files}
        original_zone_stmt_file_values: Dict[int, Optional[str]] = {}
        for stmt in self._statements:
            if getattr(stmt, "statement_name", "") != "zone":
                continue
            for child in getattr(stmt, "_statements", []):
                if getattr(child, "statement_name", "") == "file":
                    original_zone_stmt_file_values[id(child)] = getattr(child, "value", None)
                    break

        try:
            stage_layout = self._build_layout(stage_etc, stage_var)
            self._write_layout_to_disk(stage_layout)
            self._validate_layout(stage_layout)

            working_on = os.path.join(named_etc, "named.conf.working-on")
            named_conf = os.path.join(named_etc, "named.conf")
            target_conf = os.path.join(named_etc, "dwlab.named.conf")

            if os.path.exists(working_on):
                if not force:
                    logger.warning(
                        f"Stop processing: '{working_on}' already exists; another update process seems to be in progress."
                    )
                    raise RuntimeError("named.conf.working-on already exists")
                logger.warning(
                    "Force mode enabled: stale '%s' detected, attempting recovery/cleanup.",
                    working_on,
                )
                if not os.path.exists(named_conf):
                    os.rename(working_on, named_conf)
                else:
                    os.remove(working_on)
            if not os.path.exists(named_conf):
                logger.warning(
                    f"Stop processing: '{named_conf}' does not exist; another update process seems to be in progress."
                )
                raise RuntimeError("named.conf missing")

            os.rename(named_conf, working_on)
            moved = True
            try:
                real_layout = self._build_layout(named_etc, named_var)
                self._write_layout_to_disk(real_layout)
                if os.path.lexists(named_conf):
                    os.remove(named_conf)
                os.symlink(target_conf, named_conf)
                # Cleanup lock/work marker after successful handover.
                if os.path.exists(working_on):
                    os.remove(working_on)
            except Exception:
                if os.path.lexists(named_conf):
                    os.remove(named_conf)
                if moved and os.path.exists(working_on):
                    os.rename(working_on, named_conf)
                raise

            logger.debug("Leaving function "+str(function_name))
            return target_conf
        finally:
            for stmt in self._statements:
                if getattr(stmt, "statement_name", "") != "zone":
                    continue
                for child in getattr(stmt, "_statements", []):
                    if getattr(child, "statement_name", "") == "file":
                        cid = id(child)
                        if cid in original_zone_stmt_file_values:
                            child.value = original_zone_stmt_file_values[cid]
                        break
            for zone_file in self._zone_files:
                zid = id(zone_file)
                if zid in original_zone_paths:
                    zone_file.file_path = original_zone_paths[zid]
                if zid in original_fixed_paths:
                    zone_file.fixed_hosts_file_path = original_fixed_paths[zid]
            shutil.rmtree(stage_root, ignore_errors=True)

class BindStatementScanner:
    def __init__(self, allowed: Optional[set[str]], cleaned: str) -> List[object]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self._allowed = allowed
        self._cleaned = cleaned
        self._value: Optional[str] = None
        self._statements: List[object] = []

        scannedStatements = self._scan_statements(cleaned, allowed=allowed)
        for name, raw in scannedStatements:
            logger.debug(f"Found statement '{name}' in text {self._cleaned}")
            stmt_cls = _statement_class_for_name(name)
            logger.debug(f"Found statement '{name}' in text {self._cleaned}, class {stmt_cls}")
            if stmt_cls is None:
                continue
            try:
                allowed_sub = set(stmt_cls.allowed_statements())
                logger.debug(f"{stmt_cls.__name__} allows: {sorted(allowed_sub)}")
                stmt_obj = stmt_cls.fromText(raw)
            except Exception:
                logger.warning(f"Failed to parse statement '{name}' in text {self._cleaned}")
                continue
            self._statements.append(stmt_obj)
            
        
    @property
    def statements(self) -> List[object]:
        return self._statements 


    def _scan_statements(
            self, 
            text: str, 
            allowed: Optional[set[str]] = None
        ) -> List[Statement]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        results: List[tuple[str, str]] = []
        idx = 0
        length = len(text)
        while idx < length:
            while idx < length and text[idx].isspace():
                idx += 1
            if idx >= length:
                break
            if not (text[idx].isalnum() or text[idx] in "-_"):
                idx += 1
                continue

            stmt_start = idx
            while idx < length and (text[idx].isalnum() or text[idx] in "-_"):
                idx += 1
            name = text[stmt_start:idx]

            # Consume entire statement, including optional args and any
            # nested sub-blocks, until top-level ';'.
            j = idx
            in_quote = False
            escape = False
            brace_depth = 0
            stmt_end: Optional[int] = None
            while j < length:
                ch = text[j]
                if escape:
                    escape = False
                    j += 1
                    continue
                if ch == "\\":
                    escape = True
                    j += 1
                    continue
                if ch == "\"":
                    in_quote = not in_quote
                    j += 1
                    continue
                if not in_quote:
                    if ch == "{":
                        brace_depth += 1
                        j += 1
                        continue
                    if ch == "}":
                        brace_depth = max(0, brace_depth - 1)
                        j += 1
                        continue
                    if ch == ";" and brace_depth == 0:
                        j += 1
                        stmt_end = j
                        break
                j += 1

            if stmt_end is None:
                stmt_end = length

            if allowed is None or name in allowed:
                raw = text[stmt_start:stmt_end].strip()
                logger.debug(f"Found top-level statement: {name}")
                results.append((name, raw))

            idx = stmt_end
        logger.debug("Leaving function "+str(function_name))
        return results

def backup_named_conf(named_conf: str, output_tar: str) -> str:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.fromConfFile(named_conf)

    logger.debug("Leaving function "+str(function_name))
    return server.backup(output_tar)


def _backup_files_from_archive(archive_path: str) -> set[str]:
    files: set[str] = set()
    with tarfile.open(archive_path, "r") as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.issym() or member.islnk()):
                continue
            relative = member.name.lstrip("/")
            normalized = os.path.normpath("/" + relative)
            files.add(normalized)
    return files


def _restore_from_backup_archive(archive_path: str) -> None:
    with tarfile.open(archive_path, "r") as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.issym() or member.islnk()):
                continue
            relative = member.name.lstrip("/")
            target_path = os.path.normpath("/" + relative)
            if not target_path.startswith("/"):
                continue
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            if os.path.lexists(target_path):
                if os.path.isdir(target_path) and not os.path.islink(target_path):
                    shutil.rmtree(target_path)
                else:
                    os.remove(target_path)
            if member.issym() or member.islnk():
                link_target = member.linkname
                os.symlink(link_target, target_path)
                continue
            source = tar.extractfile(member)
            if source is None:
                continue
            with source, open(target_path, "wb") as handle:
                handle.write(source.read())


def _is_under_path(path: str, root: str) -> bool:
    root_abs = os.path.abspath(root)
    path_abs = os.path.abspath(path)
    try:
        common = os.path.commonpath([path_abs, root_abs])
    except ValueError:
        return False
    return common == root_abs


def _is_package_managed_path(path: str) -> bool:
    apath = os.path.abspath(path)
    if apath.startswith("/usr/share/dns/"):
        return True
    basename = os.path.basename(apath)
    if basename in PACKAGE_MANAGED_CONFIG_BASENAMES:
        return True
    if basename in PACKAGE_MANAGED_ZONE_BASENAMES:
        return True
    return False


def _remove_unreferenced_backed_up_files(
    archive_path: str,
    active_refs: set[str],
    named_etc: str,
    named_var: str,
) -> list[str]:
    removed: list[str] = []
    backup_files = _backup_files_from_archive(archive_path)
    keep_files = set(os.path.abspath(path) for path in active_refs)
    keep_files.add(os.path.abspath(os.path.join(named_etc, "named.conf")))
    for path in sorted(backup_files):
        apath = os.path.abspath(path)
        if apath in keep_files:
            continue
        if _is_package_managed_path(apath):
            continue
        if not (_is_under_path(apath, named_etc) or _is_under_path(apath, named_var)):
            continue
        if not os.path.lexists(apath):
            continue
        if os.path.isdir(apath) and not os.path.islink(apath):
            continue
        os.remove(apath)
        removed.append(apath)
    return removed


def _cleanup_generated_definitions(
    named_etc: str,
    named_var: str,
    xml_path: str,
    keep_files: set[str],
) -> None:
    generated_files = [
        os.path.join(named_etc, "dwlab.named.conf"),
        os.path.join(named_etc, "named.conf"),
        os.path.join(named_etc, "named.conf.working-on"),
        xml_path,
    ]
    for path in generated_files:
        apath = os.path.abspath(path)
        if apath in keep_files:
            continue
        if not os.path.lexists(apath):
            continue
        if os.path.isdir(apath) and not os.path.islink(apath):
            continue
        os.remove(apath)

    for root in (os.path.join(named_etc, "dwlab"), os.path.join(named_var, "dwlab")):
        if not os.path.isdir(root):
            continue
        for current, _, files in os.walk(root, topdown=False):
            for filename in files:
                candidate = os.path.abspath(os.path.join(current, filename))
                if candidate in keep_files:
                    continue
                if os.path.lexists(candidate):
                    os.remove(candidate)
            if not os.listdir(current):
                os.rmdir(current)


def import_named_conf(named_conf: str) -> str:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.fromConfFile(named_conf)
    logger.info("Referenced files:")
    for ref in server._collect_referenced_files():
        logger.info(f" - {ref}")
    base_dir = os.path.dirname(server.source_path or "")
    output_path = os.path.join(base_dir, "dwlabbind.xml")
    bindServerDict=server.to_dict()
    bindServerSettings=dwlabSettings(data=bindServerDict)
    yaml_path=os.path.join(os.path.dirname(__file__), "bind_server_settings.yaml")
    logger.debug(f"Write YAML settings from {yaml_path}")
    _write_server_xml(server, output_path)

    logger.debug("Leaving function "+str(function_name))
    return output_path


def add_fixed_host_entry(
    named_conf: str,
    fqdn: str,
    ip_address: str,
    ttl: Optional[str] = None,
    force: bool = False,
    persist: bool = True,
) -> dict:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.fromConfFile(named_conf)
    result = server.add_fixed_host(
        fqdn=fqdn,
        ip_address=ip_address,
        ttl=ttl,
        force=force,
        persist=persist,
    )

    logger.debug("Leaving function "+str(function_name))
    return result


def add_fixed_host_and_write(
    named_conf: str,
    fqdn: str,
    ip_address: str,
    ttl: Optional[str] = None,
    force: bool = False,
    named_etc: Optional[str] = None,
    named_var: Optional[str] = None,
) -> dict:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.fromConfFile(named_conf)
    host_result = server.add_fixed_host(
        fqdn=fqdn,
        ip_address=ip_address,
        ttl=ttl,
        force=force,
        persist=False,
    )

    base_dir = os.path.dirname(server.source_path or named_conf)
    xml_path = os.path.join(base_dir, "dwlabbind.xml")
    _write_server_xml(server, xml_path)

    etc_path = named_etc or os.path.dirname(named_conf)
    var_path = named_var or "/var/lib/bind"
    conf_path = server.toConfFile(named_etc=etc_path, named_var=var_path, force=force)

    logger.debug("Leaving function "+str(function_name))
    return {
        **host_result,
        "xml": xml_path,
        "conf": conf_path,
    }


def create_zone_and_write(
    named_conf: str,
    domain_name: str,
    dns_server_cidr: str,
    base_hostname: str,
    force: bool = False,
    named_etc: Optional[str] = None,
    named_var: Optional[str] = None,
    enable_allow_recursion: bool = True,
    enable_allow_update: bool = True,
) -> dict:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.fromConfFile(named_conf)
    zone_result = server.create_zone_minimal(
        domain_name=domain_name,
        dns_server_cidr=dns_server_cidr,
        base_hostname=base_hostname,
        force=force,
        enable_allow_recursion=enable_allow_recursion,
        enable_allow_update=enable_allow_update,
    )

    base_dir = os.path.dirname(server.source_path or named_conf)
    xml_path = os.path.join(base_dir, "dwlabbind.xml")
    _write_server_xml(server, xml_path)

    etc_path = named_etc or os.path.dirname(named_conf)
    var_path = named_var or "/var/lib/bind"
    conf_path = server.toConfFile(named_etc=etc_path, named_var=var_path, force=force)

    logger.debug("Leaving function "+str(function_name))
    return {
        **zone_result,
        "xml": xml_path,
        "conf": conf_path,
    }


def initialize_named_conf(
    named_conf: str,
    backup_output: Optional[str] = None,
    named_etc: Optional[str] = None,
    named_var: Optional[str] = None,
    force: bool = False,
    cleanup: bool = True,
) -> dict:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.fromConfFile(named_conf)
    if backup_output:
        archive_target = backup_output
    else:
        backup_dir = os.path.dirname(named_conf) or "/etc/bind"
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_target = os.path.join(backup_dir, f"named.dwlab.conf.{ts}.tar")
    archive_path = server.backup(archive_target)

    etc_path = named_etc or os.path.dirname(named_conf)
    var_path = named_var or "/var/lib/bind"
    base_dir = os.path.dirname(server.source_path or named_conf)
    xml_path = os.path.join(base_dir, "dwlabbind.xml")
    conf_path = ""
    try:
        _write_server_xml(server, xml_path)
        conf_path = server.toConfFile(named_etc=etc_path, named_var=var_path, force=force)
        if cleanup:
            rendered = BindServer.fromConfFile(conf_path)
            active_refs = set(rendered._collect_referenced_files())
            removed = _remove_unreferenced_backed_up_files(
                archive_path=archive_path,
                active_refs=active_refs,
                named_etc=etc_path,
                named_var=var_path,
            )
            if removed:
                logger.info(
                    "Cleanup removed %d unreferenced legacy BIND file(s) after initialize.",
                    len(removed),
                )
                for removed_path in removed:
                    logger.info("Cleanup deleted file: %s", removed_path)
    except Exception as exc:
        logger.error(
            "Initialize failed after backup. Rolling back from archive '%s': %s",
            archive_path,
            exc,
        )
        keep_files = _backup_files_from_archive(archive_path)
        try:
            _cleanup_generated_definitions(
                named_etc=etc_path,
                named_var=var_path,
                xml_path=xml_path,
                keep_files=keep_files,
            )
            _restore_from_backup_archive(archive_path)
            logger.warning("Rollback from backup archive completed.")
        except Exception as rollback_exc:
            logger.error("Rollback failed: %s", rollback_exc)
        raise

    logger.debug("Leaving function "+str(function_name))
    return {
        "archive": archive_path,
        "xml": xml_path,
        "conf": conf_path,
    }


def _plural_statement_name(name: str) -> str:
    if name == "key":
        return "keys"
    if name == "zone":
        return "zones"
    if name.endswith("y"):
        return name[:-1] + "ies"
    return name + "s"


def _normalize_text_value(value: object) -> str:
    text = str(value)
    # Normalize CRLF/LF and collapse repeated whitespace to a single space.
    return " ".join(text.replace("\r\n", "\n").replace("\r", "\n").split())


def _append_statement_xml(parent: ET.Element, statement: object) -> None:
    if not hasattr(statement, "statement_name"):
        raw_el = ET.SubElement(parent, "raw")
        raw_el.text = _normalize_text_value(statement)
        return
    node = ET.SubElement(parent, str(statement.statement_name))
    value = getattr(statement, "value", None)
    if value is not None:
        value_el = ET.SubElement(node, "value")
        value_el.text = _normalize_text_value(value)
    children = getattr(statement, "_statements", None) or []
    if children:
        statements_el = ET.SubElement(node, "statements")
        for child in children:
            _append_statement_xml(statements_el, child)


def _append_zone_file_statement_xml(
    parent: ET.Element,
    statement: ZoneFileStatement,
    position: Optional[int] = None,
    node_name_override: Optional[str] = None,
) -> None:
    payload = statement.to_dict() if hasattr(statement, "to_dict") else {"raw": str(statement)}
    name = node_name_override or str(payload.get("statement", "raw")).lower().replace("$", "")
    if not name:
        name = "raw"
    node = ET.SubElement(parent, name)
    if position is not None:
        node.set("position", str(position))
    for key, value in payload.items():
        if key == "statement":
            continue
        if value is None:
            continue
        if isinstance(value, list):
            list_el = ET.SubElement(node, key)
            for item in value:
                item_el = ET.SubElement(list_el, "item")
                item_el.text = _normalize_text_value(item)
            continue
        if isinstance(value, dict):
            obj_el = ET.SubElement(node, key)
            for sub_key, sub_value in value.items():
                if sub_value is None:
                    continue
                sub_el = ET.SubElement(obj_el, str(sub_key))
                sub_el.text = _normalize_text_value(sub_value)
            continue
        field_el = ET.SubElement(node, key)
        field_el.text = _normalize_text_value(value)


def _write_server_xml(server: BindServer, path: str) -> None:
    function_name = sys._getframe().f_code.co_name
    function_name=__PACKAGE_NAME__+"."+function_name
    logger.debug("Entering function "+str(function_name))

    root = ET.Element("root")
    name_el = ET.SubElement(root, "name")
    name_el.text = str(server.name)
    if server.source_path is not None:
        source_el = ET.SubElement(root, "source_path")
        source_el.text = str(server.source_path)

    files_el = ET.SubElement(root, "source_files")
    for file_path in server._source_files:
        file_el = ET.SubElement(files_el, "file")
        file_el.text = str(file_path)

    grouped: Dict[str, List[object]] = {}
    for stmt in server._statements:
        stmt_name = getattr(stmt, "statement_name", stmt.__class__.__name__.lower())
        grouped.setdefault(str(stmt_name), []).append(stmt)

    for stmt_name, stmt_list in grouped.items():
        if len(stmt_list) > 1:
            container = ET.SubElement(root, _plural_statement_name(stmt_name))
            for stmt in stmt_list:
                _append_statement_xml(container, stmt)
        else:
            _append_statement_xml(root, stmt_list[0])

    if server._zone_files:
        zone_files_el = ET.SubElement(root, "zone_files")
        for zone_file in server._zone_files:
            zone_file_el = ET.SubElement(zone_files_el, "zone_file")
            zone_name_el = ET.SubElement(zone_file_el, "zone_name")
            zone_name_el.text = _normalize_text_value(zone_file.zone_name)
            file_path_el = ET.SubElement(zone_file_el, "file_path")
            file_path_el.text = _normalize_text_value(zone_file.file_path)
            if zone_file.zone_type:
                zone_type_el = ET.SubElement(zone_file_el, "zone_type")
                zone_type_el.text = _normalize_text_value(zone_file.zone_type)
            ddns_el = ET.SubElement(zone_file_el, "ddns_enabled")
            ddns_el.text = "true" if zone_file.ddns_enabled else "false"
            fixed_hosts_path_el = ET.SubElement(zone_file_el, "fixed_hosts_file_path")
            fixed_hosts_path_el.text = _normalize_text_value(zone_file.fixed_hosts_file_path)
            static_include_el = ET.SubElement(zone_file_el, "static_hosts_include")
            include_value = f'"{zone_file.fixed_hosts_file_path}"'
            include_origin = zone_file._include_origin()
            if include_origin:
                include_value = f"{include_value} {include_origin}"
            include_stmt = ZoneDirectiveInclude.fromText(f"$INCLUDE {include_value}")
            _append_zone_file_statement_xml(
                static_include_el,
                include_stmt,
                node_name_override="include",
            )
            generated_el = ET.SubElement(static_include_el, "generated")
            generated_el.text = "true"
            statements_el = ET.SubElement(zone_file_el, "statements")
            seen_soa = False
            default_ttl_written = False
            for idx, statement in enumerate(zone_file.zone_file_statements):
                tag_override = None
                if isinstance(statement, ZoneResourceRecord) and getattr(statement, "rr_type", None) == "SOA":
                    seen_soa = True
                if isinstance(statement, ZoneDirectiveTtl) and not seen_soa and not default_ttl_written:
                    tag_override = "DefaultTTL"
                    default_ttl_written = True
                _append_zone_file_statement_xml(
                    statements_el,
                    statement,
                    position=idx,
                    node_name_override=tag_override,
                )
            fixed_hosts_el = ET.SubElement(zone_file_el, "FixedHosts")
            for idx, statement in enumerate(zone_file.fixed_host_statements):
                _append_zone_file_statement_xml(
                    fixed_hosts_el,
                    statement,
                    position=idx,
                )

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)

    logger.debug("Leaving function "+str(function_name))
