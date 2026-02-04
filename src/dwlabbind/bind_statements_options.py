"""Options statement class."""

from __future__ import annotations

import logging
import sys
from typing import Dict, List, Optional

from .bind_statements_utils import _extract_statement_body, _split_statement_texts, _statement_class_for_name, _class_accepts_param

logger = logging.getLogger(__name__)

class Options:
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

    def __init__(
        self,
        statements: Optional[Dict[str, List[object]]] = None,
    ) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self._statements: Dict[str, List[object]] = statements or {}

        logger.debug("Leaving function "+str(function_name))

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="Options"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        cleaned = (text or "").strip()
        if cleaned.endswith(";"):
            cleaned = cleaned[:-1].strip()
        if hasattr(cls, "ALLOWED_STATEMENTS"):
            body = _extract_statement_body(cleaned)
            statements = {}
            for chunk in _split_statement_texts(body):
                name = chunk.split(None, 1)[0] if chunk.split() else ""
                if not name:
                    continue
                if name in cls.ALLOWED_STATEMENTS:
                    stmt_cls = _statement_class_for_name(name)
                    if stmt_cls is None or not hasattr(stmt_cls, "fromText"):
                        continue
                    stmt_obj = stmt_cls.fromText(chunk + ";")
                    statements.setdefault(name, []).append(stmt_obj)
            try:
                logger.debug("Leaving function "+str(function_name))
                return cls(statements=statements)
            except TypeError:
                logger.debug("Leaving function "+str(function_name))
                return cls()
        if _class_accepts_param(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            logger.debug("Leaving function "+str(function_name))
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        if _class_accepts_param(cls, "value"):
            logger.debug("Leaving function "+str(function_name))
            return cls(value=value)
        logger.debug("Leaving function "+str(function_name))
        return cls()
    def to_dict(self) -> dict:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Leaving function "+str(function_name))
        return {}

    @classmethod
    def from_dict(cls, data: dict) -> "Options":
        function_name = sys._getframe().f_code.co_name
        class_name="Options"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Leaving function "+str(function_name))
        return cls()

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        element = ET.Element(self.xml_tag)
        logger.debug("Leaving function "+str(function_name))
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Options":
        function_name = sys._getframe().f_code.co_name
        class_name="Options"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if element is None:
            logger.debug("Leaving function "+str(function_name))
            return cls()
        logger.debug("Leaving function "+str(function_name))
        return cls()

    @classmethod
    def allowed_statements(cls) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name="Options"
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
        if name not in self.allowed_statements():
            raise ValueError(f"Statement '{name}' not allowed for Options")

        logger.debug("Leaving function "+str(function_name))
    def insert_statement(self, statement: object) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        self._statements.setdefault(name, []).append(statement)

        logger.debug("Leaving function "+str(function_name))
    def update_statement(self, statement: object, index: int = 0) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        bucket = self._statements.setdefault(name, [])
        if index < 0 or index >= len(bucket):
            raise IndexError("statement index out of range")
        bucket[index] = statement

        logger.debug("Leaving function "+str(function_name))
    def delete_statement(self, statement: object, index: int = 0) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        bucket = self._statements.get(name, [])
        if not bucket:
            logger.debug("Leaving function "+str(function_name))
            return
        if index < 0 or index >= len(bucket):
            raise IndexError("statement index out of range")
        bucket.pop(index)
        if not bucket:
            self._statements.pop(name, None)

