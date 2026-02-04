"""Zone statement classes."""

from __future__ import annotations

import logging
import sys
from typing import Dict, List, Optional

from .bind_statements_utils import _extract_statement_body, _split_statement_texts, _statement_class_for_name, _class_accepts_param

logger = logging.getLogger(__name__)

class Zone:
    ALLOWED_STATEMENTS: List[str] = []

    def __init__(
        self,
        value: Optional[str] = None,
        statements: Optional[Dict[str, List[object]]] = None,
    ) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.value = value
        self._statements: Dict[str, List[object]] = statements or {}

        logger.debug("Leaving function "+str(function_name))

    def set_value(self, value: Optional[str]) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.value = value

        logger.debug("Leaving function "+str(function_name))
    @classmethod
    def allowed_statements(cls) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name="Zone"
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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="Zone"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        logger.debug("Receive text: " + text)
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
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Zone":
        function_name = sys._getframe().f_code.co_name
        class_name="Zone"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if isinstance(data, str) or data is None:
            logger.debug("Leaving function "+str(function_name))
            return cls(value=data)
        logger.debug("Leaving function "+str(function_name))
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        logger.debug("Leaving function "+str(function_name))
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Zone":
        function_name = sys._getframe().f_code.co_name
        class_name="Zone"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if element is None:
            logger.debug("Leaving function "+str(function_name))
            return cls()
        logger.debug("Leaving function "+str(function_name))
        return cls(value=element.text)

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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZonePrimary"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

class ZoneMaster(Zone):
    zone_type = "master"
    ALLOWED_STATEMENTS = ZonePrimary.ALLOWED_STATEMENTS

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneMaster"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneSecondary"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

class ZoneSlave(Zone):
    zone_type = "slave"
    ALLOWED_STATEMENTS = ZoneSecondary.ALLOWED_STATEMENTS

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneSlave"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneMirror"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

class ZoneHint(Zone):
    zone_type = "hint"
    ALLOWED_STATEMENTS = [
        "type",
        "check-names",
        "delegation-only",
        "file",
    ]

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneHint"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneStub"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneStaticStub"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

class ZoneForward(Zone):
    zone_type = "forward"
    ALLOWED_STATEMENTS = [
        "type",
        "delegation-only",
        "forward",
        "forwarders",
    ]

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneForward"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneRedirect"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

class ZoneDelegationOnly(Zone):
    zone_type = "delegation-only"
    ALLOWED_STATEMENTS = [
        "type",
    ]

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneDelegationOnly"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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

class ZoneInView(Zone):
    zone_type = "in-view"
    ALLOWED_STATEMENTS = [
        "in-view",
        "forward",
        "forwarders",
    ]

    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneInView"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        logger.debug("Receive text: " + text)
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


class ZonePropagationDelay:
    statement_name = "zone-propagation-delay"
    xml_tag = "zone_propagation_delay"
    def __init__(self, value: Optional[str] = None) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.value = value

        logger.debug("Leaving function "+str(function_name))
    def set_value(self, value: Optional[str]) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.value = value

        logger.debug("Leaving function "+str(function_name))
    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZonePropagationDelay"
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
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ZonePropagationDelay":
        function_name = sys._getframe().f_code.co_name
        class_name="ZonePropagationDelay"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if isinstance(data, str) or data is None:
            logger.debug("Leaving function "+str(function_name))
            return cls(value=data)
        logger.debug("Leaving function "+str(function_name))
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        logger.debug("Leaving function "+str(function_name))
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ZonePropagationDelay":
        function_name = sys._getframe().f_code.co_name
        class_name="ZonePropagationDelay"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if element is None:
            logger.debug("Leaving function "+str(function_name))
            return cls()
        logger.debug("Leaving function "+str(function_name))
        return cls(value=element.text)


class ZoneStatistics:
    statement_name = "zone-statistics"
    xml_tag = "zone_statistics"
    def __init__(self, value: Optional[str] = None) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.value = value

        logger.debug("Leaving function "+str(function_name))
    def set_value(self, value: Optional[str]) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.value = value

        logger.debug("Leaving function "+str(function_name))
    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneStatistics"
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
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ZoneStatistics":
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneStatistics"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if isinstance(data, str) or data is None:
            logger.debug("Leaving function "+str(function_name))
            return cls(value=data)
        logger.debug("Leaving function "+str(function_name))
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        logger.debug("Leaving function "+str(function_name))
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ZoneStatistics":
        function_name = sys._getframe().f_code.co_name
        class_name="ZoneStatistics"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if element is None:
            logger.debug("Leaving function "+str(function_name))
            return cls()
        logger.debug("Leaving function "+str(function_name))
        return cls(value=element.text)
