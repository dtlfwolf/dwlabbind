"""Explicit statement classes generated from bind_statements_data.json."""

from __future__ import annotations

from typing import Dict, List, Optional
import re
import xml.etree.ElementTree as ET



def _statement_class_for_name(name: str):
    safe = re.sub(r"[^0-9A-Za-z_]+", "_", name).strip("_")
    if not safe:
        return None
    class_name = "".join(part.capitalize() for part in safe.split("_"))
    return globals().get(class_name)


def _extract_statement_body(text: str) -> str:
    if "{" in text and "}" in text:
        return text[text.find("{") + 1:text.rfind("}")].strip()
    return text


def _split_statement_texts(body: str) -> list[str]:
    parts = []
    for chunk in body.split(";"):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts
__all__ = ['Acl', 'Algorithm', 'AllPerSecond', 'AllowNewZones', 'AllowNotify', 'AllowQuery', 'AllowQueryCache', 'AllowQueryCacheOn', 'AllowQueryOn', 'AllowRecursion', 'AllowRecursionOn', 'AllowTransfer', 'AllowUpdate', 'AllowUpdateForwarding', 'AlsoNotify', 'AltTransferSource', 'AltTransferSourceV6', 'AnswerCookie', 'AttachCache', 'AuthNxdomain', 'AutoDnssec', 'AutomaticInterfaceScan', 'AvoidV4UdpPorts', 'AvoidV6UdpPorts', 'BindkeysFile', 'Blackhole', 'Bogus', 'BreakDnssec', 'Buffered', 'CaFile', 'CatalogZones', 'Category', 'CertFile', 'Channel', 'CheckDupRecords', 'CheckIntegrity', 'CheckMx', 'CheckMxCname', 'CheckNames', 'CheckSibling', 'CheckSpf', 'CheckSrvCname', 'CheckWildcard', 'Ciphers', 'Clients', 'ClientsPerQuery', 'Controls', 'CookieAlgorithm', 'CookieSecret', 'Coresize', 'Database', 'Datasize', 'DelegationOnly', 'DenyAnswerAddresses', 'DenyAnswerAliases', 'DhparamFile', 'Dialup', 'Directory', 'DisableAlgorithms', 'DisableDsDigests', 'DisableEmptyZone', 'Dlz', 'Dns64', 'Dns64Contact', 'Dns64Server', 'DnskeySigValidity', 'DnskeyTtl', 'DnsrpsEnable', 'DnsrpsOptions', 'DnssecAcceptExpired', 'DnssecDnskeyKskonly', 'DnssecLoadkeysInterval', 'DnssecMustBeSecure', 'DnssecPolicy', 'DnssecSecureToInsecure', 'DnssecUpdateMode', 'DnssecValidation', 'Dnstap', 'DnstapIdentity', 'DnstapOutput', 'DnstapVersion', 'Dscp', 'DualStackServers', 'DumpFile', 'Dyndb', 'Edns', 'EdnsUdpSize', 'EdnsVersion', 'EmptyContact', 'EmptyServer', 'EmptyZonesEnable', 'Endpoints', 'ErrorsPerSecond', 'Exclude', 'ExemptClients', 'FetchQuotaParams', 'FetchesPerServer', 'FetchesPerZone', 'File', 'Files', 'FlushZonesOnShutdown', 'Forward', 'Forwarders', 'FstrmSetBufferHint', 'FstrmSetFlushTimeout', 'FstrmSetInputQueueSize', 'FstrmSetOutputNotifyThreshold', 'FstrmSetOutputQueueModel', 'FstrmSetOutputQueueSize', 'FstrmSetReopenInterval', 'GeoipDirectory', 'GlueCache', 'HeartbeatInterval', 'Hostname', 'Http', 'HttpListenerClients', 'HttpPort', 'HttpStreamsPerConnection', 'HttpsPort', 'InView', 'Inet', 'InlineSigning', 'InterfaceInterval', 'Ipv4PrefixLength', 'Ipv4onlyContact', 'Ipv4onlyEnable', 'Ipv4onlyServer', 'Ipv6PrefixLength', 'IxfrFromDifferences', 'Journal', 'KeepResponseOrder', 'Key', 'KeyDirectory', 'KeyFile', 'Keys', 'LameTtl', 'ListenOn', 'ListenOnV6', 'ListenerClients', 'LmdbMapsize', 'LockFile', 'LogOnly', 'Logging', 'ManagedKeys', 'ManagedKeysDirectory', 'Mapped', 'MasterfileFormat', 'MasterfileStyle', 'MatchClients', 'MatchDestinations', 'MatchMappedAddresses', 'MatchRecursiveOnly', 'MaxCacheSize', 'MaxCacheTtl', 'MaxClientsPerQuery', 'MaxIxfrRatio', 'MaxJournalSize', 'MaxNcacheTtl', 'MaxRecords', 'MaxRecursionDepth', 'MaxRecursionQueries', 'MaxRefreshTime', 'MaxRetryTime', 'MaxRsaExponentSize', 'MaxStaleTtl', 'MaxTableSize', 'MaxTransferIdleIn', 'MaxTransferIdleOut', 'MaxTransferTimeIn', 'MaxTransferTimeOut', 'MaxUdpSize', 'MaxZoneTtl', 'Memstatistics', 'MemstatisticsFile', 'MessageCompression', 'MinCacheTtl', 'MinNcacheTtl', 'MinRefreshTime', 'MinRetryTime', 'MinTableSize', 'MinimalAny', 'MinimalResponses', 'MultiMaster', 'NewZonesDirectory', 'NoCaseCompress', 'NocookieUdpSize', 'NodataPerSecond', 'Notify', 'NotifyDelay', 'NotifyRate', 'NotifySource', 'NotifySourceV6', 'NotifyToSoa', 'Nsec3param', 'NtaLifetime', 'NtaRecheck', 'Null', 'NxdomainRedirect', 'NxdomainsPerSecond', 'Options', 'Padding', 'ParentDsTtl', 'ParentPropagationDelay', 'ParentalAgents', 'ParentalSource', 'ParentalSourceV6', 'PidFile', 'Plugin', 'Port', 'PreferServerCiphers', 'PreferredGlue', 'Prefetch', 'Primaries', 'PrintCategory', 'PrintSeverity', 'PrintTime', 'Protocols', 'ProvideIxfr', 'PublishSafety', 'PurgeKeys', 'QnameMinimization', 'QpsScale', 'QuerySource', 'QuerySourceV6', 'Querylog', 'RateLimit', 'RecursingFile', 'Recursion', 'RecursiveClients', 'RecursiveOnly', 'ReferralsPerSecond', 'RemoteHostname', 'RequestExpire', 'RequestIxfr', 'RequestNsid', 'RequireServerCookie', 'ReservedSockets', 'ResolverNonbackoffTries', 'ResolverQueryTimeout', 'ResolverRetryInterval', 'ResponsePadding', 'ResponsePolicy', 'ResponsesPerSecond', 'RetireSafety', 'Reuseport', 'RootDelegationOnly', 'RootKeySentinel', 'RrsetOrder', 'Search', 'Secret', 'SecrootsFile', 'SendCookie', 'SerialQueryRate', 'SerialUpdateMethod', 'Server', 'ServerAddresses', 'ServerId', 'ServerNames', 'ServfailTtl', 'SessionKeyalg', 'SessionKeyfile', 'SessionKeyname', 'SessionTickets', 'Severity', 'SigSigningNodes', 'SigSigningSignatures', 'SigSigningType', 'SigValidityInterval', 'SignaturesRefresh', 'SignaturesValidity', 'SignaturesValidityDnskey', 'Slip', 'Sortlist', 'Stacksize', 'StaleAnswerClientTimeout', 'StaleAnswerEnable', 'StaleAnswerTtl', 'StaleCacheEnable', 'StaleRefreshTime', 'StartupNotifyRate', 'StatisticsChannels', 'StatisticsFile', 'Stderr', 'StreamsPerConnection', 'Suffix', 'SynthFromDnssec', 'Syslog', 'TcpAdvertisedTimeout', 'TcpClients', 'TcpIdleTimeout', 'TcpInitialTimeout', 'TcpKeepalive', 'TcpKeepaliveTimeout', 'TcpListenQueue', 'TcpOnly', 'TcpReceiveBuffer', 'TcpSendBuffer', 'TkeyDhkey', 'TkeyDomain', 'TkeyGssapiCredential', 'TkeyGssapiKeytab', 'Tls', 'TlsPort', 'TransferFormat', 'TransferMessageSize', 'TransferSource', 'TransferSourceV6', 'Transfers', 'TransfersIn', 'TransfersOut', 'TransfersPerNs', 'TrustAnchorTelemetry', 'TrustAnchors', 'TrustedKeys', 'TryTcpRefresh', 'Type', 'TypeDelegationOnly', 'TypeForward', 'TypeHint', 'TypeMirror', 'TypePrimary', 'TypeRedirect', 'TypeSecondary', 'TypeStaticStub', 'TypeStub', 'UdpReceiveBuffer', 'UdpSendBuffer', 'Unix', 'UpdateCheckKsk', 'UpdatePolicy', 'UpdateQuota', 'UseAltTransferSource', 'UseV4UdpPorts', 'UseV6UdpPorts', 'V6Bias', 'ValidateExcept', 'Version', 'View', 'Window', 'ZeroNoSoaTtl', 'ZeroNoSoaTtlCache', 'Zone', 'ZonePropagationDelay', 'ZoneStatistics']

class Acl:
    statement_name = "acl"
    xml_tag = "acl"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Acl":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Acl":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Algorithm:
    statement_name = "algorithm"
    xml_tag = "algorithm"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Algorithm":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Algorithm":
        if element is None:
            return cls()
        return cls(value=element.text)

class AllPerSecond:
    statement_name = "all-per-second"
    xml_tag = "all_per_second"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AllPerSecond":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllPerSecond":
        if element is None:
            return cls()
        return cls(value=element.text)

class AllowNewZones:
    statement_name = "allow-new-zones"
    xml_tag = "allow_new_zones"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowNewZones":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowNewZones":
        if element is None:
            return cls()
        return cls(value=element.text)

class AllowNotify:
    statement_name = "allow-notify"
    xml_tag = "allow_notify"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowNotify":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowNotify":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowQuery:
    statement_name = "allow-query"
    xml_tag = "allow_query"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowQuery":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowQuery":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowQueryCache:
    statement_name = "allow-query-cache"
    xml_tag = "allow_query_cache"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowQueryCache":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowQueryCache":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowQueryCacheOn:
    statement_name = "allow-query-cache-on"
    xml_tag = "allow_query_cache_on"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowQueryCacheOn":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowQueryCacheOn":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowQueryOn:
    statement_name = "allow-query-on"
    xml_tag = "allow_query_on"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowQueryOn":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowQueryOn":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowRecursion:
    statement_name = "allow-recursion"
    xml_tag = "allow_recursion"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowRecursion":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowRecursion":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowRecursionOn:
    statement_name = "allow-recursion-on"
    xml_tag = "allow_recursion_on"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowRecursionOn":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowRecursionOn":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowTransfer:
    statement_name = "allow-transfer"
    xml_tag = "allow_transfer"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowTransfer":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowTransfer":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowUpdate:
    statement_name = "allow-update"
    xml_tag = "allow_update"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowUpdate":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowUpdate":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AllowUpdateForwarding:
    statement_name = "allow-update-forwarding"
    xml_tag = "allow_update_forwarding"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AllowUpdateForwarding":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AllowUpdateForwarding":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AlsoNotify:
    statement_name = "also-notify"
    xml_tag = "also_notify"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AlsoNotify":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AlsoNotify":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AltTransferSource:
    statement_name = "alt-transfer-source"
    xml_tag = "alt_transfer_source"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AltTransferSource":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AltTransferSource":
        if element is None:
            return cls()
        return cls(value=element.text)

class AltTransferSourceV6:
    statement_name = "alt-transfer-source-v6"
    xml_tag = "alt_transfer_source_v6"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AltTransferSourceV6":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AltTransferSourceV6":
        if element is None:
            return cls()
        return cls(value=element.text)

class AnswerCookie:
    statement_name = "answer-cookie"
    xml_tag = "answer_cookie"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AnswerCookie":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AnswerCookie":
        if element is None:
            return cls()
        return cls(value=element.text)

class AttachCache:
    statement_name = "attach-cache"
    xml_tag = "attach_cache"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AttachCache":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AttachCache":
        if element is None:
            return cls()
        return cls(value=element.text)

class AuthNxdomain:
    statement_name = "auth-nxdomain"
    xml_tag = "auth_nxdomain"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AuthNxdomain":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AuthNxdomain":
        if element is None:
            return cls()
        return cls(value=element.text)

class AutoDnssec:
    statement_name = "auto-dnssec"
    xml_tag = "auto_dnssec"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AutoDnssec":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AutoDnssec":
        if element is None:
            return cls()
        return cls(value=element.text)

class AutomaticInterfaceScan:
    statement_name = "automatic-interface-scan"
    xml_tag = "automatic_interface_scan"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "AutomaticInterfaceScan":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AutomaticInterfaceScan":
        if element is None:
            return cls()
        return cls(value=element.text)

class AvoidV4UdpPorts:
    statement_name = "avoid-v4-udp-ports"
    xml_tag = "avoid_v4_udp_ports"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AvoidV4UdpPorts":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AvoidV4UdpPorts":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class AvoidV6UdpPorts:
    statement_name = "avoid-v6-udp-ports"
    xml_tag = "avoid_v6_udp_ports"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "AvoidV6UdpPorts":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "AvoidV6UdpPorts":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class BindkeysFile:
    statement_name = "bindkeys-file"
    xml_tag = "bindkeys_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "BindkeysFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "BindkeysFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Blackhole:
    statement_name = "blackhole"
    xml_tag = "blackhole"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Blackhole":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Blackhole":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Bogus:
    statement_name = "bogus"
    xml_tag = "bogus"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Bogus":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Bogus":
        if element is None:
            return cls()
        return cls(value=element.text)

class BreakDnssec:
    statement_name = "break-dnssec"
    xml_tag = "break_dnssec"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "BreakDnssec":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "BreakDnssec":
        if element is None:
            return cls()
        return cls(value=element.text)

class Buffered:
    statement_name = "buffered"
    xml_tag = "buffered"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Buffered":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Buffered":
        if element is None:
            return cls()
        return cls(value=element.text)

class CaFile:
    statement_name = "ca-file"
    xml_tag = "ca_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CaFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CaFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class CatalogZones:
    statement_name = "catalog-zones"
    xml_tag = "catalog_zones"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CatalogZones":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CatalogZones":
        if element is None:
            return cls()
        return cls(value=element.text)

class Category:
    statement_name = "category"
    xml_tag = "category"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Category":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Category":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class CertFile:
    statement_name = "cert-file"
    xml_tag = "cert_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CertFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CertFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Channel:
    statement_name = "channel"
    xml_tag = "channel"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Channel":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Channel":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class CheckDupRecords:
    statement_name = "check-dup-records"
    xml_tag = "check_dup_records"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckDupRecords":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckDupRecords":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckIntegrity:
    statement_name = "check-integrity"
    xml_tag = "check_integrity"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckIntegrity":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckIntegrity":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckMx:
    statement_name = "check-mx"
    xml_tag = "check_mx"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckMx":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckMx":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckMxCname:
    statement_name = "check-mx-cname"
    xml_tag = "check_mx_cname"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckMxCname":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckMxCname":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckNames:
    statement_name = "check-names"
    xml_tag = "check_names"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckNames":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckNames":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckSibling:
    statement_name = "check-sibling"
    xml_tag = "check_sibling"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckSibling":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckSibling":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckSpf:
    statement_name = "check-spf"
    xml_tag = "check_spf"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckSpf":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckSpf":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckSrvCname:
    statement_name = "check-srv-cname"
    xml_tag = "check_srv_cname"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckSrvCname":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckSrvCname":
        if element is None:
            return cls()
        return cls(value=element.text)

class CheckWildcard:
    statement_name = "check-wildcard"
    xml_tag = "check_wildcard"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CheckWildcard":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CheckWildcard":
        if element is None:
            return cls()
        return cls(value=element.text)

class Ciphers:
    statement_name = "ciphers"
    xml_tag = "ciphers"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Ciphers":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Ciphers":
        if element is None:
            return cls()
        return cls(value=element.text)

class Clients:
    statement_name = "clients"
    xml_tag = "clients"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Clients":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Clients":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ClientsPerQuery:
    statement_name = "clients-per-query"
    xml_tag = "clients_per_query"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ClientsPerQuery":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ClientsPerQuery":
        if element is None:
            return cls()
        return cls(value=element.text)

class Controls:
    statement_name = "controls"
    ALLOWED_STATEMENTS = [
        "inet",
        "unix",
    ]

    xml_tag = "controls"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Controls":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Controls":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class CookieAlgorithm:
    statement_name = "cookie-algorithm"
    xml_tag = "cookie_algorithm"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CookieAlgorithm":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CookieAlgorithm":
        if element is None:
            return cls()
        return cls(value=element.text)

class CookieSecret:
    statement_name = "cookie-secret"
    xml_tag = "cookie_secret"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "CookieSecret":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "CookieSecret":
        if element is None:
            return cls()
        return cls(value=element.text)

class Coresize:
    statement_name = "coresize"
    xml_tag = "coresize"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Coresize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Coresize":
        if element is None:
            return cls()
        return cls(value=element.text)

class Database:
    statement_name = "database"
    xml_tag = "database"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Database":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Database":
        if element is None:
            return cls()
        return cls(value=element.text)

class Datasize:
    statement_name = "datasize"
    xml_tag = "datasize"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Datasize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Datasize":
        if element is None:
            return cls()
        return cls(value=element.text)

class DelegationOnly:
    statement_name = "delegation-only"
    xml_tag = "delegation_only"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DelegationOnly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DelegationOnly":
        if element is None:
            return cls()
        return cls(value=element.text)

class DenyAnswerAddresses:
    statement_name = "deny-answer-addresses"
    xml_tag = "deny_answer_addresses"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "DenyAnswerAddresses":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DenyAnswerAddresses":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DenyAnswerAliases:
    statement_name = "deny-answer-aliases"
    xml_tag = "deny_answer_aliases"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "DenyAnswerAliases":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DenyAnswerAliases":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DhparamFile:
    statement_name = "dhparam-file"
    xml_tag = "dhparam_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DhparamFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DhparamFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dialup:
    statement_name = "dialup"
    xml_tag = "dialup"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Dialup":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dialup":
        if element is None:
            return cls()
        return cls(value=element.text)

class Directory:
    statement_name = "directory"
    xml_tag = "directory"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Directory":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Directory":
        if element is None:
            return cls()
        return cls(value=element.text)

class DisableAlgorithms:
    statement_name = "disable-algorithms"
    xml_tag = "disable_algorithms"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "DisableAlgorithms":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DisableAlgorithms":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DisableDsDigests:
    statement_name = "disable-ds-digests"
    xml_tag = "disable_ds_digests"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "DisableDsDigests":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DisableDsDigests":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DisableEmptyZone:
    statement_name = "disable-empty-zone"
    xml_tag = "disable_empty_zone"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DisableEmptyZone":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DisableEmptyZone":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dlz:
    statement_name = "dlz"
    ALLOWED_STATEMENTS = [
        "database",
    ]

    xml_tag = "dlz"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Dlz":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dlz":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dns64:
    statement_name = "dns64"
    xml_tag = "dns64"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Dns64":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dns64":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Dns64Contact:
    statement_name = "dns64-contact"
    xml_tag = "dns64_contact"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Dns64Contact":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dns64Contact":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dns64Server:
    statement_name = "dns64-server"
    xml_tag = "dns64_server"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Dns64Server":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dns64Server":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnskeySigValidity:
    statement_name = "dnskey-sig-validity"
    xml_tag = "dnskey_sig_validity"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnskeySigValidity":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnskeySigValidity":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnskeyTtl:
    statement_name = "dnskey-ttl"
    xml_tag = "dnskey_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnskeyTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnskeyTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnsrpsEnable:
    statement_name = "dnsrps-enable"
    xml_tag = "dnsrps_enable"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnsrpsEnable":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnsrpsEnable":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnsrpsOptions:
    statement_name = "dnsrps-options"
    xml_tag = "dnsrps_options"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "DnsrpsOptions":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnsrpsOptions":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DnssecAcceptExpired:
    statement_name = "dnssec-accept-expired"
    xml_tag = "dnssec_accept_expired"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecAcceptExpired":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecAcceptExpired":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecDnskeyKskonly:
    statement_name = "dnssec-dnskey-kskonly"
    xml_tag = "dnssec_dnskey_kskonly"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecDnskeyKskonly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecDnskeyKskonly":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecLoadkeysInterval:
    statement_name = "dnssec-loadkeys-interval"
    xml_tag = "dnssec_loadkeys_interval"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecLoadkeysInterval":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecLoadkeysInterval":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecMustBeSecure:
    statement_name = "dnssec-must-be-secure"
    xml_tag = "dnssec_must_be_secure"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecMustBeSecure":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecMustBeSecure":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecPolicy:
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
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecPolicy":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecPolicy":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecSecureToInsecure:
    statement_name = "dnssec-secure-to-insecure"
    xml_tag = "dnssec_secure_to_insecure"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecSecureToInsecure":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecSecureToInsecure":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecUpdateMode:
    statement_name = "dnssec-update-mode"
    xml_tag = "dnssec_update_mode"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecUpdateMode":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecUpdateMode":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnssecValidation:
    statement_name = "dnssec-validation"
    xml_tag = "dnssec_validation"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnssecValidation":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnssecValidation":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dnstap:
    statement_name = "dnstap"
    xml_tag = "dnstap"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Dnstap":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dnstap":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DnstapIdentity:
    statement_name = "dnstap-identity"
    xml_tag = "dnstap_identity"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnstapIdentity":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnstapIdentity":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnstapOutput:
    statement_name = "dnstap-output"
    xml_tag = "dnstap_output"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnstapOutput":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnstapOutput":
        if element is None:
            return cls()
        return cls(value=element.text)

class DnstapVersion:
    statement_name = "dnstap-version"
    xml_tag = "dnstap_version"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DnstapVersion":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DnstapVersion":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dscp:
    statement_name = "dscp"
    xml_tag = "dscp"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Dscp":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dscp":
        if element is None:
            return cls()
        return cls(value=element.text)

class DualStackServers:
    statement_name = "dual-stack-servers"
    xml_tag = "dual_stack_servers"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "DualStackServers":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DualStackServers":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class DumpFile:
    statement_name = "dump-file"
    xml_tag = "dump_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "DumpFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "DumpFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Dyndb:
    statement_name = "dyndb"
    xml_tag = "dyndb"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Dyndb":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Dyndb":
        if element is None:
            return cls()
        return cls(value=element.text)

class Edns:
    statement_name = "edns"
    xml_tag = "edns"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Edns":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Edns":
        if element is None:
            return cls()
        return cls(value=element.text)

class EdnsUdpSize:
    statement_name = "edns-udp-size"
    xml_tag = "edns_udp_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "EdnsUdpSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "EdnsUdpSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class EdnsVersion:
    statement_name = "edns-version"
    xml_tag = "edns_version"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "EdnsVersion":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "EdnsVersion":
        if element is None:
            return cls()
        return cls(value=element.text)

class EmptyContact:
    statement_name = "empty-contact"
    xml_tag = "empty_contact"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "EmptyContact":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "EmptyContact":
        if element is None:
            return cls()
        return cls(value=element.text)

class EmptyServer:
    statement_name = "empty-server"
    xml_tag = "empty_server"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "EmptyServer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "EmptyServer":
        if element is None:
            return cls()
        return cls(value=element.text)

class EmptyZonesEnable:
    statement_name = "empty-zones-enable"
    xml_tag = "empty_zones_enable"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "EmptyZonesEnable":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "EmptyZonesEnable":
        if element is None:
            return cls()
        return cls(value=element.text)

class Endpoints:
    statement_name = "endpoints"
    xml_tag = "endpoints"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Endpoints":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Endpoints":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ErrorsPerSecond:
    statement_name = "errors-per-second"
    xml_tag = "errors_per_second"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ErrorsPerSecond":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ErrorsPerSecond":
        if element is None:
            return cls()
        return cls(value=element.text)

class Exclude:
    statement_name = "exclude"
    xml_tag = "exclude"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Exclude":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Exclude":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ExemptClients:
    statement_name = "exempt-clients"
    xml_tag = "exempt_clients"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ExemptClients":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ExemptClients":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class FetchQuotaParams:
    statement_name = "fetch-quota-params"
    xml_tag = "fetch_quota_params"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FetchQuotaParams":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FetchQuotaParams":
        if element is None:
            return cls()
        return cls(value=element.text)

class FetchesPerServer:
    statement_name = "fetches-per-server"
    xml_tag = "fetches_per_server"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FetchesPerServer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FetchesPerServer":
        if element is None:
            return cls()
        return cls(value=element.text)

class FetchesPerZone:
    statement_name = "fetches-per-zone"
    xml_tag = "fetches_per_zone"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FetchesPerZone":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FetchesPerZone":
        if element is None:
            return cls()
        return cls(value=element.text)

class File:
    statement_name = "file"
    xml_tag = "file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "File":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "File":
        if element is None:
            return cls()
        return cls(value=element.text)

class Files:
    statement_name = "files"
    xml_tag = "files"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Files":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Files":
        if element is None:
            return cls()
        return cls(value=element.text)

class FlushZonesOnShutdown:
    statement_name = "flush-zones-on-shutdown"
    xml_tag = "flush_zones_on_shutdown"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FlushZonesOnShutdown":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FlushZonesOnShutdown":
        if element is None:
            return cls()
        return cls(value=element.text)

class Forward:
    statement_name = "forward"
    xml_tag = "forward"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Forward":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Forward":
        if element is None:
            return cls()
        return cls(value=element.text)

class Forwarders:
    statement_name = "forwarders"
    xml_tag = "forwarders"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Forwarders":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Forwarders":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class FstrmSetBufferHint:
    statement_name = "fstrm-set-buffer-hint"
    xml_tag = "fstrm_set_buffer_hint"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetBufferHint":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetBufferHint":
        if element is None:
            return cls()
        return cls(value=element.text)

class FstrmSetFlushTimeout:
    statement_name = "fstrm-set-flush-timeout"
    xml_tag = "fstrm_set_flush_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetFlushTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetFlushTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class FstrmSetInputQueueSize:
    statement_name = "fstrm-set-input-queue-size"
    xml_tag = "fstrm_set_input_queue_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetInputQueueSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetInputQueueSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class FstrmSetOutputNotifyThreshold:
    statement_name = "fstrm-set-output-notify-threshold"
    xml_tag = "fstrm_set_output_notify_threshold"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetOutputNotifyThreshold":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetOutputNotifyThreshold":
        if element is None:
            return cls()
        return cls(value=element.text)

class FstrmSetOutputQueueModel:
    statement_name = "fstrm-set-output-queue-model"
    xml_tag = "fstrm_set_output_queue_model"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetOutputQueueModel":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetOutputQueueModel":
        if element is None:
            return cls()
        return cls(value=element.text)

class FstrmSetOutputQueueSize:
    statement_name = "fstrm-set-output-queue-size"
    xml_tag = "fstrm_set_output_queue_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetOutputQueueSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetOutputQueueSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class FstrmSetReopenInterval:
    statement_name = "fstrm-set-reopen-interval"
    xml_tag = "fstrm_set_reopen_interval"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "FstrmSetReopenInterval":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "FstrmSetReopenInterval":
        if element is None:
            return cls()
        return cls(value=element.text)

class GeoipDirectory:
    statement_name = "geoip-directory"
    xml_tag = "geoip_directory"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "GeoipDirectory":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "GeoipDirectory":
        if element is None:
            return cls()
        return cls(value=element.text)

class GlueCache:
    statement_name = "glue-cache"
    xml_tag = "glue_cache"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "GlueCache":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "GlueCache":
        if element is None:
            return cls()
        return cls(value=element.text)

class HeartbeatInterval:
    statement_name = "heartbeat-interval"
    xml_tag = "heartbeat_interval"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "HeartbeatInterval":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "HeartbeatInterval":
        if element is None:
            return cls()
        return cls(value=element.text)

class Hostname:
    statement_name = "hostname"
    xml_tag = "hostname"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Hostname":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Hostname":
        if element is None:
            return cls()
        return cls(value=element.text)

class Http:
    statement_name = "http"
    ALLOWED_STATEMENTS = [
        "endpoints",
        "listener-clients",
        "streams-per-connection",
    ]

    xml_tag = "http"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Http":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Http":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class HttpListenerClients:
    statement_name = "http-listener-clients"
    xml_tag = "http_listener_clients"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "HttpListenerClients":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "HttpListenerClients":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class HttpPort:
    statement_name = "http-port"
    xml_tag = "http_port"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "HttpPort":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "HttpPort":
        if element is None:
            return cls()
        return cls(value=element.text)

class HttpStreamsPerConnection:
    statement_name = "http-streams-per-connection"
    xml_tag = "http_streams_per_connection"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "HttpStreamsPerConnection":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "HttpStreamsPerConnection":
        if element is None:
            return cls()
        return cls(value=element.text)

class HttpsPort:
    statement_name = "https-port"
    xml_tag = "https_port"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "HttpsPort":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "HttpsPort":
        if element is None:
            return cls()
        return cls(value=element.text)

class InView:
    statement_name = "in-view"
    xml_tag = "in_view"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "InView":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "InView":
        if element is None:
            return cls()
        return cls(value=element.text)

class Inet:
    statement_name = "inet"
    xml_tag = "inet"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Inet":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Inet":
        if element is None:
            return cls()
        return cls(value=element.text)

class InlineSigning:
    statement_name = "inline-signing"
    xml_tag = "inline_signing"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "InlineSigning":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "InlineSigning":
        if element is None:
            return cls()
        return cls(value=element.text)

class InterfaceInterval:
    statement_name = "interface-interval"
    xml_tag = "interface_interval"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "InterfaceInterval":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "InterfaceInterval":
        if element is None:
            return cls()
        return cls(value=element.text)

class Ipv4PrefixLength:
    statement_name = "ipv4-prefix-length"
    xml_tag = "ipv4_prefix_length"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Ipv4PrefixLength":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Ipv4PrefixLength":
        if element is None:
            return cls()
        return cls(value=element.text)

class Ipv4onlyContact:
    statement_name = "ipv4only-contact"
    xml_tag = "ipv4only_contact"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Ipv4onlyContact":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Ipv4onlyContact":
        if element is None:
            return cls()
        return cls(value=element.text)

class Ipv4onlyEnable:
    statement_name = "ipv4only-enable"
    xml_tag = "ipv4only_enable"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Ipv4onlyEnable":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Ipv4onlyEnable":
        if element is None:
            return cls()
        return cls(value=element.text)

class Ipv4onlyServer:
    statement_name = "ipv4only-server"
    xml_tag = "ipv4only_server"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Ipv4onlyServer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Ipv4onlyServer":
        if element is None:
            return cls()
        return cls(value=element.text)

class Ipv6PrefixLength:
    statement_name = "ipv6-prefix-length"
    xml_tag = "ipv6_prefix_length"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Ipv6PrefixLength":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Ipv6PrefixLength":
        if element is None:
            return cls()
        return cls(value=element.text)

class IxfrFromDifferences:
    statement_name = "ixfr-from-differences"
    xml_tag = "ixfr_from_differences"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "IxfrFromDifferences":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "IxfrFromDifferences":
        if element is None:
            return cls()
        return cls(value=element.text)

class Journal:
    statement_name = "journal"
    xml_tag = "journal"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Journal":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Journal":
        if element is None:
            return cls()
        return cls(value=element.text)

class KeepResponseOrder:
    statement_name = "keep-response-order"
    xml_tag = "keep_response_order"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "KeepResponseOrder":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "KeepResponseOrder":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Key:
    statement_name = "key"
    ALLOWED_STATEMENTS = [
        "algorithm",
        "secret",
    ]

    xml_tag = "key"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Key":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Key":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class KeyDirectory:
    statement_name = "key-directory"
    xml_tag = "key_directory"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "KeyDirectory":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "KeyDirectory":
        if element is None:
            return cls()
        return cls(value=element.text)

class KeyFile:
    statement_name = "key-file"
    xml_tag = "key_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "KeyFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "KeyFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Keys:
    statement_name = "keys"
    xml_tag = "keys"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Keys":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Keys":
        if element is None:
            return cls()
        return cls(value=element.text)

class LameTtl:
    statement_name = "lame-ttl"
    xml_tag = "lame_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "LameTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "LameTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class ListenOn:
    statement_name = "listen-on"
    xml_tag = "listen_on"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ListenOn":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ListenOn":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ListenOnV6:
    statement_name = "listen-on-v6"
    xml_tag = "listen_on_v6"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ListenOnV6":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ListenOnV6":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ListenerClients:
    statement_name = "listener-clients"
    xml_tag = "listener_clients"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ListenerClients":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ListenerClients":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class LmdbMapsize:
    statement_name = "lmdb-mapsize"
    xml_tag = "lmdb_mapsize"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "LmdbMapsize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "LmdbMapsize":
        if element is None:
            return cls()
        return cls(value=element.text)

class LockFile:
    statement_name = "lock-file"
    xml_tag = "lock_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "LockFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "LockFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class LogOnly:
    statement_name = "log-only"
    xml_tag = "log_only"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "LogOnly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "LogOnly":
        if element is None:
            return cls()
        return cls(value=element.text)

class Logging:
    statement_name = "logging"
    ALLOWED_STATEMENTS = [
        "category",
        "channel",
    ]

    xml_tag = "logging"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Logging":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Logging":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ManagedKeys:
    statement_name = "managed-keys"
    xml_tag = "managed_keys"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ManagedKeys":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ManagedKeys":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ManagedKeysDirectory:
    statement_name = "managed-keys-directory"
    xml_tag = "managed_keys_directory"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ManagedKeysDirectory":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ManagedKeysDirectory":
        if element is None:
            return cls()
        return cls(value=element.text)

class Mapped:
    statement_name = "mapped"
    xml_tag = "mapped"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Mapped":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Mapped":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class MasterfileFormat:
    statement_name = "masterfile-format"
    xml_tag = "masterfile_format"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MasterfileFormat":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MasterfileFormat":
        if element is None:
            return cls()
        return cls(value=element.text)

class MasterfileStyle:
    statement_name = "masterfile-style"
    xml_tag = "masterfile_style"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MasterfileStyle":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MasterfileStyle":
        if element is None:
            return cls()
        return cls(value=element.text)

class MatchClients:
    statement_name = "match-clients"
    xml_tag = "match_clients"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "MatchClients":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MatchClients":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class MatchDestinations:
    statement_name = "match-destinations"
    xml_tag = "match_destinations"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "MatchDestinations":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MatchDestinations":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class MatchMappedAddresses:
    statement_name = "match-mapped-addresses"
    xml_tag = "match_mapped_addresses"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MatchMappedAddresses":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MatchMappedAddresses":
        if element is None:
            return cls()
        return cls(value=element.text)

class MatchRecursiveOnly:
    statement_name = "match-recursive-only"
    xml_tag = "match_recursive_only"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MatchRecursiveOnly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MatchRecursiveOnly":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxCacheSize:
    statement_name = "max-cache-size"
    xml_tag = "max_cache_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxCacheSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxCacheSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxCacheTtl:
    statement_name = "max-cache-ttl"
    xml_tag = "max_cache_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxCacheTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxCacheTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxClientsPerQuery:
    statement_name = "max-clients-per-query"
    xml_tag = "max_clients_per_query"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxClientsPerQuery":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxClientsPerQuery":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxIxfrRatio:
    statement_name = "max-ixfr-ratio"
    xml_tag = "max_ixfr_ratio"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxIxfrRatio":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxIxfrRatio":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxJournalSize:
    statement_name = "max-journal-size"
    xml_tag = "max_journal_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxJournalSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxJournalSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxNcacheTtl:
    statement_name = "max-ncache-ttl"
    xml_tag = "max_ncache_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxNcacheTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxNcacheTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxRecords:
    statement_name = "max-records"
    xml_tag = "max_records"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxRecords":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxRecords":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxRecursionDepth:
    statement_name = "max-recursion-depth"
    xml_tag = "max_recursion_depth"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxRecursionDepth":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxRecursionDepth":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxRecursionQueries:
    statement_name = "max-recursion-queries"
    xml_tag = "max_recursion_queries"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxRecursionQueries":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxRecursionQueries":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxRefreshTime:
    statement_name = "max-refresh-time"
    xml_tag = "max_refresh_time"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxRefreshTime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxRefreshTime":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxRetryTime:
    statement_name = "max-retry-time"
    xml_tag = "max_retry_time"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxRetryTime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxRetryTime":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxRsaExponentSize:
    statement_name = "max-rsa-exponent-size"
    xml_tag = "max_rsa_exponent_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxRsaExponentSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxRsaExponentSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxStaleTtl:
    statement_name = "max-stale-ttl"
    xml_tag = "max_stale_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxStaleTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxStaleTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxTableSize:
    statement_name = "max-table-size"
    xml_tag = "max_table_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxTableSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxTableSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxTransferIdleIn:
    statement_name = "max-transfer-idle-in"
    xml_tag = "max_transfer_idle_in"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxTransferIdleIn":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxTransferIdleIn":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxTransferIdleOut:
    statement_name = "max-transfer-idle-out"
    xml_tag = "max_transfer_idle_out"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxTransferIdleOut":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxTransferIdleOut":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxTransferTimeIn:
    statement_name = "max-transfer-time-in"
    xml_tag = "max_transfer_time_in"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxTransferTimeIn":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxTransferTimeIn":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxTransferTimeOut:
    statement_name = "max-transfer-time-out"
    xml_tag = "max_transfer_time_out"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxTransferTimeOut":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxTransferTimeOut":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxUdpSize:
    statement_name = "max-udp-size"
    xml_tag = "max_udp_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxUdpSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxUdpSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class MaxZoneTtl:
    statement_name = "max-zone-ttl"
    xml_tag = "max_zone_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MaxZoneTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MaxZoneTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class Memstatistics:
    statement_name = "memstatistics"
    xml_tag = "memstatistics"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Memstatistics":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Memstatistics":
        if element is None:
            return cls()
        return cls(value=element.text)

class MemstatisticsFile:
    statement_name = "memstatistics-file"
    xml_tag = "memstatistics_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MemstatisticsFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MemstatisticsFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class MessageCompression:
    statement_name = "message-compression"
    xml_tag = "message_compression"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MessageCompression":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MessageCompression":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinCacheTtl:
    statement_name = "min-cache-ttl"
    xml_tag = "min_cache_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinCacheTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinCacheTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinNcacheTtl:
    statement_name = "min-ncache-ttl"
    xml_tag = "min_ncache_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinNcacheTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinNcacheTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinRefreshTime:
    statement_name = "min-refresh-time"
    xml_tag = "min_refresh_time"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinRefreshTime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinRefreshTime":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinRetryTime:
    statement_name = "min-retry-time"
    xml_tag = "min_retry_time"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinRetryTime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinRetryTime":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinTableSize:
    statement_name = "min-table-size"
    xml_tag = "min_table_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinTableSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinTableSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinimalAny:
    statement_name = "minimal-any"
    xml_tag = "minimal_any"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinimalAny":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinimalAny":
        if element is None:
            return cls()
        return cls(value=element.text)

class MinimalResponses:
    statement_name = "minimal-responses"
    xml_tag = "minimal_responses"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MinimalResponses":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MinimalResponses":
        if element is None:
            return cls()
        return cls(value=element.text)

class MultiMaster:
    statement_name = "multi-master"
    xml_tag = "multi_master"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "MultiMaster":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "MultiMaster":
        if element is None:
            return cls()
        return cls(value=element.text)

class NewZonesDirectory:
    statement_name = "new-zones-directory"
    xml_tag = "new_zones_directory"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NewZonesDirectory":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NewZonesDirectory":
        if element is None:
            return cls()
        return cls(value=element.text)

class NoCaseCompress:
    statement_name = "no-case-compress"
    xml_tag = "no_case_compress"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "NoCaseCompress":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NoCaseCompress":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class NocookieUdpSize:
    statement_name = "nocookie-udp-size"
    xml_tag = "nocookie_udp_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NocookieUdpSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NocookieUdpSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class NodataPerSecond:
    statement_name = "nodata-per-second"
    xml_tag = "nodata_per_second"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NodataPerSecond":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NodataPerSecond":
        if element is None:
            return cls()
        return cls(value=element.text)

class Notify:
    statement_name = "notify"
    xml_tag = "notify"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Notify":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Notify":
        if element is None:
            return cls()
        return cls(value=element.text)

class NotifyDelay:
    statement_name = "notify-delay"
    xml_tag = "notify_delay"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NotifyDelay":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NotifyDelay":
        if element is None:
            return cls()
        return cls(value=element.text)

class NotifyRate:
    statement_name = "notify-rate"
    xml_tag = "notify_rate"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NotifyRate":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NotifyRate":
        if element is None:
            return cls()
        return cls(value=element.text)

class NotifySource:
    statement_name = "notify-source"
    xml_tag = "notify_source"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NotifySource":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NotifySource":
        if element is None:
            return cls()
        return cls(value=element.text)

class NotifySourceV6:
    statement_name = "notify-source-v6"
    xml_tag = "notify_source_v6"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NotifySourceV6":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NotifySourceV6":
        if element is None:
            return cls()
        return cls(value=element.text)

class NotifyToSoa:
    statement_name = "notify-to-soa"
    xml_tag = "notify_to_soa"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NotifyToSoa":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NotifyToSoa":
        if element is None:
            return cls()
        return cls(value=element.text)

class Nsec3param:
    statement_name = "nsec3param"
    xml_tag = "nsec3param"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Nsec3param":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Nsec3param":
        if element is None:
            return cls()
        return cls(value=element.text)

class NtaLifetime:
    statement_name = "nta-lifetime"
    xml_tag = "nta_lifetime"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NtaLifetime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NtaLifetime":
        if element is None:
            return cls()
        return cls(value=element.text)

class NtaRecheck:
    statement_name = "nta-recheck"
    xml_tag = "nta_recheck"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NtaRecheck":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NtaRecheck":
        if element is None:
            return cls()
        return cls(value=element.text)

class Null:
    statement_name = "null"
    xml_tag = "null"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Null":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Null":
        if element is None:
            return cls()
        return cls(value=element.text)

class NxdomainRedirect:
    statement_name = "nxdomain-redirect"
    xml_tag = "nxdomain_redirect"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NxdomainRedirect":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NxdomainRedirect":
        if element is None:
            return cls()
        return cls(value=element.text)

class NxdomainsPerSecond:
    statement_name = "nxdomains-per-second"
    xml_tag = "nxdomains_per_second"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "NxdomainsPerSecond":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "NxdomainsPerSecond":
        if element is None:
            return cls()
        return cls(value=element.text)

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
        self._statements: Dict[str, List[object]] = statements or {}

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {}

    @classmethod
    def from_dict(cls, data: dict) -> "Options":
        return cls()

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Options":
        if element is None:
            return cls()
        return cls()

    @classmethod
    def allowed_statements(cls) -> List[str]:
        return list(cls.ALLOWED_STATEMENTS)

    def _statement_name(self, statement: object) -> str:
        if isinstance(statement, str):
            return statement
        name = getattr(statement, "statement_name", None)
        if not name:
            raise ValueError("Unknown statement object: missing statement_name")
        return str(name)

    def _ensure_allowed(self, name: str) -> None:
        if name not in self.allowed_statements():
            raise ValueError(f"Statement '{name}' not allowed for Options")

    def insert_statement(self, statement: object) -> None:
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        self._statements.setdefault(name, []).append(statement)

    def update_statement(self, statement: object, index: int = 0) -> None:
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        bucket = self._statements.setdefault(name, [])
        if index < 0 or index >= len(bucket):
            raise IndexError("statement index out of range")
        bucket[index] = statement

    def delete_statement(self, statement: object, index: int = 0) -> None:
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        bucket = self._statements.get(name, [])
        if not bucket:
            return
        if index < 0 or index >= len(bucket):
            raise IndexError("statement index out of range")
        bucket.pop(index)
        if not bucket:
            self._statements.pop(name, None)

class Padding:
    statement_name = "padding"
    xml_tag = "padding"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Padding":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Padding":
        if element is None:
            return cls()
        return cls(value=element.text)

class ParentDsTtl:
    statement_name = "parent-ds-ttl"
    xml_tag = "parent_ds_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ParentDsTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ParentDsTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class ParentPropagationDelay:
    statement_name = "parent-propagation-delay"
    xml_tag = "parent_propagation_delay"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ParentPropagationDelay":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ParentPropagationDelay":
        if element is None:
            return cls()
        return cls(value=element.text)

class ParentalAgents:
    statement_name = "parental-agents"
    xml_tag = "parental_agents"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ParentalAgents":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ParentalAgents":
        if element is None:
            return cls()
        return cls(value=element.text)

class ParentalSource:
    statement_name = "parental-source"
    xml_tag = "parental_source"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ParentalSource":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ParentalSource":
        if element is None:
            return cls()
        return cls(value=element.text)

class ParentalSourceV6:
    statement_name = "parental-source-v6"
    xml_tag = "parental_source_v6"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ParentalSourceV6":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ParentalSourceV6":
        if element is None:
            return cls()
        return cls(value=element.text)

class PidFile:
    statement_name = "pid-file"
    xml_tag = "pid_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PidFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PidFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Plugin:
    statement_name = "plugin"
    xml_tag = "plugin"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Plugin":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Plugin":
        if element is None:
            return cls()
        return cls(value=element.text)

class Port:
    statement_name = "port"
    xml_tag = "port"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Port":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Port":
        if element is None:
            return cls()
        return cls(value=element.text)

class PreferServerCiphers:
    statement_name = "prefer-server-ciphers"
    xml_tag = "prefer_server_ciphers"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PreferServerCiphers":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PreferServerCiphers":
        if element is None:
            return cls()
        return cls(value=element.text)

class PreferredGlue:
    statement_name = "preferred-glue"
    xml_tag = "preferred_glue"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PreferredGlue":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PreferredGlue":
        if element is None:
            return cls()
        return cls(value=element.text)

class Prefetch:
    statement_name = "prefetch"
    xml_tag = "prefetch"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Prefetch":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Prefetch":
        if element is None:
            return cls()
        return cls(value=element.text)

class Primaries:
    statement_name = "primaries"
    xml_tag = "primaries"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Primaries":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Primaries":
        if element is None:
            return cls()
        return cls(value=element.text)

class PrintCategory:
    statement_name = "print-category"
    xml_tag = "print_category"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PrintCategory":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PrintCategory":
        if element is None:
            return cls()
        return cls(value=element.text)

class PrintSeverity:
    statement_name = "print-severity"
    xml_tag = "print_severity"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PrintSeverity":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PrintSeverity":
        if element is None:
            return cls()
        return cls(value=element.text)

class PrintTime:
    statement_name = "print-time"
    xml_tag = "print_time"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PrintTime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PrintTime":
        if element is None:
            return cls()
        return cls(value=element.text)

class Protocols:
    statement_name = "protocols"
    xml_tag = "protocols"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Protocols":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Protocols":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ProvideIxfr:
    statement_name = "provide-ixfr"
    xml_tag = "provide_ixfr"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ProvideIxfr":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ProvideIxfr":
        if element is None:
            return cls()
        return cls(value=element.text)

class PublishSafety:
    statement_name = "publish-safety"
    xml_tag = "publish_safety"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PublishSafety":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PublishSafety":
        if element is None:
            return cls()
        return cls(value=element.text)

class PurgeKeys:
    statement_name = "purge-keys"
    xml_tag = "purge_keys"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "PurgeKeys":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "PurgeKeys":
        if element is None:
            return cls()
        return cls(value=element.text)

class QnameMinimization:
    statement_name = "qname-minimization"
    xml_tag = "qname_minimization"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "QnameMinimization":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "QnameMinimization":
        if element is None:
            return cls()
        return cls(value=element.text)

class QpsScale:
    statement_name = "qps-scale"
    xml_tag = "qps_scale"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "QpsScale":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "QpsScale":
        if element is None:
            return cls()
        return cls(value=element.text)

class QuerySource:
    statement_name = "query-source"
    xml_tag = "query_source"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "QuerySource":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "QuerySource":
        if element is None:
            return cls()
        return cls(value=element.text)

class QuerySourceV6:
    statement_name = "query-source-v6"
    xml_tag = "query_source_v6"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "QuerySourceV6":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "QuerySourceV6":
        if element is None:
            return cls()
        return cls(value=element.text)

class Querylog:
    statement_name = "querylog"
    xml_tag = "querylog"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Querylog":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Querylog":
        if element is None:
            return cls()
        return cls(value=element.text)

class RateLimit:
    statement_name = "rate-limit"
    xml_tag = "rate_limit"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "RateLimit":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RateLimit":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class RecursingFile:
    statement_name = "recursing-file"
    xml_tag = "recursing_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RecursingFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RecursingFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Recursion:
    statement_name = "recursion"
    xml_tag = "recursion"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Recursion":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Recursion":
        if element is None:
            return cls()
        return cls(value=element.text)

class RecursiveClients:
    statement_name = "recursive-clients"
    xml_tag = "recursive_clients"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RecursiveClients":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RecursiveClients":
        if element is None:
            return cls()
        return cls(value=element.text)

class RecursiveOnly:
    statement_name = "recursive-only"
    xml_tag = "recursive_only"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RecursiveOnly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RecursiveOnly":
        if element is None:
            return cls()
        return cls(value=element.text)

class ReferralsPerSecond:
    statement_name = "referrals-per-second"
    xml_tag = "referrals_per_second"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ReferralsPerSecond":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ReferralsPerSecond":
        if element is None:
            return cls()
        return cls(value=element.text)

class RemoteHostname:
    statement_name = "remote-hostname"
    xml_tag = "remote_hostname"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RemoteHostname":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RemoteHostname":
        if element is None:
            return cls()
        return cls(value=element.text)

class RequestExpire:
    statement_name = "request-expire"
    xml_tag = "request_expire"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RequestExpire":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RequestExpire":
        if element is None:
            return cls()
        return cls(value=element.text)

class RequestIxfr:
    statement_name = "request-ixfr"
    xml_tag = "request_ixfr"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RequestIxfr":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RequestIxfr":
        if element is None:
            return cls()
        return cls(value=element.text)

class RequestNsid:
    statement_name = "request-nsid"
    xml_tag = "request_nsid"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RequestNsid":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RequestNsid":
        if element is None:
            return cls()
        return cls(value=element.text)

class RequireServerCookie:
    statement_name = "require-server-cookie"
    xml_tag = "require_server_cookie"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RequireServerCookie":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RequireServerCookie":
        if element is None:
            return cls()
        return cls(value=element.text)

class ReservedSockets:
    statement_name = "reserved-sockets"
    xml_tag = "reserved_sockets"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ReservedSockets":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ReservedSockets":
        if element is None:
            return cls()
        return cls(value=element.text)

class ResolverNonbackoffTries:
    statement_name = "resolver-nonbackoff-tries"
    xml_tag = "resolver_nonbackoff_tries"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ResolverNonbackoffTries":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ResolverNonbackoffTries":
        if element is None:
            return cls()
        return cls(value=element.text)

class ResolverQueryTimeout:
    statement_name = "resolver-query-timeout"
    xml_tag = "resolver_query_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ResolverQueryTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ResolverQueryTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class ResolverRetryInterval:
    statement_name = "resolver-retry-interval"
    xml_tag = "resolver_retry_interval"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ResolverRetryInterval":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ResolverRetryInterval":
        if element is None:
            return cls()
        return cls(value=element.text)

class ResponsePadding:
    statement_name = "response-padding"
    xml_tag = "response_padding"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ResponsePadding":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ResponsePadding":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ResponsePolicy:
    statement_name = "response-policy"
    xml_tag = "response_policy"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ResponsePolicy":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ResponsePolicy":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ResponsesPerSecond:
    statement_name = "responses-per-second"
    xml_tag = "responses_per_second"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ResponsesPerSecond":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ResponsesPerSecond":
        if element is None:
            return cls()
        return cls(value=element.text)

class RetireSafety:
    statement_name = "retire-safety"
    xml_tag = "retire_safety"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RetireSafety":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RetireSafety":
        if element is None:
            return cls()
        return cls(value=element.text)

class Reuseport:
    statement_name = "reuseport"
    xml_tag = "reuseport"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Reuseport":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Reuseport":
        if element is None:
            return cls()
        return cls(value=element.text)

class RootDelegationOnly:
    statement_name = "root-delegation-only"
    xml_tag = "root_delegation_only"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "RootDelegationOnly":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RootDelegationOnly":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class RootKeySentinel:
    statement_name = "root-key-sentinel"
    xml_tag = "root_key_sentinel"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "RootKeySentinel":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RootKeySentinel":
        if element is None:
            return cls()
        return cls(value=element.text)

class RrsetOrder:
    statement_name = "rrset-order"
    xml_tag = "rrset_order"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "RrsetOrder":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "RrsetOrder":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Search:
    statement_name = "search"
    xml_tag = "search"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Search":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Search":
        if element is None:
            return cls()
        return cls(value=element.text)

class Secret:
    statement_name = "secret"
    xml_tag = "secret"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Secret":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Secret":
        if element is None:
            return cls()
        return cls(value=element.text)

class SecrootsFile:
    statement_name = "secroots-file"
    xml_tag = "secroots_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SecrootsFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SecrootsFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class SendCookie:
    statement_name = "send-cookie"
    xml_tag = "send_cookie"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SendCookie":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SendCookie":
        if element is None:
            return cls()
        return cls(value=element.text)

class SerialQueryRate:
    statement_name = "serial-query-rate"
    xml_tag = "serial_query_rate"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SerialQueryRate":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SerialQueryRate":
        if element is None:
            return cls()
        return cls(value=element.text)

class SerialUpdateMethod:
    statement_name = "serial-update-method"
    xml_tag = "serial_update_method"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SerialUpdateMethod":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SerialUpdateMethod":
        if element is None:
            return cls()
        return cls(value=element.text)

class Server:
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
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Server":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Server":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ServerAddresses:
    statement_name = "server-addresses"
    xml_tag = "server_addresses"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ServerAddresses":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ServerAddresses":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ServerId:
    statement_name = "server-id"
    xml_tag = "server_id"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ServerId":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ServerId":
        if element is None:
            return cls()
        return cls(value=element.text)

class ServerNames:
    statement_name = "server-names"
    xml_tag = "server_names"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ServerNames":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ServerNames":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class ServfailTtl:
    statement_name = "servfail-ttl"
    xml_tag = "servfail_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ServfailTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ServfailTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class SessionKeyalg:
    statement_name = "session-keyalg"
    xml_tag = "session_keyalg"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SessionKeyalg":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SessionKeyalg":
        if element is None:
            return cls()
        return cls(value=element.text)

class SessionKeyfile:
    statement_name = "session-keyfile"
    xml_tag = "session_keyfile"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SessionKeyfile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SessionKeyfile":
        if element is None:
            return cls()
        return cls(value=element.text)

class SessionKeyname:
    statement_name = "session-keyname"
    xml_tag = "session_keyname"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SessionKeyname":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SessionKeyname":
        if element is None:
            return cls()
        return cls(value=element.text)

class SessionTickets:
    statement_name = "session-tickets"
    xml_tag = "session_tickets"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SessionTickets":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SessionTickets":
        if element is None:
            return cls()
        return cls(value=element.text)

class Severity:
    statement_name = "severity"
    xml_tag = "severity"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Severity":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Severity":
        if element is None:
            return cls()
        return cls(value=element.text)

class SigSigningNodes:
    statement_name = "sig-signing-nodes"
    xml_tag = "sig_signing_nodes"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SigSigningNodes":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SigSigningNodes":
        if element is None:
            return cls()
        return cls(value=element.text)

class SigSigningSignatures:
    statement_name = "sig-signing-signatures"
    xml_tag = "sig_signing_signatures"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SigSigningSignatures":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SigSigningSignatures":
        if element is None:
            return cls()
        return cls(value=element.text)

class SigSigningType:
    statement_name = "sig-signing-type"
    xml_tag = "sig_signing_type"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SigSigningType":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SigSigningType":
        if element is None:
            return cls()
        return cls(value=element.text)

class SigValidityInterval:
    statement_name = "sig-validity-interval"
    xml_tag = "sig_validity_interval"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SigValidityInterval":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SigValidityInterval":
        if element is None:
            return cls()
        return cls(value=element.text)

class SignaturesRefresh:
    statement_name = "signatures-refresh"
    xml_tag = "signatures_refresh"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SignaturesRefresh":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SignaturesRefresh":
        if element is None:
            return cls()
        return cls(value=element.text)

class SignaturesValidity:
    statement_name = "signatures-validity"
    xml_tag = "signatures_validity"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SignaturesValidity":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SignaturesValidity":
        if element is None:
            return cls()
        return cls(value=element.text)

class SignaturesValidityDnskey:
    statement_name = "signatures-validity-dnskey"
    xml_tag = "signatures_validity_dnskey"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SignaturesValidityDnskey":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SignaturesValidityDnskey":
        if element is None:
            return cls()
        return cls(value=element.text)

class Slip:
    statement_name = "slip"
    xml_tag = "slip"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Slip":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Slip":
        if element is None:
            return cls()
        return cls(value=element.text)

class Sortlist:
    statement_name = "sortlist"
    xml_tag = "sortlist"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Sortlist":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Sortlist":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Stacksize:
    statement_name = "stacksize"
    xml_tag = "stacksize"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Stacksize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Stacksize":
        if element is None:
            return cls()
        return cls(value=element.text)

class StaleAnswerClientTimeout:
    statement_name = "stale-answer-client-timeout"
    xml_tag = "stale_answer_client_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StaleAnswerClientTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StaleAnswerClientTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class StaleAnswerEnable:
    statement_name = "stale-answer-enable"
    xml_tag = "stale_answer_enable"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StaleAnswerEnable":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StaleAnswerEnable":
        if element is None:
            return cls()
        return cls(value=element.text)

class StaleAnswerTtl:
    statement_name = "stale-answer-ttl"
    xml_tag = "stale_answer_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StaleAnswerTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StaleAnswerTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class StaleCacheEnable:
    statement_name = "stale-cache-enable"
    xml_tag = "stale_cache_enable"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StaleCacheEnable":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StaleCacheEnable":
        if element is None:
            return cls()
        return cls(value=element.text)

class StaleRefreshTime:
    statement_name = "stale-refresh-time"
    xml_tag = "stale_refresh_time"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StaleRefreshTime":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StaleRefreshTime":
        if element is None:
            return cls()
        return cls(value=element.text)

class StartupNotifyRate:
    statement_name = "startup-notify-rate"
    xml_tag = "startup_notify_rate"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StartupNotifyRate":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StartupNotifyRate":
        if element is None:
            return cls()
        return cls(value=element.text)

class StatisticsChannels:
    statement_name = "statistics-channels"
    ALLOWED_STATEMENTS = [
        "inet",
    ]

    xml_tag = "statistics_channels"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "StatisticsChannels":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StatisticsChannels":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class StatisticsFile:
    statement_name = "statistics-file"
    xml_tag = "statistics_file"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StatisticsFile":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StatisticsFile":
        if element is None:
            return cls()
        return cls(value=element.text)

class Stderr:
    statement_name = "stderr"
    xml_tag = "stderr"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Stderr":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Stderr":
        if element is None:
            return cls()
        return cls(value=element.text)

class StreamsPerConnection:
    statement_name = "streams-per-connection"
    xml_tag = "streams_per_connection"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "StreamsPerConnection":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "StreamsPerConnection":
        if element is None:
            return cls()
        return cls(value=element.text)

class Suffix:
    statement_name = "suffix"
    xml_tag = "suffix"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Suffix":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Suffix":
        if element is None:
            return cls()
        return cls(value=element.text)

class SynthFromDnssec:
    statement_name = "synth-from-dnssec"
    xml_tag = "synth_from_dnssec"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "SynthFromDnssec":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "SynthFromDnssec":
        if element is None:
            return cls()
        return cls(value=element.text)

class Syslog:
    statement_name = "syslog"
    xml_tag = "syslog"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Syslog":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Syslog":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpAdvertisedTimeout:
    statement_name = "tcp-advertised-timeout"
    xml_tag = "tcp_advertised_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpAdvertisedTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpAdvertisedTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpClients:
    statement_name = "tcp-clients"
    xml_tag = "tcp_clients"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpClients":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpClients":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpIdleTimeout:
    statement_name = "tcp-idle-timeout"
    xml_tag = "tcp_idle_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpIdleTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpIdleTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpInitialTimeout:
    statement_name = "tcp-initial-timeout"
    xml_tag = "tcp_initial_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpInitialTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpInitialTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpKeepalive:
    statement_name = "tcp-keepalive"
    xml_tag = "tcp_keepalive"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpKeepalive":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpKeepalive":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpKeepaliveTimeout:
    statement_name = "tcp-keepalive-timeout"
    xml_tag = "tcp_keepalive_timeout"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpKeepaliveTimeout":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpKeepaliveTimeout":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpListenQueue:
    statement_name = "tcp-listen-queue"
    xml_tag = "tcp_listen_queue"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpListenQueue":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpListenQueue":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class TcpOnly:
    statement_name = "tcp-only"
    xml_tag = "tcp_only"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpOnly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpOnly":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpReceiveBuffer:
    statement_name = "tcp-receive-buffer"
    xml_tag = "tcp_receive_buffer"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpReceiveBuffer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpReceiveBuffer":
        if element is None:
            return cls()
        return cls(value=element.text)

class TcpSendBuffer:
    statement_name = "tcp-send-buffer"
    xml_tag = "tcp_send_buffer"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TcpSendBuffer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TcpSendBuffer":
        if element is None:
            return cls()
        return cls(value=element.text)

class TkeyDhkey:
    statement_name = "tkey-dhkey"
    xml_tag = "tkey_dhkey"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TkeyDhkey":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TkeyDhkey":
        if element is None:
            return cls()
        return cls(value=element.text)

class TkeyDomain:
    statement_name = "tkey-domain"
    xml_tag = "tkey_domain"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TkeyDomain":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TkeyDomain":
        if element is None:
            return cls()
        return cls(value=element.text)

class TkeyGssapiCredential:
    statement_name = "tkey-gssapi-credential"
    xml_tag = "tkey_gssapi_credential"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TkeyGssapiCredential":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TkeyGssapiCredential":
        if element is None:
            return cls()
        return cls(value=element.text)

class TkeyGssapiKeytab:
    statement_name = "tkey-gssapi-keytab"
    xml_tag = "tkey_gssapi_keytab"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TkeyGssapiKeytab":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TkeyGssapiKeytab":
        if element is None:
            return cls()
        return cls(value=element.text)

class Tls:
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
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Tls":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Tls":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class TlsPort:
    statement_name = "tls-port"
    xml_tag = "tls_port"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TlsPort":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TlsPort":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransferFormat:
    statement_name = "transfer-format"
    xml_tag = "transfer_format"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransferFormat":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransferFormat":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransferMessageSize:
    statement_name = "transfer-message-size"
    xml_tag = "transfer_message_size"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransferMessageSize":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransferMessageSize":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransferSource:
    statement_name = "transfer-source"
    xml_tag = "transfer_source"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransferSource":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransferSource":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransferSourceV6:
    statement_name = "transfer-source-v6"
    xml_tag = "transfer_source_v6"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransferSourceV6":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransferSourceV6":
        if element is None:
            return cls()
        return cls(value=element.text)

class Transfers:
    statement_name = "transfers"
    xml_tag = "transfers"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Transfers":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Transfers":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransfersIn:
    statement_name = "transfers-in"
    xml_tag = "transfers_in"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransfersIn":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransfersIn":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransfersOut:
    statement_name = "transfers-out"
    xml_tag = "transfers_out"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransfersOut":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransfersOut":
        if element is None:
            return cls()
        return cls(value=element.text)

class TransfersPerNs:
    statement_name = "transfers-per-ns"
    xml_tag = "transfers_per_ns"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TransfersPerNs":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TransfersPerNs":
        if element is None:
            return cls()
        return cls(value=element.text)

class TrustAnchorTelemetry:
    statement_name = "trust-anchor-telemetry"
    xml_tag = "trust_anchor_telemetry"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TrustAnchorTelemetry":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TrustAnchorTelemetry":
        if element is None:
            return cls()
        return cls(value=element.text)

class TrustAnchors:
    statement_name = "trust-anchors"
    xml_tag = "trust_anchors"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "TrustAnchors":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TrustAnchors":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class TrustedKeys:
    statement_name = "trusted-keys"
    xml_tag = "trusted_keys"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "TrustedKeys":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TrustedKeys":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class TryTcpRefresh:
    statement_name = "try-tcp-refresh"
    xml_tag = "try_tcp_refresh"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TryTcpRefresh":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TryTcpRefresh":
        if element is None:
            return cls()
        return cls(value=element.text)

class Type:
    statement_name = "type"
    xml_tag = "type"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Type":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Type":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class TypeDelegationOnly:
    statement_name = "type delegation-only"
    xml_tag = "type delegation_only"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeDelegationOnly":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeDelegationOnly":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeForward:
    statement_name = "type forward"
    xml_tag = "type forward"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeForward":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeForward":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeHint:
    statement_name = "type hint"
    xml_tag = "type hint"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeHint":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeHint":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeMirror:
    statement_name = "type mirror"
    xml_tag = "type mirror"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeMirror":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeMirror":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypePrimary:
    statement_name = "type primary"
    xml_tag = "type primary"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypePrimary":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypePrimary":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeRedirect:
    statement_name = "type redirect"
    xml_tag = "type redirect"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeRedirect":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeRedirect":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeSecondary:
    statement_name = "type secondary"
    xml_tag = "type secondary"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeSecondary":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeSecondary":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeStaticStub:
    statement_name = "type static-stub"
    xml_tag = "type static_stub"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeStaticStub":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeStaticStub":
        if element is None:
            return cls()
        return cls(value=element.text)

class TypeStub:
    statement_name = "type stub"
    xml_tag = "type stub"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "TypeStub":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "TypeStub":
        if element is None:
            return cls()
        return cls(value=element.text)

class UdpReceiveBuffer:
    statement_name = "udp-receive-buffer"
    xml_tag = "udp_receive_buffer"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "UdpReceiveBuffer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UdpReceiveBuffer":
        if element is None:
            return cls()
        return cls(value=element.text)

class UdpSendBuffer:
    statement_name = "udp-send-buffer"
    xml_tag = "udp_send_buffer"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "UdpSendBuffer":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UdpSendBuffer":
        if element is None:
            return cls()
        return cls(value=element.text)

class Unix:
    statement_name = "unix"
    xml_tag = "unix"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Unix":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Unix":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class UpdateCheckKsk:
    statement_name = "update-check-ksk"
    xml_tag = "update_check_ksk"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "UpdateCheckKsk":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UpdateCheckKsk":
        if element is None:
            return cls()
        return cls(value=element.text)

class UpdatePolicy:
    statement_name = "update-policy"
    xml_tag = "update_policy"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "UpdatePolicy":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UpdatePolicy":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class UpdateQuota:
    statement_name = "update-quota"
    xml_tag = "update_quota"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "UpdateQuota":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UpdateQuota":
        if element is None:
            return cls()
        return cls(value=element.text)

class UseAltTransferSource:
    statement_name = "use-alt-transfer-source"
    xml_tag = "use_alt_transfer_source"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "UseAltTransferSource":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UseAltTransferSource":
        if element is None:
            return cls()
        return cls(value=element.text)

class UseV4UdpPorts:
    statement_name = "use-v4-udp-ports"
    xml_tag = "use_v4_udp_ports"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "UseV4UdpPorts":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UseV4UdpPorts":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class UseV6UdpPorts:
    statement_name = "use-v6-udp-ports"
    xml_tag = "use_v6_udp_ports"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "UseV6UdpPorts":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "UseV6UdpPorts":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class V6Bias:
    statement_name = "v6-bias"
    xml_tag = "v6_bias"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "V6Bias":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "V6Bias":
        if element is None:
            return cls()
        return cls(value=element.text)

class ValidateExcept:
    statement_name = "validate-except"
    xml_tag = "validate_except"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "ValidateExcept":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ValidateExcept":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Version:
    statement_name = "version"
    xml_tag = "version"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Version":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Version":
        if element is None:
            return cls()
        return cls(value=element.text)

class View:
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
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        self.elements = elements or []

    def add(self, element: str) -> None:
        self.elements.append(element)

    def remove(self, element: str) -> None:
        self.elements = [item for item in self.elements if item != element]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "View":
        if isinstance(data, list):
            return cls(elements=list(data))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "View":
        if element is None:
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        return cls(elements=items)

class Window:
    statement_name = "window"
    xml_tag = "window"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Window":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Window":
        if element is None:
            return cls()
        return cls(value=element.text)

class ZeroNoSoaTtl:
    statement_name = "zero-no-soa-ttl"
    xml_tag = "zero_no_soa_ttl"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ZeroNoSoaTtl":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ZeroNoSoaTtl":
        if element is None:
            return cls()
        return cls(value=element.text)

class ZeroNoSoaTtlCache:
    statement_name = "zero-no-soa-ttl-cache"
    xml_tag = "zero_no_soa_ttl_cache"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ZeroNoSoaTtlCache":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ZeroNoSoaTtlCache":
        if element is None:
            return cls()
        return cls(value=element.text)

class Zone:
    ALLOWED_STATEMENTS: List[str] = []

    def __init__(
        self,
        value: Optional[str] = None,
        statements: Optional[Dict[str, List[object]]] = None,
    ) -> None:
        self.value = value
        self._statements: Dict[str, List[object]] = statements or {}

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def allowed_statements(cls) -> List[str]:
        return list(cls.ALLOWED_STATEMENTS)

    def _statement_name(self, statement: object) -> str:
        if isinstance(statement, str):
            return statement
        name = getattr(statement, "statement_name", None)
        if not name:
            raise ValueError("Unknown statement object: missing statement_name")
        return str(name)

    def _ensure_allowed(self, name: str) -> None:
        if name not in self.ALLOWED_STATEMENTS:
            raise ValueError(f"Statement '{name}' not allowed for {self.__class__.__name__}")

    def insert_statement(self, statement: object) -> None:
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        self._statements.setdefault(name, []).append(statement)

    def update_statement(self, statement: object, index: int = 0) -> None:
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        bucket = self._statements.setdefault(name, [])
        if index < 0 or index >= len(bucket):
            raise IndexError("statement index out of range")
        bucket[index] = statement

    def delete_statement(self, statement: object, index: int = 0) -> None:
        name = self._statement_name(statement)
        self._ensure_allowed(name)
        bucket = self._statements.get(name, [])
        if not bucket:
            return
        if index < 0 or index >= len(bucket):
            raise IndexError("statement index out of range")
        bucket.pop(index)
        if not bucket:
            self._statements.pop(name, None)

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "Zone":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Zone":
        if element is None:
            return cls()
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

class ZoneMaster(Zone):
    zone_type = "master"
    ALLOWED_STATEMENTS = ZonePrimary.ALLOWED_STATEMENTS

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

class ZoneSlave(Zone):
    zone_type = "slave"
    ALLOWED_STATEMENTS = ZoneSecondary.ALLOWED_STATEMENTS

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

class ZoneDelegationOnly(Zone):
    zone_type = "delegation-only"
    ALLOWED_STATEMENTS = [
        "type",
    ]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

class ZoneInView(Zone):
    zone_type = "in-view"
    ALLOWED_STATEMENTS = [
        "in-view",
        "forward",
        "forwarders",
    ]

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

class ZonePropagationDelay:
    statement_name = "zone-propagation-delay"
    xml_tag = "zone_propagation_delay"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ZonePropagationDelay":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ZonePropagationDelay":
        if element is None:
            return cls()
        return cls(value=element.text)

class ZoneStatistics:
    statement_name = "zone-statistics"
    xml_tag = "zone_statistics"
    def __init__(self, value: Optional[str] = None) -> None:
        self.value = value

    def set_value(self, value: Optional[str]) -> None:
        self.value = value

    @classmethod
    def fromText(cls, text: str):
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
                return cls(statements=statements)
            except TypeError:
                return cls()
        if hasattr(cls, "elements"):
            body = _extract_statement_body(cleaned)
            elements = _split_statement_texts(body)
            return cls(elements=elements)
        value = cleaned
        if hasattr(cls, "statement_name") and cleaned.startswith(cls.statement_name):
            value = cleaned[len(cls.statement_name):].strip()
        if value == "":
            value = None
        return cls(value=value)

    def to_dict(self) -> dict:
        return {"value": self.value}

    @classmethod
    def from_dict(cls, data: dict) -> "ZoneStatistics":
        if isinstance(data, str) or data is None:
            return cls(value=data)
        return cls(value=data.get("value"))

    def to_xml_element(self) -> ET.Element:
        element = ET.Element(self.xml_tag)
        if self.value is not None:
            element.text = str(self.value)
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "ZoneStatistics":
        if element is None:
            return cls()
        return cls(value=element.text)
