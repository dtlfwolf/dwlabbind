"""Core BIND configuration containers (skeleton)."""

from __future__ import annotations

from typing import Iterable, List, Optional
import sys
import os
import re
import tarfile
import xml.etree.ElementTree as ET

import dwlabbind.bind_statements as BS

import logging
from dwlabbasicpy import dwlabLogger
dwlabLogger.setup_logging()
logger=logging.getLogger(__name__)
__PACKAGE_NAME__ = "bind_conf"


class BindServer:
    def __init__(
        self,
        name: str,
        zone_files: Optional[List["BindZoneFile"]] = None,
        options: Optional["BindOptionsFile"] = None,
        hosts_files: Optional[List["BindZoneHostsFile"]] = None,
    ) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.name = name
        self.zone_files = zone_files or []
        self.options = options
        self.hosts_files = hosts_files or []
        self.source_path: Optional[str] = None
        self._source_files: List[str] = []
        logger.debug("Leaving function "+str(function_name))

    @classmethod
    def readConf(cls, filename: Optional[str] = None) -> "BindServer":
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

    def to_xml(self, path: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        root = ET.Element("bind_server")
        if self.source_path:
            root.set("source", self.source_path)
        zones_el = ET.SubElement(root, "zones")
        for zone in self.zone_files:
            zones_el.append(zone.to_xml_element())
        if self.options:
            root.append(self.options.to_xml_element())
        tree = ET.ElementTree(root)
        tree.write(path, encoding="utf-8", xml_declaration=True)

        logger.debug("Leaving function "+str(function_name))

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

    def import_to_xml(self, named_conf: Optional[str] = None) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        server = self.readConf(named_conf)
        base_dir = os.path.dirname(server.source_path or "")
        output_path = os.path.join(base_dir, "dwlabbind.xml")
        server.to_xml(output_path)

        logger.debug("Leaving function "+str(function_name))
        return output_path

    def _parse_named_conf(self, path: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        base_dir = os.path.dirname(path)
        seen_files: set[str] = set()
        self._parse_into(path, base_dir=base_dir, seen_files=seen_files)

        logger.debug("Leaving function "+str(function_name))

    def _parse_into(self, path: str, base_dir: str, seen_files: set[str]) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        print(f"Handling file: {path}")
        text = self._read_file(path, seen_files)
        if path not in self._source_files:
            self._source_files.append(path)
        cleaned = self._strip_comments(text)
        for include_path in self._extract_includes(cleaned, base_dir):
            print(f"Detected include: {include_path}")
            self._parse_into(include_path, base_dir=base_dir, seen_files=seen_files)
        options_block = self._extract_block(cleaned, "options")
        if options_block:
            print(f"Detected options block in: {path}")
            self.options = BindOptionsFile.fromText(options_block)
        for block in self._extract_zone_blocks(cleaned):
            zone_obj = self._parse_zone_block(block)
            if zone_obj:
                print(f"Detected zone: {zone_obj.zone_name}")
                self.zone_files.append(zone_obj)

        logger.debug("Leaving function "+str(function_name))

    def _read_file(self, path: str, seen_files: set[str]) -> str:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        real = os.path.abspath(path)
        if real in seen_files:
            return ""
        seen_files.add(real)
        with open(real, "r", encoding="utf-8") as handle:
            return handle.read()

        logger.debug("Leaving function "+str(function_name))

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

    def _extract_block(self, text: str, keyword: str) -> Optional[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        match = re.search(rf"\b{re.escape(keyword)}\b\s*{{", text, re.I)
        if not match:
            return None
        start = match.end()
        depth = 1
        idx = start
        while idx < len(text) and depth > 0:
            if text[idx] == "{":
                depth += 1
            elif text[idx] == "}":
                depth -= 1
            idx += 1
        if depth != 0:
            return None

        logger.debug("Leaving function "+str(function_name))
        return text[start:idx - 1].strip()

    def _extract_zone_blocks(self, text: str) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        blocks: List[str] = []
        for match in re.finditer(r'zone\s+"([^"]+)"\s*{', text, re.I):
            start = match.end()
            depth = 1
            idx = start
            while idx < len(text) and depth > 0:
                if text[idx] == "{":
                    depth += 1
                elif text[idx] == "}":
                    depth -= 1
                idx += 1
            if depth == 0:
                block = text[match.start():idx]
                blocks.append(block)

        logger.debug("Leaving function "+str(function_name))
        return blocks

    def _parse_zone_block(self, block: str) -> Optional["BindZoneFile"]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        name_match = re.search(r'zone\s+"([^"]+)"', block, re.I)
        if not name_match:

            logger.debug("Leaving function "+str(function_name))
            return None
        zone_name = name_match.group(1)
        type_match = re.search(r"\btype\s+([^;]+);", block, re.I)
        zone_type = type_match.group(1).strip().strip('"') if type_match else ""
        file_match = re.search(r'\bfile\s+"([^"]+)"\s*;', block, re.I)
        zone_file = file_match.group(1) if file_match else None
        if zone_file and not os.path.isabs(zone_file) and self.source_path:
            zone_file = os.path.join(os.path.dirname(self.source_path), zone_file)
        type_map = {
            "primary": BS.ZonePrimary,
            "master": BS.ZoneMaster,
            "secondary": BS.ZoneSecondary,
            "slave": BS.ZoneSlave,
            "mirror": BS.ZoneMirror,
            "hint": BS.ZoneHint,
            "stub": BS.ZoneStub,
            "static-stub": BS.ZoneStaticStub,
            "forward": BS.ZoneForward,
            "redirect": BS.ZoneRedirect,
            "delegation-only": BS.ZoneDelegationOnly,
            "in-view": BS.ZoneInView,
        }
        zone_cls = type_map.get(zone_type, BS.Zone)
        zone_body = BS._extract_statement_body(block)
        try:
            zone_cls.fromText(zone_body)
        except Exception:
            pass

        logger.debug("Leaving function "+str(function_name))
        return BindZoneFile(zone_name=zone_name, zone_type=zone_type or None, file_path=zone_file)

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
        for zone in self.zone_files:
            if zone.file_path and zone.file_path not in files:
                files.append(zone.file_path)

        logger.debug("Leaving function "+str(function_name))
        return files

class BindZoneFile:
    def __init__(self, zone_name: str, zone_type: Optional[str] = None, file_path: Optional[str] = None) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.zone_name = zone_name
        self.zone_type = zone_type
        self.file_path = file_path

        logger.debug("Leaving function "+str(function_name))

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        element = ET.Element("zone")
        element.set("name", self.zone_name)
        if self.zone_type:
            element.set("type", self.zone_type)
        if self.file_path:
            element.set("file", self.file_path)

        logger.debug("Leaving function "+str(function_name))
        return element


class BindZoneHostsFile:
    def __init__(self, zone_name: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.zone_name = zone_name

        logger.debug("Leaving function "+str(function_name))


class BindOptionsFile:
    def __init__(self, options: Optional[BS.Options] = None) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        self.options = options

        logger.debug("Leaving function "+str(function_name))

    @classmethod
    def fromText(cls, text: str) -> "BindOptionsFile":
        function_name = sys._getframe().f_code.co_name
        class_name="BindOptionsFile"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        options = BS.Options.fromText(text)

        logger.debug("Leaving function "+str(function_name))
        return cls(options=options)

    def list_statements(self) -> List[str]:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        if not self.options:
            logger.debug("Leaving function "+str(function_name))
            return 
        result = self.options.allowed_statements()

        logger.debug("Leaving function "+str(function_name))
        return result

    def insert_statement(self, statement: object) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        if not self.options:
            self.options = BS.Options()
        self.options.insert_statement(statement)

        logger.debug("Leaving function "+str(function_name))

    def update_statement(self, statement: object, index: int = 0) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        if not self.options:
            self.options = BS.Options()
        self.options.update_statement(statement, index=index)

        logger.debug("Leaving function "+str(function_name))

    def delete_statement(self, statement: object, index: int = 0) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        if not self.options:
            logger.debug("No options to delete from.")
            logger.debug("Leaving function "+str(function_name))
            return
        self.options.delete_statement(statement, index=index)

        logger.debug("Leaving function "+str(function_name))

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))

        element = ET.Element("options")

        logger.debug("Leaving function "+str(function_name))
        return element


def backup_named_conf(named_conf: str, output_tar: str) -> str:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.readConf(named_conf)

    logger.debug("Leaving function "+str(function_name))
    return server.backup(output_tar)


def import_named_conf(named_conf: str) -> str:
    function_name = sys._getframe().f_code.co_name
    package_name = __PACKAGE_NAME__
    function_name=package_name+"."+function_name
    logger.debug("Entering function "+str(function_name))

    server = BindServer.readConf(named_conf)
    print("Referenced files:")
    for ref in server._collect_referenced_files():
        print(f" - {ref}")
    base_dir = os.path.dirname(server.source_path or "")
    output_path = os.path.join(base_dir, "dwlabbind.xml")
    server.to_xml(output_path)

    logger.debug("Leaving function "+str(function_name))
    return output_path
