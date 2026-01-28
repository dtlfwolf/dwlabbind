"""XML persistence for bind server configuration."""

from __future__ import annotations

from typing import Optional
import os
import sys
import xml.etree.ElementTree as ET

from .models import BindServer


class XmlConfigStore:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or self.default_path()

    @staticmethod
    def default_path() -> str:
        override = os.environ.get("DWLABBIND_CONFIG")
        if override:
            return os.path.expanduser(override)
        if os.name == "nt":
            base = os.environ.get("APPDATA") or os.path.expanduser("~")
            return os.path.join(base, "dwlabbind", "bind.xml")
        if sys_platform() == "darwin":
            base = os.path.expanduser("~/Library/Application Support")
            return os.path.join(base, "dwlabbind", "bind.xml")
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        return os.path.join(base, "dwlabbind", "bind.xml")

    def save(self, server: BindServer) -> None:
        root = server.to_xml_element()
        tree = ET.ElementTree(root)
        self._indent_xml(root)
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tree.write(self.path, encoding="utf-8", xml_declaration=True)

    def load(self) -> Optional[BindServer]:
        try:
            tree = ET.parse(self.path)
        except FileNotFoundError:
            return None
        root = tree.getroot()
        return BindServer.from_xml_element(root)

    def _indent_xml(self, element: ET.Element, level: int = 0) -> None:
        indent = "\n" + ("  " * level)
        if len(element):
            if not element.text or not element.text.strip():
                element.text = indent + "  "
            for child in element:
                self._indent_xml(child, level + 1)
            if not child.tail or not child.tail.strip():
                child.tail = indent
        if level and (not element.tail or not element.tail.strip()):
            element.tail = indent


def sys_platform() -> str:
    return sys.platform.lower()
