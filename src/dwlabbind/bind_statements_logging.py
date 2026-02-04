"""Logging statement class."""

from __future__ import annotations

import logging
import sys
from typing import Dict, List, Optional

from .bind_statements_utils import _extract_statement_body, _split_statement_texts, _statement_class_for_name, _class_accepts_param

logger = logging.getLogger(__name__)

class Logging:
    statement_name = "logging"
    ALLOWED_STATEMENTS = [
        "category",
        "channel",
    ]

    xml_tag = "logging"
    def __init__(self, elements: Optional[List[str]] = None) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.elements = elements or []

        logger.debug("Leaving function "+str(function_name))
    def add(self, element: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.elements.append(element)

        logger.debug("Leaving function "+str(function_name))
    def remove(self, element: str) -> None:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        self.elements = [item for item in self.elements if item != element]

        logger.debug("Leaving function "+str(function_name))
    @classmethod
    def fromText(cls, text: str):
        function_name = sys._getframe().f_code.co_name
        class_name="Logging"
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
        return {"elements": list(self.elements)}

    @classmethod
    def from_dict(cls, data: dict) -> "Logging":
        function_name = sys._getframe().f_code.co_name
        class_name="Logging"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if isinstance(data, list):
            logger.debug("Leaving function "+str(function_name))
            return cls(elements=list(data))
        logger.debug("Leaving function "+str(function_name))
        return cls(elements=list(data.get("elements", [])))

    def to_xml_element(self) -> ET.Element:
        function_name = sys._getframe().f_code.co_name
        class_name=self.__class__.__name__
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        element = ET.Element(self.xml_tag)
        for item in self.elements:
            entry = ET.SubElement(element, "value")
            entry.text = item
        logger.debug("Leaving function "+str(function_name))
        return element

    @classmethod
    def from_xml_element(cls, element: Optional[ET.Element]) -> "Logging":
        function_name = sys._getframe().f_code.co_name
        class_name="Logging"
        function_name=class_name+"."+function_name
        logger.debug("Entering function "+str(function_name))
        if element is None:
            logger.debug("Leaving function "+str(function_name))
            return cls()
        items = [item.text or "" for item in element.findall("value")]
        if not items and element.text:
            items = [element.text]
        logger.debug("Leaving function "+str(function_name))
        return cls(elements=items)

