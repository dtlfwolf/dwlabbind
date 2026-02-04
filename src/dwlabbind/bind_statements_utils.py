"""Shared parsing helpers for bind statements."""

from __future__ import annotations

import re


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


def _class_accepts_param(cls, name: str) -> bool:
    try:
        params = cls.__init__.__code__.co_varnames
    except Exception:
        return False
    return name in params
