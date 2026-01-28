"""Import DNS server configurations into dwlabbind models."""

from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .models import BindServer, BindZone, NameServerProfile, OptionsConfig


class Bind9Importer:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self.base_dir = os.path.dirname(config_path)

    def import_server(
        self,
        name: str,
        ip: str,
        port: int = 53,
        role: str = "master",
        version: str = "",
    ) -> BindServer:
        zones = self._collect_zones()
        options = self._collect_options()
        profile = NameServerProfile(server_type="bind9", version=version)
        return BindServer(
            name=name,
            ip=ip,
            port=port,
            role=role,
            zones=zones,
            options=options,
            server_profile=profile,
        )

    def _collect_zones(self) -> List[BindZone]:
        zones: List[BindZone] = []
        for conf_path in self._collect_conf_files():
            text = self._read_text(conf_path)
            zones.extend(self._parse_zone_stanzas(text, conf_path))
        return zones

    def _collect_options(self) -> OptionsConfig:
        options = OptionsConfig()
        for conf_path in self._collect_conf_files():
            text = self._read_text(conf_path)
            for body in self._parse_options_blocks(text):
                for name, value in self._parse_option_entries(body).items():
                    options.add_option(name, value)
        return options

    def _collect_conf_files(self) -> List[str]:
        start = self.config_path
        queue: List[str] = [start]
        seen: Set[str] = set()
        result: List[str] = []

        while queue:
            path = queue.pop(0)
            if not os.path.exists(path) or path in seen:
                continue
            seen.add(path)
            result.append(path)
            text = self._read_text(path)
            for inc in self._parse_includes(text):
                inc_path = inc
                if not os.path.isabs(inc_path):
                    inc_path = os.path.join(self.base_dir, inc_path)
                if os.path.isdir(inc_path):
                    for conf in sorted(self._glob_conf_files(inc_path)):
                        queue.append(conf)
                else:
                    queue.append(inc_path)
        return result

    def _parse_includes(self, text: str) -> List[str]:
        includes: List[str] = []
        for match in re.finditer(r"^\s*include\s+\"([^\"]+)\"", text, re.M):
            includes.append(match.group(1))
        return includes

    def _parse_zone_stanzas(self, text: str, conf_path: str) -> List[BindZone]:
        zones: List[BindZone] = []
        for match in re.finditer(r"zone\s+\"([^\"]+)\"\s*{(.*?)};", text, re.S):
            zone_name = match.group(1)
            body = match.group(2)
            zone_type = self._parse_value(body, r"\btype\s+([^;]+);") or "master"
            file_path = self._parse_value(body, r"\bfile\s+\"([^\"]+)\";") or ""
            if file_path and not os.path.isabs(file_path):
                file_path = os.path.join(self.base_dir, file_path)
            masters = self._parse_list_block(body, "masters")
            allow_update = bool(re.search(r"allow-update\s*{", body))
            if zone_name and file_path:
                zones.append(
                    BindZone(
                        name=zone_name,
                        zone_type=zone_type.strip(),
                        file=file_path,
                        masters=masters,
                        allow_update=allow_update,
                    )
                )
        return zones

    def _parse_options_blocks(self, text: str) -> List[str]:
        cleaned = self._strip_comments(text)
        return self._extract_blocks(cleaned, "options")

    def _parse_option_entries(self, body: str) -> Dict[str, str]:
        entries: Dict[str, str] = {}
        cleaned = self._strip_comments(body)
        for statement in self._split_statements(cleaned):
            parts = statement.split(None, 1)
            if len(parts) != 2:
                continue
            name, value = parts
            entries[name] = value.strip()
        return entries

    def _parse_value(self, body: str, pattern: str) -> Optional[str]:
        match = re.search(pattern, body, re.S)
        if not match:
            return None
        return match.group(1).strip()

    def _parse_list_block(self, body: str, keyword: str) -> List[str]:
        match = re.search(rf"{keyword}\s*{{(.*?)}};", body, re.S)
        if not match:
            return []
        items = []
        for line in match.group(1).split(";"):
            value = line.strip()
            if value:
                items.append(value)
        return items

    def _strip_comments(self, text: str) -> str:
        text = re.sub(r"//.*", "", text)
        text = re.sub(r"#.*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        return text

    def _read_text(self, path: str) -> str:
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def _glob_conf_files(self, directory: str) -> Iterable[str]:
        for entry in os.listdir(directory):
            if entry.endswith(".conf"):
                yield os.path.join(directory, entry)

    def _extract_blocks(self, text: str, keyword: str) -> List[str]:
        blocks: List[str] = []
        pattern = re.compile(rf"\\b{re.escape(keyword)}\\b\\s*{{")
        index = 0
        while True:
            match = pattern.search(text, index)
            if not match:
                break
            brace_start = match.end() - 1
            body, end_index = self._read_brace_block(text, brace_start)
            blocks.append(body)
            index = end_index
        return blocks

    def _read_brace_block(self, text: str, brace_start: int) -> Tuple[str, int]:
        depth = 0
        for idx in range(brace_start, len(text)):
            char = text[idx]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_start + 1 : idx], idx + 1
        return text[brace_start + 1 :], len(text)

    def _split_statements(self, text: str) -> List[str]:
        statements: List[str] = []
        current: List[str] = []
        depth = 0
        for char in text:
            if char == "{":
                depth += 1
            elif char == "}":
                depth = max(depth - 1, 0)
            if char == ";" and depth == 0:
                statement = "".join(current).strip()
                if statement:
                    statements.append(statement)
                current = []
                continue
            current.append(char)
        statement = "".join(current).strip()
        if statement:
            statements.append(statement)
        return statements


class PowerDnsImporter:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self.base_dir = os.path.dirname(config_path)

    def import_server(
        self,
        name: str,
        ip: str,
        port: int = 53,
        role: str = "master",
        version: str = "",
    ) -> BindServer:
        bind_conf = self._discover_bind_config()
        importer = Bind9Importer(bind_conf)
        server = importer.import_server(name=name, ip=ip, port=port, role=role, version=version)
        server.server_profile = NameServerProfile(server_type="powerdns", version=version)
        return server

    def _discover_bind_config(self) -> str:
        text = self._read_text(self.config_path)
        key_match = re.search(r"^\\s*bind-config\\s*=\\s*(.+)$", text, re.M)
        if not key_match:
            key_match = re.search(r"^\\s*bind-config-file\\s*=\\s*(.+)$", text, re.M)
        if key_match:
            value = key_match.group(1).strip().strip('\"')
            if not os.path.isabs(value):
                value = os.path.join(self.base_dir, value)
            return value
        if re.search(r"\\bzone\\b\\s+\\\"", text):
            return self.config_path
        raise ValueError("PowerDNS config missing bind-config reference")

    def _read_text(self, path: str) -> str:
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()


class MsDnsImporter:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self.base_dir = os.path.dirname(config_path)

    def import_server(
        self,
        name: str,
        ip: str,
        port: int = 53,
        role: str = "master",
        version: str = "",
    ) -> BindServer:
        zones = self._collect_zones()
        profile = NameServerProfile(server_type="msdns", version=version)
        return BindServer(
            name=name,
            ip=ip,
            port=port,
            role=role,
            zones=zones,
            server_profile=profile,
        )

    def _collect_zones(self) -> List[BindZone]:
        if os.path.isdir(self.config_path):
            return self._zones_from_directory(self.config_path)
        return self._zones_from_list_file(self.config_path)

    def _zones_from_directory(self, directory: str) -> List[BindZone]:
        zones: List[BindZone] = []
        for entry in os.listdir(directory):
            if not entry.lower().endswith(".dns"):
                continue
            zone_name = entry[:-4]
            file_path = os.path.join(directory, entry)
            zones.append(BindZone(name=zone_name, zone_type="master", file=file_path))
        return zones

    def _zones_from_list_file(self, list_file: str) -> List[BindZone]:
        if not os.path.exists(list_file):
            raise FileNotFoundError(list_file)
        zones: List[BindZone] = []
        with open(list_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith(("#", "//", ";")):
                    continue
                parts = [part.strip() for part in line.split("|")]
                zone_name = parts[0] if parts else ""
                file_path = parts[1] if len(parts) > 1 else ""
                zone_type = parts[2] if len(parts) > 2 else "master"
                masters = []
                if len(parts) > 3 and parts[3]:
                    masters = [item.strip() for item in parts[3].split(",") if item.strip()]
                if file_path and not os.path.isabs(file_path):
                    file_path = os.path.join(self.base_dir, file_path)
                if zone_name and file_path:
                    zones.append(
                        BindZone(
                            name=zone_name,
                            zone_type=zone_type,
                            file=file_path,
                            masters=masters,
                        )
                    )
        return zones


def import_server_config(
    server_type: str,
    config_path: str,
    name: str,
    ip: str,
    port: int = 53,
    role: str = "master",
    version: str = "",
) -> BindServer:
    if server_type == "bind9":
        importer = Bind9Importer(config_path)
        return importer.import_server(name=name, ip=ip, port=port, role=role, version=version)
    if server_type == "powerdns":
        importer = PowerDnsImporter(config_path)
        return importer.import_server(name=name, ip=ip, port=port, role=role, version=version)
    if server_type == "msdns":
        importer = MsDnsImporter(config_path)
        return importer.import_server(name=name, ip=ip, port=port, role=role, version=version)
    raise ValueError(f"Unsupported server type: {server_type}")
