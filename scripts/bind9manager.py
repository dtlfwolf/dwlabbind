#!/usr/bin/env python3
"""DW-Lab BIND9 management (Python parity with bind9manager.sh)."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, List, Optional, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dwlabbind.models import BindZone, TSIGKey

DWLAB_PREFIX = "DW-Lab:"
BIND_ETC = "/etc/bind"

DWLAB_MARKER_BEGIN = "// DW-Lab GmbH managed DNS server - DO NOT EDIT"
DWLAB_MARKER_END = "// /DW-Lab GmbH managed DNS server"

DWLAB_OPTIONS_FILE = os.path.join(BIND_ETC, "named.conf.options.dwlab.conf")
DWLAB_RECURSION_FILE = os.path.join(BIND_ETC, "named.conf.recursion.dwlab.conf")
DWLAB_ZONES_FILE = os.path.join(BIND_ETC, "named.conf.zones.dwlab.conf")
DWLAB_RECURSION_ACL_BEGIN = "// DW-Lab recursion ACL - BEGIN"
DWLAB_RECURSION_ACL_END = "// DW-Lab recursion ACL - END"

DWLAB_KEYS_DIR = os.path.join(BIND_ETC, "keys")


class Bind9Manager:
    def __init__(self, bind_etc: str = BIND_ETC) -> None:
        self.bind_etc = bind_etc
        self.options_file = os.path.join(bind_etc, os.path.basename(DWLAB_OPTIONS_FILE))
        self.recursion_file = os.path.join(bind_etc, os.path.basename(DWLAB_RECURSION_FILE))
        self.zones_file = os.path.join(bind_etc, os.path.basename(DWLAB_ZONES_FILE))
        self.keys_dir = os.path.join(bind_etc, "keys")
        self.zone_dir = self._default_zone_dir()

    def dwlab_echo(self, message: str) -> None:
        print(f"{DWLAB_PREFIX} {message}")

    def need_root(self) -> None:
        if os.geteuid() != 0:
            self.dwlab_echo("ERROR: run as root.")
            sys.exit(1)

    def require_cmd(self, command: str) -> None:
        if shutil.which(command) is None:
            self.dwlab_echo(f"ERROR: missing command: {command}")
            sys.exit(1)

    def _os_id_like(self) -> Tuple[str, str]:
        os_release = "/etc/os-release"
        if not os.path.exists(os_release):
            return "", ""
        data: Dict[str, str] = {}
        with open(os_release, "r", encoding="utf-8") as handle:
            for line in handle:
                if "=" not in line:
                    continue
                key, value = line.rstrip().split("=", 1)
                data[key] = value.strip().strip('"')
        return data.get("ID", ""), data.get("ID_LIKE", "")

    def _default_zone_dir(self) -> str:
        os_id, os_like = self._os_id_like()
        if "debian" in f" {os_id} {os_like} " or "ubuntu" in f" {os_id} {os_like} ":
            return "/var/lib/bind/zones.dwlab"
        if any(x in f" {os_id} {os_like} " for x in ["rhel", "centos", "fedora", "rocky", "alma", "almalinux"]):
            return "/var/named/zones.dwlab"
        return os.path.join(self.bind_etc, "zones.dwlab")

    def is_fqdn(self, value: str) -> bool:
        return "." in value and not value.startswith(".") and not value.endswith(".") and " " not in value

    def is_ipv4(self, value: str) -> bool:
        if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", value):
            return False
        parts = value.split(".")
        return all(0 <= int(part) <= 255 for part in parts)

    def zone_to_rev_arpa_24(self, cidr: str) -> str:
        ip, prefix = cidr.split("/", 1)
        if prefix != "24":
            raise ValueError(f"only /24 supported (got /{prefix})")
        o1, o2, o3, _o4 = ip.split(".")
        return f"{o3}.{o2}.{o1}.in-addr.arpa"

    def rev_arpa_to_cidr_24(self, rev: str) -> Optional[str]:
        suffix = ".in-addr.arpa"
        if not rev.endswith(suffix):
            return None
        base = rev[: -len(suffix)]
        parts = base.split(".")
        if len(parts) != 3:
            return None
        o1, o2, o3 = parts
        return f"{o3}.{o2}.{o1}.0/24"

    def atomic_write(self, target: str, content: str) -> None:
        directory = os.path.dirname(target)
        os.makedirs(directory, exist_ok=True)
        tmp_handle, tmp_path = tempfile.mkstemp(prefix=os.path.basename(target) + ".", dir=directory)
        try:
            with os.fdopen(tmp_handle, "w", encoding="utf-8") as handle:
                handle.write(content)
            if os.path.exists(target):
                try:
                    st = os.stat(target)
                    os.chmod(tmp_path, st.st_mode)
                    try:
                        os.chown(tmp_path, st.st_uid, st.st_gid)
                    except PermissionError:
                        pass
                except FileNotFoundError:
                    pass
            else:
                os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, target)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def ensure_dir(self, path: str) -> None:
        os.makedirs(path, exist_ok=True)

    def backup_prepare(self, files: Iterable[str]) -> None:
        self.require_cmd("tar")
        ts = dt.datetime.now().strftime("%Y%m%d%H%M%S")
        dest = os.path.join(self.bind_etc, "backup.dwlab")
        self.ensure_dir(dest)
        archive = os.path.join(dest, f"dwlab-bind9-{ts}.tar.gz")
        args = ["tar", "-czf", archive, *files]
        subprocess.run(args, check=True)
        self.dwlab_echo(f"OK: backup created: {archive}")

    def named_conf_remove_include(self, named_conf: str, include_path: str) -> None:
        if not os.path.exists(named_conf):
            return
        inc_line = f'include "{include_path}";'
        lines = self._read_lines(named_conf)
        kept = [line for line in lines if line.rstrip("\n") != inc_line]
        self.atomic_write(named_conf, "".join(kept))

    def options_ensure_include(self) -> None:
        options_conf = os.path.join(self.bind_etc, "named.conf.options")
        if not os.path.exists(options_conf):
            self.dwlab_echo(f"ERROR: {options_conf} not found.")
            sys.exit(1)
        include_options = f'    include "{self.options_file}";\n'
        include_recursion = f'    include "{self.recursion_file}";\n'
        lines = self._read_lines(options_conf)
        if include_options in lines and include_recursion in lines:
            return
        result: List[str] = []
        in_options = False
        inserted = False
        for line in lines:
            if re.match(r"^[\s]*options[\s]*{", line):
                in_options = True
            if in_options and re.match(r"^[\s]*};[\s]*$", line) and not inserted:
                result.append(include_options)
                result.append(include_recursion)
                inserted = True
            result.append(line)
        self.atomic_write(options_conf, "".join(result))

    def ensure_named_conf_includes(self) -> None:
        named_conf = os.path.join(self.bind_etc, "named.conf")
        if not os.path.exists(named_conf):
            self.dwlab_echo(f"ERROR: {named_conf} not found (unexpected for BIND9).")
            sys.exit(1)
        if self._file_contains(named_conf, DWLAB_MARKER_BEGIN):
            self.named_conf_remove_include(named_conf, self.options_file)
            self.named_conf_remove_include(named_conf, self.recursion_file)
            return
        self.dwlab_echo(f"INFO: adding DW-Lab includes to {named_conf}")
        with open(named_conf, "a", encoding="utf-8") as handle:
            handle.write("\n")
            handle.write(DWLAB_MARKER_BEGIN + "\n")
            handle.write(f"include \"{self.zones_file}\";\n")
            handle.write(DWLAB_MARKER_END + "\n")

    def collect_named_conf_files(self) -> List[str]:
        start = os.path.join(self.bind_etc, "named.conf")
        queue = [start]
        seen: Dict[str, bool] = {}
        result: List[str] = []
        while queue:
            path = queue.pop(0)
            if not os.path.exists(path) or path in seen:
                continue
            seen[path] = True
            result.append(path)
            includes = self._parse_includes(path)
            for inc in includes:
                inc_path = inc
                if not os.path.isabs(inc_path):
                    inc_path = os.path.join(self.bind_etc, inc_path)
                if os.path.isdir(inc_path):
                    for conf in sorted(glob_conf_files(inc_path)):
                        queue.append(conf)
                else:
                    queue.append(inc_path)
        return result

    def collect_referenced_files(self) -> List[str]:
        files: List[str] = []
        for conf in self.collect_named_conf_files():
            if not os.path.exists(conf):
                continue
            files.append(conf)
            for file_path in self._parse_zone_files(conf):
                if not os.path.isabs(file_path):
                    file_path = os.path.join(self.bind_etc, file_path)
                files.append(file_path)
        return files

    def recursion_ensure_file(self, force: bool = False) -> None:
        if os.path.exists(self.recursion_file):
            if self._file_contains(self.recursion_file, DWLAB_MARKER_BEGIN) and self._file_contains(
                self.recursion_file, DWLAB_RECURSION_ACL_BEGIN
            ) and not self._file_contains(self.recursion_file, "options"):
                return
            if not self._file_contains(self.recursion_file, DWLAB_MARKER_BEGIN) and not force:
                self.dwlab_echo(f"ERROR: recursion file is not DW-Lab managed: {self.recursion_file}")
                sys.exit(1)
            if not self._file_contains(self.recursion_file, DWLAB_MARKER_BEGIN) and force:
                self.dwlab_echo(f"INFO: rewriting non-managed recursion file: {self.recursion_file}")
        self.dwlab_echo(f"INFO: (re)writing DW-Lab recursion file with managed ACL markers: {self.recursion_file}")
        content = "\n".join(
            [
                DWLAB_MARKER_BEGIN,
                "allow-recursion {",
                "    localhost;",
                "    localnets;",
                f"    {DWLAB_RECURSION_ACL_BEGIN}",
                f"    {DWLAB_RECURSION_ACL_END}",
                "};",
                DWLAB_MARKER_END,
                "",
            ]
        )
        self.atomic_write(self.recursion_file, content)

    def zones_ensure_file(self) -> None:
        if os.path.exists(self.zones_file) and self._file_contains(self.zones_file, DWLAB_MARKER_BEGIN):
            return
        if os.path.exists(self.zones_file) and not self._file_contains(self.zones_file, DWLAB_MARKER_BEGIN):
            self.dwlab_echo(f"ERROR: zones file is not DW-Lab managed: {self.zones_file}")
            sys.exit(1)
        self.dwlab_echo(f"INFO: creating managed zones file: {self.zones_file}")
        content = "\n".join(
            [
                DWLAB_MARKER_BEGIN,
                "// Zone stanzas managed by dwlab-bind9manager.sh will be placed below.",
                DWLAB_MARKER_END,
                "",
            ]
        )
        self.atomic_write(self.zones_file, content)

    def recursion_has_cidr(self, cidr: str) -> bool:
        lines = self._read_lines(self.recursion_file)
        in_block = False
        for line in lines:
            trimmed = line.strip()
            if trimmed == DWLAB_RECURSION_ACL_BEGIN:
                in_block = True
                continue
            if trimmed == DWLAB_RECURSION_ACL_END:
                in_block = False
            if in_block and trimmed == f"{cidr};":
                return True
        return False

    def recursion_add_cidr(self, cidr: str) -> None:
        self.recursion_ensure_file()
        if self.recursion_has_cidr(cidr):
            self.dwlab_echo(f"INFO: recursion already allows {cidr}")
            return
        lines = self._read_lines(self.recursion_file)
        result: List[str] = []
        for line in lines:
            if line.strip() == DWLAB_RECURSION_ACL_END:
                result.append(f"    {cidr};\n")
            result.append(line)
        self.atomic_write(self.recursion_file, "".join(result))
        self.dwlab_echo(f"OK: added recursion allow for {cidr}")

    def recursion_remove_cidr(self, cidr: str) -> None:
        self.recursion_ensure_file()
        lines = self._read_lines(self.recursion_file)
        result: List[str] = []
        in_block = False
        for line in lines:
            trimmed = line.strip()
            if trimmed == DWLAB_RECURSION_ACL_BEGIN:
                in_block = True
                result.append(line)
                continue
            if trimmed == DWLAB_RECURSION_ACL_END:
                in_block = False
                result.append(line)
                continue
            if in_block and trimmed == f"{cidr};":
                continue
            result.append(line)
        self.atomic_write(self.recursion_file, "".join(result))
        self.dwlab_echo(f"OK: removed recursion allow for {cidr}")

    def recursion_sync_from_managed_zones(self) -> None:
        self.need_root()
        if not os.path.exists(self.zones_file):
            self.dwlab_echo(f"ERROR: managed zones file not found: {self.zones_file}")
            sys.exit(1)
        self.recursion_ensure_file(force=True)
        cidrs: List[str] = []
        with open(self.zones_file, "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith('zone "'):
                    zone = line.split('"')[1]
                    if zone.endswith(".in-addr.arpa"):
                        cidr = self.rev_arpa_to_cidr_24(zone)
                        if cidr:
                            cidrs.append(cidr)
        cidrs = sorted(set(cidrs))
        lines = self._read_lines(self.recursion_file)
        result: List[str] = []
        in_block = False
        for line in lines:
            if line.strip() == DWLAB_RECURSION_ACL_BEGIN:
                in_block = True
                result.append(line)
                for cidr in cidrs:
                    result.append(f"    {cidr};\n")
                continue
            if line.strip() == DWLAB_RECURSION_ACL_END:
                in_block = False
                result.append(line)
                continue
            if in_block:
                continue
            result.append(line)
        self.atomic_write(self.recursion_file, "".join(result))
        self.dwlab_echo("OK: synced recursion ACL from managed reverse zones.")

    def install(self) -> None:
        self.need_root()
        self.require_cmd("named-checkconf")
        self.ensure_dir(self.zone_dir)
        if os.path.exists(self.options_file) and self._file_contains(self.options_file, DWLAB_MARKER_BEGIN):
            if not self._file_contains(self.options_file, "options"):
                self.dwlab_echo(f"INFO: {self.options_file} already managed. Leaving unchanged.")
            else:
                self.dwlab_echo(f"Writing {self.options_file}")
                self._write_default_options()
        else:
            self.dwlab_echo(f"Writing {self.options_file}")
            self._write_default_options()

        self.options_ensure_include()

        if os.path.exists(self.recursion_file) and self._file_contains(self.recursion_file, DWLAB_MARKER_BEGIN):
            if not self._file_contains(self.recursion_file, "options"):
                self.dwlab_echo(f"INFO: {self.recursion_file} already exists. Leaving unchanged.")
            else:
                self.dwlab_echo(f"Writing {self.recursion_file}")
                self.recursion_ensure_file(force=True)
        else:
            self.dwlab_echo(f"Writing {self.recursion_file}")
            self.recursion_ensure_file(force=True)

        if os.path.exists(self.zones_file) and self._file_contains(self.zones_file, DWLAB_MARKER_BEGIN):
            self.dwlab_echo(f"INFO: {self.zones_file} already managed. Leaving unchanged.")
        else:
            self.dwlab_echo(f"Writing {self.zones_file}")
            self._write_default_zones()

        named_conf = os.path.join(self.bind_etc, "named.conf")
        if not os.path.exists(named_conf):
            self.dwlab_echo(f"ERROR: {named_conf} not found (unexpected for BIND9).")
            sys.exit(1)
        if self._file_contains(named_conf, DWLAB_MARKER_BEGIN):
            self.named_conf_remove_include(named_conf, self.options_file)
            self.named_conf_remove_include(named_conf, self.recursion_file)
            self.dwlab_echo(f"INFO: {named_conf} already contains DW-Lab marker. Ensured includes.")
        else:
            self.dwlab_echo(f"Adding DW-Lab marker + includes to {named_conf}")
            with open(named_conf, "a", encoding="utf-8") as handle:
                handle.write("\n")
                handle.write(DWLAB_MARKER_BEGIN + "\n")
                handle.write(f"include \"{self.zones_file}\";\n")
                handle.write(DWLAB_MARKER_END + "\n")

        subprocess.run(["named-checkconf"], check=True)
        self.dwlab_echo("OK: installation/bootstrapping complete.")

    def create_tsig(self, keyname: str, algo: str = "hmac-sha256") -> TSIGKey:
        self.need_root()
        self.require_cmd("tsig-keygen")
        if not self.is_fqdn(keyname):
            self.dwlab_echo(f"ERROR: keyname should be FQDN-ish (e.g. dw-lab.de). Got: {keyname}")
            sys.exit(1)
        self.ensure_dir(self.keys_dir)
        managed_keyfile = os.path.join(self.keys_dir, f"{keyname}.dwlab.tsig")
        compat_keyfile = os.path.join(self.keys_dir, f"{keyname}.tsig")
        if os.path.exists(managed_keyfile) and self._file_contains(managed_keyfile, DWLAB_MARKER_BEGIN):
            self.dwlab_echo(f"INFO: TSIG already exists (DW-Lab managed): {managed_keyfile}")
        else:
            self.dwlab_echo(f"Creating TSIG key: {managed_keyfile} (algo={algo})")
            output = subprocess.check_output(["tsig-keygen", "-a", algo, keyname], text=True)
            content = "\n".join(
                [
                    DWLAB_MARKER_BEGIN,
                    "// TSIG key generated by DW-Lab GmbH tooling.",
                    output.strip(),
                    DWLAB_MARKER_END,
                    "",
                ]
            )
            self.atomic_write(managed_keyfile, content)
            try:
                os.chmod(managed_keyfile, 0o640)
            except PermissionError:
                pass

        if os.path.islink(compat_keyfile) or os.path.exists(compat_keyfile):
            self.dwlab_echo(f"INFO: Compat key path already exists, not touching: {compat_keyfile}")
        else:
            os.symlink(os.path.basename(managed_keyfile), compat_keyfile)
            self.dwlab_echo(f"OK: Created compat symlink: {compat_keyfile} -> {os.path.basename(managed_keyfile)}")

        self.dwlab_echo(f"OK: TSIG ready. Use key name: \"{keyname}\"")
        self.dwlab_echo(f"OK: Managed key file: {managed_keyfile}")
        return TSIGKey(name=keyname, algorithm=algo, secret="")

    def create_zone(
        self,
        zone: str,
        keyfile: Optional[str],
        reverse_cidr: str,
        hostname: str,
        dnshost_ip: str,
        reuse_files: bool,
    ) -> None:
        self.need_root()
        self.require_cmd("named-checkconf")
        self.require_cmd("named-checkzone")
        if not (os.path.exists(self.options_file) and os.path.exists(self.recursion_file) and os.path.exists(self.zones_file)):
            self.install()
        if not self.is_fqdn(zone):
            self.dwlab_echo(f"ERROR: zone must be a FQDN like example.com (got: {zone})")
            sys.exit(1)
        if not reverse_cidr:
            self.dwlab_echo("ERROR: --reverse <CIDR/24> is required")
            sys.exit(1)
        if not hostname:
            self.dwlab_echo("ERROR: --hostname <label> is required")
            sys.exit(1)
        if not dnshost_ip:
            self.dwlab_echo("ERROR: --dnshostIP <IPv4> is required")
            sys.exit(1)
        if not self.is_ipv4(dnshost_ip):
            self.dwlab_echo(f"ERROR: invalid IPv4 for --dnshostIP: {dnshost_ip}")
            sys.exit(1)

        if not keyfile:
            self.dwlab_echo(f"INFO: No TSIG file provided. Generating TSIG for {zone}.")
            self.create_tsig(zone)
            keyfile = os.path.join(self.keys_dir, f"{zone}.dwlab.tsig")

        if not os.path.exists(keyfile):
            self.dwlab_echo(f"ERROR: TSIG key file not found: {keyfile}")
            sys.exit(1)

        zonefile = os.path.join(self.zone_dir, f"db.{zone}.dwlab.zone")
        if self.zones_file_has_zone(zone):
            self.dwlab_echo(f"ERROR: zone already exists on this DNS: {zone}")
            sys.exit(1)

        if os.path.exists(zonefile) and not reuse_files:
            self.dwlab_echo(f"ERROR: forward zone file already exists: {zonefile}")
            sys.exit(1)
        if os.path.exists(zonefile) and reuse_files:
            self.dwlab_echo(f"INFO: Reusing existing forward zone file: {zonefile}")
        if not os.path.exists(zonefile):
            self.dwlab_echo(f"Creating forward zone file: {zonefile}")
            serial = dt.datetime.now().strftime("%Y%m%d") + "01"
            content = "\n".join(
                [
                    "$TTL 86400",
                    f"@   IN SOA  {hostname}.{zone}. hostmaster.{zone}. (",
                    f"        {serial} ; serial",
                    "        10800      ; refresh",
                    "        3600       ; retry",
                    "        604800     ; expire",
                    "        86400      ; minimum",
                    ")",
                    f"    IN NS   {hostname}.{zone}.",
                    f"{hostname}    IN A    {dnshost_ip}",
                    "; Add your records below",
                    "",
                ]
            )
            self.atomic_write(zonefile, content)

        key_name = os.path.basename(keyfile).replace(".tsig", "")
        forward_zone = BindZone(name=zone, zone_type="master", file=zonefile, allow_update=True)
        self.add_zone_stanza(forward_zone, key_name)

        rev_zone = self.zone_to_rev_arpa_24(reverse_cidr)
        rev_file = os.path.join(self.zone_dir, f"db.{rev_zone}.dwlab.zone")
        if self.zones_file_has_zone(rev_zone):
            self.dwlab_echo(f"ERROR: reverse zone already exists on this DNS: {rev_zone}")
            sys.exit(1)
        if os.path.exists(rev_file) and not reuse_files:
            self.dwlab_echo(f"ERROR: reverse zone file already exists: {rev_file}")
            sys.exit(1)
        if os.path.exists(rev_file) and reuse_files:
            self.dwlab_echo(f"INFO: Reusing existing reverse zone file: {rev_file}")
        if not os.path.exists(rev_file):
            self.dwlab_echo(f"Creating reverse zone file: {rev_file}")
            serial = dt.datetime.now().strftime("%Y%m%d") + "01"
            last_octet = dnshost_ip.split(".")[-1]
            content = "\n".join(
                [
                    "$TTL 86400",
                    f"@   IN SOA  {hostname}.{zone}. hostmaster.{zone}. (",
                    f"        {serial} ; serial",
                    "        10800      ; refresh",
                    "        3600       ; retry",
                    "        604800     ; expire",
                    "        86400      ; minimum",
                    ")",
                    f"    IN NS   {hostname}.{zone}.",
                    f"{last_octet}   IN PTR {hostname}.{zone}.",
                    "; PTR records go below (last octet IN PTR host.{zone}.)",
                    "",
                ]
            )
            self.atomic_write(rev_file, content)

        reverse_zone = BindZone(name=rev_zone, zone_type="master", file=rev_file, allow_update=True)
        self.add_zone_stanza(reverse_zone, key_name)

        self.recursion_add_cidr(reverse_cidr)

        subprocess.run(["named-checkconf"], check=True)
        subprocess.run(["named-checkzone", zone, zonefile], check=True)
        subprocess.run(["named-checkzone", rev_zone, rev_file], check=True)
        self.dwlab_echo(f"OK: created/registered zone(s) for {zone}")
        self.dwlab_echo("NOTE: reload BIND: systemctl reload bind9")

    def update_zone(self, zone: str) -> None:
        self.need_root()
        self.require_cmd("named-checkzone")
        zonefile = os.path.join(self.zone_dir, f"db.{zone}.dwlab.zone")
        if not os.path.exists(zonefile):
            self.dwlab_echo(f"ERROR: zone file not found: {zonefile}")
            sys.exit(1)
        today = dt.datetime.now().strftime("%Y%m%d")
        lines = self._read_lines(zonefile)
        updated = False
        result: List[str] = []
        serial_regex = re.compile(rf"^\s*{today}[0-9]{{2}}\s*;\s*serial")
        for line in lines:
            if not updated and serial_regex.search(line):
                current = line.split(";")[0].strip()
                nn = current[8:10]
                nn_new = f"{int(nn) + 1:02d}"
                new_serial = today + nn_new
                line = re.sub(rf"^{current}\s*;\s*serial", f"{new_serial} ; serial", line)
                updated = True
            result.append(line)
        if not updated:
            new_serial = today + "01"
            serial_line = re.compile(r";\s*serial")
            replaced = False
            result = []
            for line in lines:
                if not replaced and serial_line.search(line):
                    line = re.sub(r"^\s*[0-9]+\s*;\s*serial", f"{new_serial} ; serial", line)
                    replaced = True
                result.append(line)
            updated = replaced
        self.atomic_write(zonefile, "".join(result))
        if updated:
            self.dwlab_echo(f"INFO: updated serial in {zonefile}")
        subprocess.run(["named-checkzone", zone, zonefile], check=True)
        self.dwlab_echo(f"OK: updated {zone} (reload BIND: systemctl reload bind9)")

    def delete_zone(self, zone: str, reverse_cidr: str, remove_files: bool, force: bool) -> None:
        self.need_root()
        self.require_cmd("named-checkconf")
        if not reverse_cidr:
            self.dwlab_echo("ERROR: --reverse <CIDR/24> is required")
            sys.exit(1)
        if not os.path.exists(self.zones_file):
            self.dwlab_echo(f"ERROR: missing managed zones file: {self.zones_file}")
            sys.exit(1)
        rev_zone = self.zone_to_rev_arpa_24(reverse_cidr)
        reverse_zone = rev_zone
        if not self.zones_file_has_zone(zone) and not self.zones_file_has_zone(rev_zone):
            self.dwlab_echo(f"ERROR: zone not found: {zone}")
            sys.exit(1)
        if not self.zones_file_has_zone(zone) and self.zones_file_has_zone(rev_zone):
            fzone = self.find_forward_zone_for_reverse(rev_zone)
            if not fzone:
                self.dwlab_echo(f"ERROR: cannot determine forward zone for reverse {rev_zone}")
                sys.exit(1)
            zone = fzone
        if self.zones_file_has_zone(zone):
            linked_rev = self.find_reverse_zones_for_forward(zone)
            if linked_rev:
                reverse_zone = linked_rev
        if not force:
            if remove_files:
                if not self.confirm_delete(zone, confirm="fqdn"):
                    self.dwlab_echo("INFO: deletion aborted.")
                    sys.exit(1)
            else:
                if not self.confirm_delete(zone, confirm="yes"):
                    self.dwlab_echo("INFO: deletion aborted.")
                    sys.exit(1)
        if self.zones_file_has_zone(zone):
            self.dwlab_echo(f"Removing zone stanza for {zone} from {self.zones_file}")
            self.remove_zone_from_zonesfile(zone)
        else:
            self.dwlab_echo(f"INFO: no stanza found for {zone} (nothing to remove)")
        zonefile = os.path.join(self.zone_dir, f"db.{zone}.dwlab.zone")
        if remove_files and os.path.exists(zonefile):
            self.dwlab_echo(f"Removing zone file: {zonefile}")
            os.remove(zonefile)
        if reverse_zone:
            for rz in reverse_zone.split():
                if self.zones_file_has_zone(rz):
                    self.dwlab_echo(f"Removing reverse zone stanza for {rz}")
                    self.remove_zone_from_zonesfile(rz)
                else:
                    self.dwlab_echo(f"INFO: no stanza found for reverse {rz}")
                rev_file = os.path.join(self.zone_dir, f"db.{rz}.dwlab.zone")
                if remove_files and os.path.exists(rev_file):
                    self.dwlab_echo(f"Removing reverse zone file: {rev_file}")
                    os.remove(rev_file)
        self.recursion_remove_cidr(reverse_cidr)
        subprocess.run(["named-checkconf"], check=True)
        self.dwlab_echo(f"OK: deleted zone config for {zone} (reload BIND: systemctl reload bind9)")

    def list_zones(self) -> None:
        green = "\033[0;32m"
        yellow = "\033[0;33m"
        reset = "\033[0m"
        managed = self._list_managed_zones()
        unmanaged = self._list_unmanaged_zones()
        zone_status: Dict[str, str] = {}
        zone_key: Dict[str, str] = {}
        zone_file: Dict[str, str] = {}
        zones: List[str] = []
        for zone, status, key, file_path in managed + unmanaged:
            if zone in zone_status:
                continue
            zone_status[zone] = status
            zone_key[zone] = key
            zone_file[zone] = file_path
            zones.append(zone)
        forward = sorted({z for z in zones if not z.endswith(".in-addr.arpa")})
        reverse = sorted({z for z in zones if z.endswith(".in-addr.arpa")})
        self.dwlab_echo("Existing zones on this DNS:")
        printed_rev: Dict[str, bool] = {}
        reverse_ns: Dict[str, str] = {}
        for rzone in reverse:
            rfile = zone_file.get(rzone, "")
            if rfile and not os.path.isabs(rfile):
                rfile = os.path.join(self.bind_etc, rfile)
            if rfile:
                ns_target = self.zonefile_ns_target(rfile)
                if ns_target:
                    reverse_ns[rzone] = ns_target
        for zone in forward:
            status = zone_status.get(zone, "")
            if status == "managed":
                print(f"{green}{zone}{reset} [managed]")
            else:
                print(f"{yellow}{zone}{reset} [un-managed]")
            for rzone in reverse:
                if rzone in printed_rev:
                    continue
                ns_target = reverse_ns.get(rzone, "")
                if self.ns_matches_zone(ns_target, zone):
                    status = zone_status.get(rzone, "")
                    if status == "managed":
                        print(f"  {green}{rzone}{reset} [reverse]")
                    else:
                        print(f"  {yellow}{rzone}{reset} [reverse]")
                    printed_rev[rzone] = True
        for rzone in reverse:
            if rzone in printed_rev:
                continue
            status = zone_status.get(rzone, "")
            if status == "managed":
                print(f"{green}{rzone}{reset} [managed] [reverse]")
            else:
                print(f"{yellow}{rzone}{reset} [un-managed] [reverse]")

    def migrate(self, args: argparse.Namespace) -> None:
        if not args.zone:
            self.migrate_all()
        else:
            self.migrate_single(
                zone=args.zone,
                zonefile=args.zonefile,
                keyfile=args.keyfile,
                reverse_cidr=args.reverse,
                reverse_zonefile=args.reverse_zonefile,
                source_conf=args.source_conf,
                reverse_source_conf=args.reverse_source_conf,
            )

    def migrate_single(
        self,
        zone: str,
        zonefile: str,
        keyfile: str,
        reverse_cidr: Optional[str],
        reverse_zonefile: Optional[str],
        source_conf: Optional[str],
        reverse_source_conf: Optional[str],
    ) -> None:
        self.need_root()
        self.require_cmd("named-checkconf")
        self.require_cmd("named-checkzone")
        if not (os.path.exists(self.options_file) and os.path.exists(self.recursion_file) and os.path.exists(self.zones_file)):
            self.install()
        self.ensure_named_conf_includes()
        if not zone:
            self.dwlab_echo("ERROR: zone is required")
            sys.exit(1)
        if not self.is_fqdn(zone):
            self.dwlab_echo(f"ERROR: zone must be a FQDN like example.com (got: {zone})")
            sys.exit(1)
        if not zonefile or not keyfile:
            self.dwlab_echo("ERROR: --zonefile and --keyfile are required")
            sys.exit(1)
        if reverse_cidr and not reverse_zonefile:
            self.dwlab_echo("ERROR: --reverse-zonefile is required when --reverse is used")
            sys.exit(1)
        if reverse_zonefile and not reverse_cidr:
            self.dwlab_echo("ERROR: --reverse is required when --reverse-zonefile is used")
            sys.exit(1)
        if not os.path.exists(zonefile):
            self.dwlab_echo(f"ERROR: forward zone file not found: {zonefile}")
            sys.exit(1)
        if not os.path.exists(keyfile):
            self.dwlab_echo(f"ERROR: key file not found: {keyfile}")
            sys.exit(1)
        if reverse_zonefile and not os.path.exists(reverse_zonefile):
            self.dwlab_echo(f"ERROR: reverse zone file not found: {reverse_zonefile}")
            sys.exit(1)
        if self.zones_file_has_zone(zone):
            self.dwlab_echo(f"ERROR: zone already exists in {self.zones_file}: {zone}")
            sys.exit(1)
        target_zonefile = os.path.join(self.zone_dir, f"db.{zone}.dwlab.zone")
        if os.path.exists(target_zonefile):
            self.dwlab_echo(f"ERROR: target forward zone file already exists: {target_zonefile}")
            sys.exit(1)
        rev_zone = ""
        target_revfile = ""
        if reverse_cidr:
            rev_zone = self.zone_to_rev_arpa_24(reverse_cidr)
            target_revfile = os.path.join(self.zone_dir, f"db.{rev_zone}.dwlab.zone")
            if self.zones_file_has_zone(rev_zone):
                self.dwlab_echo(f"ERROR: reverse zone already exists in {self.zones_file}: {rev_zone}")
                sys.exit(1)
            if os.path.exists(target_revfile):
                self.dwlab_echo(f"ERROR: target reverse zone file already exists: {target_revfile}")
                sys.exit(1)
        if not source_conf:
            for item in self.discover_unmanaged_zones():
                if item[0] == zone:
                    source_conf = item[3]
                    break
        if reverse_cidr and not reverse_source_conf:
            for item in self.discover_unmanaged_zones():
                if item[0] == rev_zone:
                    reverse_source_conf = item[3]
                    break

        backup_items = [f for f in self.collect_referenced_files() if os.path.exists(f)]
        self.backup_prepare(backup_items)
        self.ensure_dir(self.zone_dir)
        shutil.copy2(zonefile, target_zonefile)

        key_name = os.path.basename(keyfile).replace(".tsig", "")
        forward_zone = BindZone(name=zone, zone_type="master", file=target_zonefile, allow_update=True)
        self.add_zone_stanza(forward_zone, key_name)

        if reverse_cidr:
            shutil.copy2(reverse_zonefile, target_revfile)
            reverse_zone = BindZone(name=rev_zone, zone_type="master", file=target_revfile, allow_update=True)
            self.add_zone_stanza(reverse_zone, key_name)
            self.recursion_add_cidr(reverse_cidr)

        subprocess.run(["named-checkconf"], check=True)
        subprocess.run(["named-checkzone", zone, target_zonefile], check=True)
        if reverse_cidr:
            subprocess.run(["named-checkzone", rev_zone, target_revfile], check=True)
        if source_conf:
            self.dwlab_echo(f"INFO: removing old zone stanza from {source_conf}: {zone}")
            self.remove_zone_from_conf(source_conf, zone)
        else:
            self.dwlab_echo(f"INFO: old zone stanza not found for {zone} (no source conf)")
        if reverse_cidr:
            if reverse_source_conf:
                self.dwlab_echo(f"INFO: removing old reverse zone stanza from {reverse_source_conf}: {rev_zone}")
                self.remove_zone_from_conf(reverse_source_conf, rev_zone)
            else:
                self.dwlab_echo(f"INFO: old reverse zone stanza not found for {rev_zone} (no source conf)")

        self.dwlab_echo(f"OK: migrated zone(s) under DW-Lab management for {zone}")
        self.dwlab_echo("NOTE: reload BIND: systemctl reload bind9")

    def migrate_all(self) -> None:
        self.need_root()
        self.require_cmd("named-checkconf")
        self.require_cmd("named-checkzone")
        if not (os.path.exists(self.options_file) and os.path.exists(self.recursion_file) and os.path.exists(self.zones_file)):
            self.install()
        self.ensure_named_conf_includes()
        self.zones_ensure_file()
        backup_items = [f for f in self.collect_referenced_files() if os.path.exists(f)]
        self.backup_prepare(backup_items)
        unmanaged = sorted(set(self.discover_unmanaged_zones()))
        if not unmanaged:
            self.dwlab_echo("INFO: no unmanaged zones found.")
            return
        for zone, file_path, key, conf in unmanaged:
            if self.is_default_zone(zone):
                continue
            if self.zones_file_has_zone(zone):
                if conf:
                    self.dwlab_echo(f"INFO: removing old zone stanza from {conf}: {zone}")
                    self.remove_zone_from_conf(conf, zone)
                continue
            file_abs = file_path
            if file_abs and not os.path.isabs(file_abs):
                file_abs = os.path.join(self.bind_etc, file_abs)
            if not file_abs or not os.path.exists(file_abs):
                self.dwlab_echo(f"ERROR: zone file not found for {zone}: {file_abs}")
                continue
            target_zonefile = os.path.join(self.zone_dir, f"db.{zone}.dwlab.zone")
            if os.path.exists(target_zonefile):
                self.dwlab_echo(f"INFO: target file exists, skipping: {target_zonefile}")
                continue
            self.ensure_dir(self.zone_dir)
            shutil.copy2(file_abs, target_zonefile)
            keyfile = f"{key}.tsig" if key else ""
            key_name = keyfile.replace(".tsig", "") if keyfile else ""
            zone_obj = BindZone(name=zone, zone_type="master", file=target_zonefile, allow_update=bool(key_name))
            self.add_zone_stanza(zone_obj, key_name if key_name else None)
            if zone.endswith(".in-addr.arpa"):
                cidr = self.rev_arpa_to_cidr_24(zone)
                if cidr:
                    self.recursion_add_cidr(cidr)
            subprocess.run(["named-checkzone", zone, target_zonefile], check=True)
            if conf:
                self.dwlab_echo(f"INFO: removing old zone stanza from {conf}: {zone}")
                self.remove_zone_from_conf(conf, zone)
            self.dwlab_echo(f"OK: migrated {zone}")
        subprocess.run(["named-checkconf"], check=True)
        self.dwlab_echo("OK: migration complete (reload BIND: systemctl reload bind9)")

    def zones_file_has_zone(self, zone: str) -> bool:
        if not os.path.exists(self.zones_file):
            return False
        pattern = re.compile(rf"^\s*zone\s+\"{re.escape(zone)}\"", re.M)
        return bool(pattern.search(self._read_text(self.zones_file)))

    def zonefile_ns_target(self, zonefile: str) -> Optional[str]:
        if not os.path.exists(zonefile):
            return None
        with open(zonefile, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.split(";", 1)[0]
                parts = line.split()
                for idx, part in enumerate(parts):
                    if part.upper() == "NS" and idx + 1 < len(parts):
                        return parts[idx + 1]
        return None

    def ns_matches_zone(self, ns: str, zone: str) -> bool:
        ns = ns.rstrip(".") if ns else ""
        zone = zone.rstrip(".") if zone else ""
        if not ns or not zone:
            return False
        if ns == zone:
            return True
        return ns.endswith("." + zone)

    def zonefile_for_zone(self, zone: str) -> str:
        for zname, file_path, _key, _conf in self.discover_unmanaged_zones():
            if zname == zone:
                return file_path
        if os.path.exists(self.zones_file):
            content = self._read_text(self.zones_file)
            match = re.search(rf"zone \"{re.escape(zone)}\".*?file \"([^\"]+)\"", content, re.S)
            if match:
                file_path = match.group(1)
                if file_path and not os.path.isabs(file_path):
                    file_path = os.path.join(self.bind_etc, file_path)
                return file_path
        return ""

    def find_reverse_zones_for_forward(self, fzone: str) -> str:
        zones: List[str] = []
        for zone, _file, _key, _conf in self.discover_unmanaged_zones():
            if zone.endswith(".in-addr.arpa"):
                zones.append(zone)
        for zone in self._list_managed_zone_names():
            if zone.endswith(".in-addr.arpa"):
                zones.append(zone)
        results: List[str] = []
        for rzone in zones:
            rfile = self.zonefile_for_zone(rzone)
            if not rfile:
                continue
            ns = self.zonefile_ns_target(rfile)
            if self.ns_matches_zone(ns or "", fzone):
                results.append(rzone)
        return " ".join(results)

    def find_forward_zone_for_reverse(self, rzone: str) -> Optional[str]:
        rfile = self.zonefile_for_zone(rzone)
        if not rfile:
            return None
        ns = self.zonefile_ns_target(rfile)
        if not ns:
            return None
        ns = ns.rstrip(".")
        if "." not in ns:
            return None
        return ns.split(".", 1)[1]

    def confirm_delete(self, target: str, confirm: str) -> bool:
        if confirm == "fqdn":
            prompt = f"Type the FQDN to confirm deletion of {target}: "
        else:
            prompt = f"Type YES to confirm deletion of {target}: "
        reply = input(prompt)
        if confirm == "fqdn":
            return reply == target
        return reply == "YES"

    def discover_unmanaged_zones(self) -> List[Tuple[str, str, str, str]]:
        zones: List[Tuple[str, str, str, str]] = []
        for conf in self.collect_named_conf_files():
            if not os.path.exists(conf):
                continue
            if conf in {self.options_file, self.recursion_file, self.zones_file}:
                continue
            if self._file_contains(conf, DWLAB_MARKER_BEGIN):
                continue
            zones.extend(self._parse_zone_stanzas(conf, conf))
        return zones

    def add_zone_stanza(self, zone: BindZone, key_name: Optional[str]) -> None:
        if self.zones_file_has_zone(zone.name):
            self.dwlab_echo(f"INFO: Zone stanza already present for {zone.name} in {self.zones_file}")
            return
        self.dwlab_echo(f"Adding zone stanza for {zone.name} to {self.zones_file}")
        block = self.zone_stanza(zone, key_name)
        self.append_zone_block(block)

    def zone_stanza(self, zone: BindZone, key_name: Optional[str]) -> str:
        allow_update = ""
        if key_name:
            allow_update = f"    allow-update {{ key \"{key_name}\"; }};\n"
        return (
            f"zone \"{zone.name}\" {{\n"
            f"    type {zone.zone_type};\n"
            f"    file \"{zone.file}\";\n"
            f"{allow_update}"
            f"}};\n"
        )

    def append_zone_block(self, block: str) -> None:
        lines = self._read_lines(self.zones_file)
        result: List[str] = []
        for line in lines:
            if line.rstrip("\n") == DWLAB_MARKER_END:
                result.append(block)
                result.append(line)
            else:
                result.append(line)
        self.atomic_write(self.zones_file, "".join(result))

    def remove_zone_from_zonesfile(self, zone: str) -> None:
        if not os.path.exists(self.zones_file):
            return
        self._remove_zone_from_conf(self.zones_file, zone)

    def remove_zone_from_conf(self, conf: str, zone: str) -> None:
        if not os.path.exists(conf):
            return
        self._remove_zone_from_conf(conf, zone)

    def is_default_zone(self, zone: str) -> bool:
        return zone in {".", "localhost", "127.in-addr.arpa", "0.in-addr.arpa", "255.in-addr.arpa", "0.ip6.arpa", "255.ip6.arpa", "empty"}

    def _write_default_options(self) -> None:
        content = "\n".join(
            [
                DWLAB_MARKER_BEGIN,
                'directory "/var/cache/bind";',
                "",
                "recursion yes;                // recursion enabled; allowed clients are defined in recursion include",
                "",
                "listen-on { any; };",
                "listen-on-v6 { none; };",
                "",
                "allow-query { any; };",
                "allow-transfer { none; };",
                "",
                "dnssec-validation auto;",
                "auth-nxdomain no;",
                "minimal-responses yes;",
                DWLAB_MARKER_END,
                "",
            ]
        )
        self.atomic_write(self.options_file, content)

    def _write_default_zones(self) -> None:
        content = "\n".join(
            [
                DWLAB_MARKER_BEGIN,
                "// Zone stanzas managed by dwlab_dns_manage.sh will be placed below.",
                DWLAB_MARKER_END,
                "",
            ]
        )
        self.atomic_write(self.zones_file, content)

    def _read_text(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def _read_lines(self, path: str) -> List[str]:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.readlines()

    def _file_contains(self, path: str, token: str) -> bool:
        if not os.path.exists(path):
            return False
        return token in self._read_text(path)

    def _parse_includes(self, path: str) -> List[str]:
        includes: List[str] = []
        pattern = re.compile(r"^\s*include\s+\"([^\"]+)\"", re.M)
        text = self._read_text(path)
        for match in pattern.finditer(text):
            includes.append(match.group(1))
        return includes

    def _parse_zone_files(self, path: str) -> List[str]:
        files: List[str] = []
        pattern = re.compile(r"^\s*file\s+\"([^\"]+)\"", re.M)
        text = self._read_text(path)
        for match in pattern.finditer(text):
            files.append(match.group(1))
        return files

    def _parse_zone_stanzas(self, text_path: str, conf: str) -> List[Tuple[str, str, str, str]]:
        text = self._read_text(text_path)
        entries: List[Tuple[str, str, str, str]] = []
        zone_pattern = re.compile(r"zone\s+\"([^\"]+)\"\s*{(.*?)};", re.S)
        for match in zone_pattern.finditer(text):
            zone = match.group(1)
            body = match.group(2)
            file_match = re.search(r"file\s+\"([^\"]+)\"", body)
            file_path = file_match.group(1) if file_match else ""
            key_match = re.search(r"allow-update\s*\{\s*key\s+\"([^\"]+)\";", body)
            key = key_match.group(1) if key_match else ""
            if zone and file_path:
                entries.append((zone, file_path, key, conf))
        return entries

    def _list_managed_zone_names(self) -> List[str]:
        return [zone for zone, _file, _key, _conf in self._parse_zone_stanzas(self.zones_file, self.zones_file)]

    def _list_managed_zones(self) -> List[Tuple[str, str, str, str]]:
        if not os.path.exists(self.zones_file):
            return []
        entries = self._parse_zone_stanzas(self.zones_file, self.zones_file)
        return [(zone, "managed", key, file_path) for zone, file_path, key, _conf in entries]

    def _list_unmanaged_zones(self) -> List[Tuple[str, str, str, str]]:
        return [(zone, "un-managed", key, file_path) for zone, file_path, key, _conf in self.discover_unmanaged_zones()]

    def _remove_zone_from_conf(self, conf: str, zone: str) -> None:
        lines = self._read_lines(conf)
        result: List[str] = []
        skip = False
        marker = f'zone "{zone}"'
        for line in lines:
            if not skip and marker in line:
                skip = True
                continue
            if skip:
                if re.match(r"^[\s]*};[\s]*$", line):
                    skip = False
                continue
            result.append(line)
        self.atomic_write(conf, "".join(result))


def glob_conf_files(directory: str) -> List[str]:
    return [os.path.join(directory, name) for name in os.listdir(directory) if name.endswith(".conf")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DW-Lab BIND9 manager (Python)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("install", help="Bootstrap managed includes and markers")

    tsig = sub.add_parser("create-tsig", help="Create TSIG key")
    tsig.add_argument("keyname")
    tsig.add_argument("--algo", default="hmac-sha256")

    create = sub.add_parser("create-zone", help="Create forward and reverse zone")
    create.add_argument("zone")
    create.add_argument("keyfile", nargs="?")
    create.add_argument("--reverse", required=True)
    create.add_argument("--hostname", required=True)
    create.add_argument("--dnshostIP", required=True)
    create.add_argument("--reuse-files", action="store_true")

    update = sub.add_parser("update-zone", help="Update zone serial")
    update.add_argument("zone")

    delete = sub.add_parser("delete-zone", help="Delete zone")
    delete.add_argument("zone")
    delete.add_argument("--remove-files", action="store_true")
    delete.add_argument("--force", action="store_true")
    delete.add_argument("--reverse", required=True)

    migrate = sub.add_parser("migrate", help="Migrate zones into DW-Lab management")
    migrate.add_argument("zone", nargs="?")
    migrate.add_argument("--zonefile")
    migrate.add_argument("--keyfile")
    migrate.add_argument("--reverse")
    migrate.add_argument("--reverse-zonefile")
    migrate.add_argument("--source-conf")
    migrate.add_argument("--reverse-source-conf")

    sub.add_parser("sync-recursion", help="Sync recursion ACL from managed reverse zones")
    sub.add_parser("list-zones", help="List zones")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    manager = Bind9Manager()

    if args.command == "install":
        manager.install()
    elif args.command == "create-tsig":
        manager.create_tsig(args.keyname, algo=args.algo)
    elif args.command == "create-zone":
        manager.create_zone(
            zone=args.zone,
            keyfile=args.keyfile,
            reverse_cidr=args.reverse,
            hostname=args.hostname,
            dnshost_ip=args.dnshostIP,
            reuse_files=args.reuse_files,
        )
    elif args.command == "update-zone":
        manager.update_zone(args.zone)
    elif args.command == "delete-zone":
        manager.delete_zone(args.zone, args.reverse, args.remove_files, args.force)
    elif args.command == "migrate":
        manager.migrate(args)
    elif args.command == "sync-recursion":
        manager.recursion_sync_from_managed_zones()
    elif args.command == "list-zones":
        manager.list_zones()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
