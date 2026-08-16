"""Nmap adapter.

Runs Nmap with a per-profile argument set, parses the XML output, and returns a
normalized host/port structure. Aggressive options are only used in the
FORENSIC profile and never enabled implicitly for QUICK/STANDARD.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from security_toolkit.integrations.base import ToolAdapter, ToolNotAvailable

PROFILE_ARGS = {
    "QUICK": ["-T4", "-F"],                        # top 100 ports
    "STANDARD": ["-T4", "--top-ports", "1000"],
    "DETAILED": ["-T4", "-sV", "--top-ports", "2000"],
    "FORENSIC": ["-T4", "-sV", "-O", "-p-"],       # full range + version + OS
}


class NmapAdapter(ToolAdapter):
    binary = "nmap"
    config_key = "nmap"

    def version(self) -> str:
        try:
            proc = self._run(["--version"], timeout=15)
            m = re.search(r"Nmap version ([\d.]+)", proc.stdout)
            return m.group(1) if m else proc.stdout.splitlines()[0] if proc.stdout else ""
        except Exception:
            return ""

    def scan(self, target: str, profile: str = "STANDARD") -> List[Dict[str, Any]]:
        if not self.available():
            raise ToolNotAvailable("nmap not installed")
        args = PROFILE_ARGS.get(profile.upper(), PROFILE_ARGS["STANDARD"])
        # -oX - streams XML to stdout; -Pn avoids host-discovery skips on filtered hosts.
        proc = self._run([*args, "-Pn", "-oX", "-", target], timeout=900)
        return self.parse_xml(proc.stdout)

    @staticmethod
    def parse_xml(xml_text: str) -> List[Dict[str, Any]]:
        hosts: List[Dict[str, Any]] = []
        if not xml_text.strip():
            return hosts
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return hosts
        for host in root.findall("host"):
            addr_el = host.find("address")
            address = addr_el.get("addr") if addr_el is not None else ""
            ports: List[Dict[str, Any]] = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": service.get("name") if service is not None else "",
                    "product": (service.get("product", "") + " " +
                                service.get("version", "")).strip()
                               if service is not None else "",
                })
            os_el = host.find("./os/osmatch")
            hosts.append({
                "address": address,
                "ports": ports,
                "os": os_el.get("name") if os_el is not None else "",
            })
        return hosts
