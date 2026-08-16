"""OWASP Amass adapter (passive subdomain / asset discovery).

Amass is purpose-built for external attack-surface mapping. This adapter runs
passive enumeration and normalizes the discovered hostnames.
"""
from __future__ import annotations

import re
from typing import List

from security_toolkit.integrations.base import ToolAdapter, ToolNotAvailable


class AmassAdapter(ToolAdapter):
    binary = "amass"
    config_key = "amass"

    def version(self) -> str:
        try:
            proc = self._run(["-version"], timeout=15)
            out = (proc.stdout or proc.stderr).strip()
            m = re.search(r"v?(\d+\.\d+\.\d+)", out)
            return m.group(1) if m else out.splitlines()[0] if out else ""
        except Exception:
            return ""

    def enumerate_passive(self, domain: str, timeout: int = 300) -> List[str]:
        if not self.available():
            raise ToolNotAvailable("amass not installed")
        proc = self._run(["enum", "-passive", "-d", domain], timeout=timeout)
        hosts = set()
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.endswith(domain) or ("." + domain) in line:
                token = line.split()[0]
                if re.match(r"^[A-Za-z0-9.\-]+$", token):
                    hosts.add(token.lower())
        return sorted(hosts)
