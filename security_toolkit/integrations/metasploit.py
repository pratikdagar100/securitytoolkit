"""Metasploit Framework adapter (external controlled backend).

Metasploit is treated strictly as an external, authorized execution backend --
its exploit code is never embedded in this project. This adapter only detects
the installation and reports its version. Any intrusive operation launched
through it must pass the toolkit's AUTHORIZED_LAB authorization gate (case id,
in-scope target, explicit operator confirmation) before execution.
"""
from __future__ import annotations

import re

from security_toolkit.integrations.base import ToolAdapter


class MetasploitAdapter(ToolAdapter):
    binary = "msfconsole"
    config_key = "metasploit"

    def version(self) -> str:
        try:
            proc = self._run(["-v"], timeout=30)
            out = (proc.stdout or proc.stderr)
            m = re.search(r"v?(\d+\.\d+\.\d+)", out)
            return m.group(1) if m else out.strip().splitlines()[0] if out.strip() else ""
        except Exception:
            return ""
