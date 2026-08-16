"""Nuclei adapter (template-based scanning).

Runs Nuclei in JSON-lines mode and normalizes matches into finding dicts.
Nuclei is an assessment-class tool: callers must pass an authorized target.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from security_toolkit.integrations.base import ToolAdapter, ToolNotAvailable

SEVERITY_MAP = {"info": "INFO", "low": "LOW", "medium": "MEDIUM",
                "high": "HIGH", "critical": "CRITICAL"}


class NucleiAdapter(ToolAdapter):
    binary = "nuclei"
    config_key = "nuclei"

    def version(self) -> str:
        try:
            proc = self._run(["-version"], timeout=15)
            out = (proc.stderr or proc.stdout)
            m = re.search(r"([\d.]+)", out)
            return m.group(1) if m else ""
        except Exception:
            return ""

    def scan(self, target: str, timeout: int = 600) -> List[Dict[str, Any]]:
        if not self.available():
            raise ToolNotAvailable("nuclei not installed")
        proc = self._run(["-u", target, "-jsonl", "-silent", "-duc"], timeout=timeout)
        findings: List[Dict[str, Any]] = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            info = obj.get("info", {})
            findings.append({
                "title": info.get("name", obj.get("template-id", "nuclei match")),
                "severity": SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "INFO"),
                "target": obj.get("matched-at", target),
                "evidence": obj.get("template-id", ""),
                "reference": ", ".join(info.get("reference", []) or []),
            })
        return findings
