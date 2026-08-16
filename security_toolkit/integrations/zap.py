"""OWASP ZAP adapter (detection + controlled execution scaffold).

ZAP is a controlled, assessment/lab-class tool. This adapter detects the ZAP
CLI and exposes a guarded entry point; active scanning must be driven under an
AUTHORIZED_LAB profile with an explicit in-scope target. Full ZAP automation
(API daemon orchestration) is a documented roadmap item.
"""
from __future__ import annotations

from security_toolkit.integrations.base import ToolAdapter


class ZapAdapter(ToolAdapter):
    binary = "zap.sh"          # 'zap.bat' on Windows; override via config tools.zap
    config_key = "zap"

    def version(self) -> str:
        try:
            proc = self._run(["-version"], timeout=20)
            return (proc.stdout or proc.stderr).strip().splitlines()[0] if (proc.stdout or proc.stderr) else ""
        except Exception:
            return ""
