"""YARA adapter (rule matching for file triage).

Prefers the ``yara-python`` binding when installed; otherwise falls back to the
``yara`` CLI. Returns the list of matching rule names for a file.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from security_toolkit.integrations.base import ToolAdapter

try:
    import yara as yara_py
except Exception:  # pragma: no cover
    yara_py = None  # type: ignore


class YaraAdapter(ToolAdapter):
    binary = "yara"
    config_key = "yara"

    def available(self) -> bool:
        return yara_py is not None or super().available()

    def match(self, file_path: str, rules_path: str) -> List[str]:
        if not Path(rules_path).exists():
            return []
        if yara_py is not None:
            rules = yara_py.compile(filepath=rules_path)
            return [m.rule for m in rules.match(file_path)]
        # CLI fallback
        if super().available():
            proc = self._run([rules_path, file_path], timeout=60)
            return [line.split()[0] for line in (proc.stdout or "").splitlines() if line.strip()]
        return []
