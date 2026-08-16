"""Generic external-tool adapter interface.

Adapters wrap a CLI binary. The base class handles cross-platform binary
detection (config override -> PATH via ``shutil.which``) and safe subprocess
execution with captured stdout/stderr. Subclasses implement version parsing and
the tool-specific ``run``/parse logic.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence

from security_toolkit.core.config import Config


class ToolNotAvailable(Exception):
    pass


class ToolAdapter:
    #: binary name to look up on PATH.
    binary: str = ""
    #: config key under ``tools.<name>`` for an explicit path.
    config_key: str = ""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config
        self._path: Optional[str] = None

    def path(self) -> Optional[str]:
        if self._path:
            return self._path
        override = ""
        if self.config is not None and self.config_key:
            override = str(self.config.get(f"tools.{self.config_key}", "") or "")
        if override and Path(override).exists():
            self._path = override
        else:
            self._path = shutil.which(self.binary)
        return self._path

    def available(self) -> bool:
        return self.path() is not None

    def version(self) -> str:
        return ""

    def _run(self, args: Sequence[str], timeout: int = 120) -> subprocess.CompletedProcess:
        exe = self.path()
        if not exe:
            raise ToolNotAvailable(f"{self.binary} is not installed / not on PATH")
        return subprocess.run(
            [exe, *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
