"""Configuration system.

Loads settings from ``config.yaml`` (if present) merged over sane defaults,
then overlays environment variables. API keys are *never* stored in source and
are read from the environment where possible.

Cross-platform: the workspace lives under the user's home directory unless the
config or ``SECURITY_TOOLKIT_HOME`` overrides it.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

try:  # PyYAML is a declared dependency but degrade gracefully if missing.
    import yaml
except Exception:  # pragma: no cover
    yaml = None  # type: ignore


ENV_PREFIX = "SECURITY_TOOLKIT_"

DEFAULTS: Dict[str, Any] = {
    "workspace": "",  # resolved below to ~/.security_toolkit
    "logging": {"level": "INFO"},
    "network": {
        "default_timeout": 5,
        "rate_limit_per_second": 5,
        "profiles": {
            "QUICK": {"top_ports": 100},
            "STANDARD": {"top_ports": 1000},
            "DETAILED": {"top_ports": 5000},
            "FORENSIC": {"top_ports": 65535},
        },
    },
    "web": {"default_timeout": 10, "user_agent": "CyberShield-Toolkit/2.0 (+authorized-assessment)"},
    "availability": {"samples": 15, "timeout": 5},
    "profiles": {"default": "PASSIVE"},
    "tools": {  # external binary locations; empty => auto-detect via PATH
        "nmap": "",
        "amass": "",
        "nuclei": "",
        "yara": "",
        "oui_file": "",  # optional IEEE oui.txt for full MAC-vendor coverage
    },
    "wordlists": {
        # SecLists is the recommended source of passwords / patterns / payloads.
        # https://github.com/danielmiessler/SecLists  (clone locally, then point here)
        "seclists_path": "",
        "subdomains": "",
        "common_passwords": "",
    },
    "api_keys": {  # prefer environment variables; these are fallbacks only
        "virustotal": "",
        "shodan": "",
    },
    "proxy": {"http": "", "https": ""},
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Immutable-ish view over merged configuration."""

    def __init__(self, data: Dict[str, Any], source: Optional[Path] = None) -> None:
        self._data = data
        self.source = source

    def get(self, dotted_key: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted_key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    @property
    def workspace(self) -> Path:
        raw = self.get("workspace") or os.environ.get(ENV_PREFIX + "HOME")
        if raw:
            return Path(raw).expanduser().resolve()
        return (Path.home() / ".security_toolkit").resolve()

    def api_key(self, service: str) -> str:
        """Resolve an API key: environment variable wins over config file."""
        env_key = ENV_PREFIX + service.upper() + "_API_KEY"
        return os.environ.get(env_key) or str(self.get(f"api_keys.{service}", "") or "")

    def as_dict(self) -> Dict[str, Any]:
        return dict(self._data)


def load_config(path: Optional[str] = None) -> Config:
    """Load config from an explicit path, ``./config.yaml``, or the workspace."""
    data = dict(DEFAULTS)
    candidates = []
    if path:
        candidates.append(Path(path))
    candidates.append(Path.cwd() / "config.yaml")
    candidates.append(Path.home() / ".security_toolkit" / "config.yaml")

    chosen: Optional[Path] = None
    for candidate in candidates:
        if candidate.is_file():
            chosen = candidate
            break

    if chosen and yaml is not None:
        try:
            loaded = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data = _deep_merge(data, loaded)
        except Exception:
            pass  # a broken config file should never crash the toolkit

    return Config(data, chosen)
