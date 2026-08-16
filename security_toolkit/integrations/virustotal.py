"""VirusTotal API adapter (hash reputation lookup).

Uses the public v3 API. The API key is read from the environment
(``SECURITY_TOOLKIT_VIRUSTOTAL_API_KEY``) or config; never hard-coded.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from security_toolkit.core.config import Config

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore


class VirusTotalAdapter:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.key = config.api_key("virustotal")

    def available(self) -> bool:
        return bool(self.key) and requests is not None

    def lookup_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        if not self.available():
            return None
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": self.key}, timeout=20,
        )
        if resp.status_code == 404:
            return {"found": False}
        resp.raise_for_status()
        stats = resp.json().get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {})
        return {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
