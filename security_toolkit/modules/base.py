"""Common module interface and shared HTTP client.

Defines the plugin contract (:class:`SecurityModule`) plus a small rate-limited
HTTP helper so every web-facing module behaves consistently and politely.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.config import Config
from security_toolkit.core.models import ScanResult

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore


class SecurityModule:
    """Base contract every assessment/investigation module implements.

    Subclasses set ``name``/``version``/``description`` and implement ``run``.
    This is also the plugin interface for third-party modules.
    """

    name: str = "base"
    version: str = "2.0.0"
    description: str = "Base security module"
    #: operation class used for the authorization gate.
    operation_class: str = "passive"

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config

    def run(self, target: str, auth: AuthorizationContext,
            **options: Any) -> ScanResult:  # pragma: no cover - interface
        raise NotImplementedError


class RateLimiter:
    def __init__(self, per_second: float) -> None:
        self.min_interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


class HttpClient:
    """Thin, rate-limited wrapper over ``requests`` with safe defaults."""

    def __init__(self, config: Optional[Config] = None, *, timeout: Optional[int] = None,
                 rate_limit: float = 5.0) -> None:
        if requests is None:  # pragma: no cover
            raise RuntimeError("The 'requests' package is required for web modules.")
        self.session = requests.Session()
        ua = "CyberShield-Toolkit/2.0 (+authorized-assessment)"
        if config is not None:
            ua = config.get("web.user_agent", ua)
            timeout = timeout or config.get("web.default_timeout", 10)
            rate_limit = config.get("network.rate_limit_per_second", rate_limit)
            proxy = {k: v for k, v in {
                "http": config.get("proxy.http", ""),
                "https": config.get("proxy.https", ""),
            }.items() if v}
            if proxy:
                self.session.proxies.update(proxy)
        self.session.headers.update({"User-Agent": ua})
        self.timeout = timeout or 10
        self.limiter = RateLimiter(rate_limit)

    def request(self, method: str, url: str, *, allow_redirects: bool = True,
                **kwargs: Any):
        self.limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        return self.session.request(method, url, allow_redirects=allow_redirects, **kwargs)

    def get(self, url: str, **kwargs: Any):
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any):
        return self.request("HEAD", url, **kwargs)


def normalize_url(target: str, default_scheme: str = "https") -> str:
    if "://" in target:
        return target
    return f"{default_scheme}://{target}"
