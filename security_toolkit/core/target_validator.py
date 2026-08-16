"""Target validation and classification.

Classifies a raw target string (IP / CIDR / domain / URL / host / file) and
checks whether it falls inside an authorized scope. Scope matching supports
exact values, domain suffixes, and CIDR membership.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
)


@dataclass
class ValidationResult:
    valid: bool
    target_type: str
    normalized: str
    reason: str = ""


def classify(target: str) -> ValidationResult:
    """Classify a target string without any network activity."""
    raw = (target or "").strip()
    if not raw:
        return ValidationResult(False, "unknown", "", "empty target")

    # URL
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return ValidationResult(True, "url", raw)
        return ValidationResult(False, "url", raw, "unsupported URL scheme")

    # CIDR
    if "/" in raw and not raw.startswith("."):
        try:
            net = ipaddress.ip_network(raw, strict=False)
            return ValidationResult(True, "cidr", str(net))
        except ValueError:
            pass  # maybe it's a file path

    # IP
    try:
        ip = ipaddress.ip_address(raw)
        return ValidationResult(True, "ip", str(ip))
    except ValueError:
        pass

    # File path
    if Path(raw).exists():
        return ValidationResult(True, "file", str(Path(raw).resolve()))

    # Domain / host
    if _DOMAIN_RE.match(raw):
        return ValidationResult(True, "domain", raw.lower())
    if re.match(r"^[A-Za-z0-9._-]+$", raw):
        return ValidationResult(True, "host", raw.lower())

    return ValidationResult(False, "unknown", raw, "unrecognized target format")


def _host_of(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target


def in_scope(target: str, scopes: List[str]) -> bool:
    """Return True if ``target`` is covered by any scope entry.

    An empty scope list means *nothing* is pre-authorized -- the caller must
    still confirm. Scope entries may be IPs, CIDRs, exact hosts, or domain
    suffixes (``example.com`` authorizes ``api.example.com``).
    """
    if not scopes:
        return False

    host = _host_of(target).lower().rstrip(".")
    target_ip = None
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None

    for scope in scopes:
        scope = (scope or "").strip().lower().rstrip(".")
        if not scope:
            continue
        if host == scope:
            return True
        # CIDR / network membership
        try:
            net = ipaddress.ip_network(scope, strict=False)
            if target_ip is not None and target_ip in net:
                return True
            continue
        except ValueError:
            pass
        # domain suffix match
        if host.endswith("." + scope):
            return True
    return False
