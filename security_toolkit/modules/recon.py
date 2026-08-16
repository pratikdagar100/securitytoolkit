"""Reconnaissance / OSINT module (passive).

Native, dependency-light passive recon: DNS records, IP resolution, reverse
DNS, RDAP (WHOIS-over-HTTP), and TLS certificate metadata. Heavier asset
discovery (subdomains at scale) is delegated to OWASP Amass via the
integrations layer when it is installed.
"""
from __future__ import annotations

import socket
import ssl
from typing import Any, List, Optional
from urllib.parse import urlparse

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule, HttpClient

try:
    import dns.resolver  # dnspython, optional
except Exception:  # pragma: no cover
    dns = None  # type: ignore

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _host_of(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target


class ReconModule(SecurityModule):
    name = "recon"
    description = "Passive reconnaissance / OSINT (DNS, IP, RDAP, TLS)"
    operation_class = "passive"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        auth.authorize(target, "recon", self.operation_class)
        host = _host_of(target)
        result = ScanResult(module=self.name, target=host, profile=auth.profile)

        self._resolve(host, result, auth)
        self._reverse_dns(host, result, auth)
        self._dns_records(host, result, auth)
        self._rdap(host, result, auth)
        self._cert(host, result, auth)
        return result

    # -- steps -----------------------------------------------------------
    def _resolve(self, host: str, result: ScanResult, auth: AuthorizationContext) -> None:
        try:
            infos = socket.getaddrinfo(host, None)
            addrs = sorted({i[4][0] for i in infos})
            result.raw["addresses"] = addrs
            result.add(make_finding(
                "Host resolves", "OSINT", "INFO", "HIGH",
                target=host, evidence=", ".join(addrs),
                recommendation="Informational.", module=self.name,
                case_id=auth.case_id,
            ))
        except Exception as exc:
            result.errors.append(f"resolve: {exc}")

    def _reverse_dns(self, host: str, result: ScanResult, auth: AuthorizationContext) -> None:
        for addr in result.raw.get("addresses", [])[:5]:
            try:
                name, *_ = socket.gethostbyaddr(addr)
                result.raw.setdefault("reverse_dns", {})[addr] = name
            except Exception:
                continue

    def _dns_records(self, host: str, result: ScanResult, auth: AuthorizationContext) -> None:
        if dns is None:
            result.errors.append("dns records: install 'dnspython' for full DNS enumeration")
            return
        records = {}
        for rtype in DNS_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(host, rtype, lifetime=5)
                records[rtype] = [r.to_text() for r in answers]
            except Exception:
                continue
        result.raw["dns"] = records
        if records.get("TXT"):
            joined = " ".join(records["TXT"]).lower()
            if "v=spf1" not in joined:
                result.add(make_finding(
                    "No SPF record found", "OSINT", "LOW", "MEDIUM", target=host,
                    evidence="No 'v=spf1' TXT record present.",
                    impact="Missing SPF can ease email spoofing of this domain.",
                    recommendation="Publish an SPF record scoped to legitimate senders.",
                    reference="https://datatracker.ietf.org/doc/html/rfc7208",
                    module=self.name, case_id=auth.case_id))

    def _rdap(self, host: str, result: ScanResult, auth: AuthorizationContext) -> None:
        try:
            client = HttpClient(self.config)
            resp = client.get(f"https://rdap.org/domain/{host}")
            if resp.status_code == 200:
                data = resp.json()
                result.raw["rdap"] = {
                    "handle": data.get("handle"),
                    "status": data.get("status"),
                    "events": data.get("events"),
                }
        except Exception as exc:
            result.errors.append(f"rdap: {exc}")

    def _cert(self, host: str, result: ScanResult, auth: AuthorizationContext) -> None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            result.raw["certificate"] = {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notAfter": cert.get("notAfter"),
                "subjectAltName": [v for _, v in cert.get("subjectAltName", [])],
            }
        except Exception as exc:
            result.errors.append(f"certificate: {exc}")
