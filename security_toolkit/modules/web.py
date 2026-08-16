"""Website security assessment module (non-destructive).

Observational HTTP(S) checks: redirect behaviour, TLS certificate/expiry,
security headers, cookie attributes, CORS, CSP, server banner leakage,
robots.txt / sitemap.xml, and light technology fingerprinting. Findings never
claim a vulnerability solely because a pattern exists -- each carries evidence,
confidence and a recommendation.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule, HttpClient, normalize_url

SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "MEDIUM",
        "A restrictive CSP reduces the impact of client-side injection.",
        "Implement a Content-Security-Policy appropriate for the app's resources."),
    "strict-transport-security": ("Strict-Transport-Security", "MEDIUM",
        "HSTS forces HTTPS and mitigates SSL-stripping downgrade attacks.",
        "Send Strict-Transport-Security with a long max-age over HTTPS."),
    "x-frame-options": ("X-Frame-Options", "LOW",
        "Absent framing controls can enable clickjacking.",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors directive."),
    "x-content-type-options": ("X-Content-Type-Options", "LOW",
        "Missing nosniff allows MIME-type confusion attacks.",
        "Set X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Referrer-Policy", "INFO",
        "A referrer policy limits leakage of URLs to third parties.",
        "Set a Referrer-Policy such as strict-origin-when-cross-origin."),
    "permissions-policy": ("Permissions-Policy", "INFO",
        "Permissions-Policy restricts powerful browser features.",
        "Define a Permissions-Policy limiting unused features."),
}

TECH_SIGNATURES = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
    "via": "Proxy/CDN",
}


def _host_of(url: str) -> str:
    return urlparse(url).hostname or url


class WebModule(SecurityModule):
    name = "web"
    description = "Website security assessment (headers, TLS, cookies, CORS, CSP)"
    operation_class = "assessment"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        auth.authorize(target, "web assessment", self.operation_class)
        url = normalize_url(target)
        result = ScanResult(module=self.name, target=url, profile=auth.profile)
        client = HttpClient(self.config)

        try:
            resp = client.get(url)
        except Exception as exc:
            result.errors.append(f"request: {exc}")
            return result

        result.raw["status_code"] = resp.status_code
        result.raw["final_url"] = resp.url
        result.raw["headers"] = dict(resp.headers)

        self._check_redirect(client, url, result, auth)
        self._check_tls(url, result, auth)
        self._check_headers(resp, url, result, auth)
        self._check_cookies(resp, url, result, auth)
        self._check_cors(client, url, result, auth)
        self._check_server_leak(resp, url, result, auth)
        self._check_robots_sitemap(client, url, result, auth)
        self._fingerprint(resp, url, result, auth)
        return result

    # -- checks ----------------------------------------------------------
    def _check_redirect(self, client: HttpClient, url: str, result: ScanResult,
                        auth: AuthorizationContext) -> None:
        parsed = urlparse(url)
        http_url = f"http://{parsed.netloc}{parsed.path or '/'}"
        try:
            resp = client.get(http_url, allow_redirects=False)
        except Exception:
            return
        location = resp.headers.get("Location", "")
        redirects_https = resp.status_code in (301, 302, 307, 308) and location.startswith("https")
        if not redirects_https:
            result.add(make_finding(
                "HTTP does not redirect to HTTPS", "WEB_SECURITY", "MEDIUM", "MEDIUM",
                target=url, evidence=f"GET {http_url} -> {resp.status_code} "
                                     f"Location: {location or '(none)'}",
                impact="Users may be served content over plaintext HTTP.",
                recommendation="Force an HTTP->HTTPS redirect and enable HSTS.",
                reference="OWASP Transport Layer Protection Cheat Sheet",
                module=self.name, case_id=auth.case_id))

    def _check_tls(self, url: str, result: ScanResult, auth: AuthorizationContext) -> None:
        host = _host_of(url)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
        except Exception as exc:
            result.add(make_finding(
                "TLS handshake failed", "WEB_SECURITY", "MEDIUM", "MEDIUM",
                target=url, evidence=str(exc),
                impact="HTTPS may be misconfigured or unavailable.",
                recommendation="Verify certificate installation and TLS configuration.",
                module=self.name, case_id=auth.case_id))
            return

        result.raw["tls"] = {"protocol": proto, "notAfter": cert.get("notAfter")}
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (expires - datetime.now(timezone.utc)).days
                result.raw["tls"]["days_to_expiry"] = days
                if days < 0:
                    sev, conf = "HIGH", "HIGH"
                    msg = "Certificate has EXPIRED."
                elif days < 15:
                    sev, conf = "MEDIUM", "HIGH"
                    msg = f"Certificate expires in {days} days."
                else:
                    sev, conf, msg = None, None, ""
                if sev:
                    result.add(make_finding(
                        "TLS certificate expiry", "WEB_SECURITY", sev, conf, target=url,
                        evidence=f"notAfter={not_after} ({msg})",
                        impact="An expired/soon-to-expire cert breaks trust and availability.",
                        recommendation="Renew the certificate and automate renewal.",
                        module=self.name, case_id=auth.case_id))
            except Exception:
                pass
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            result.add(make_finding(
                f"Weak TLS protocol negotiated ({proto})", "WEB_SECURITY", "MEDIUM", "HIGH",
                target=url, evidence=f"Negotiated protocol: {proto}",
                impact="Deprecated TLS versions have known weaknesses.",
                recommendation="Disable TLS < 1.2; prefer TLS 1.2/1.3.",
                module=self.name, case_id=auth.case_id))

    def _check_headers(self, resp, url: str, result: ScanResult,
                       auth: AuthorizationContext) -> None:
        present = {k.lower() for k in resp.headers.keys()}
        for key, (label, sev, impact, rec) in SECURITY_HEADERS.items():
            if key not in present:
                result.add(make_finding(
                    f"Missing {label}", "WEB_SECURITY", sev, "HIGH", target=url,
                    evidence=f"The HTTP response did not contain a {label} header.",
                    impact=impact, recommendation=rec,
                    reference="OWASP Secure Headers Project",
                    module=self.name, case_id=auth.case_id))

    def _check_cookies(self, resp, url: str, result: ScanResult,
                      auth: AuthorizationContext) -> None:
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure")
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in [
                    k.lower() for k in cookie._rest.keys()]:
                issues.append("missing HttpOnly")
            samesite = [v for k, v in cookie._rest.items() if k.lower() == "samesite"]
            if not samesite:
                issues.append("missing SameSite")
            if issues:
                result.add(make_finding(
                    f"Cookie '{cookie.name}' weak attributes", "WEB_SECURITY", "LOW", "MEDIUM",
                    target=url, evidence=f"Cookie '{cookie.name}': {', '.join(issues)}",
                    impact="Cookies without Secure/HttpOnly/SameSite are more exposed to "
                           "theft or CSRF.",
                    recommendation="Set Secure, HttpOnly and an appropriate SameSite value.",
                    reference="OWASP Session Management Cheat Sheet",
                    module=self.name, case_id=auth.case_id))

    def _check_cors(self, client: HttpClient, url: str, result: ScanResult,
                   auth: AuthorizationContext) -> None:
        try:
            resp = client.get(url, headers={"Origin": "https://evil.example"})
        except Exception:
            return
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            result.add(make_finding(
                "Overly permissive CORS with credentials", "WEB_SECURITY", "HIGH", "HIGH",
                target=url,
                evidence="Access-Control-Allow-Origin: * together with "
                         "Access-Control-Allow-Credentials: true",
                impact="This combination can expose authenticated data cross-origin.",
                recommendation="Reflect only trusted origins; never combine '*' with credentials.",
                reference="OWASP CORS guidance",
                module=self.name, case_id=auth.case_id))
        elif acao == "https://evil.example":
            result.add(make_finding(
                "CORS reflects arbitrary Origin", "WEB_SECURITY", "MEDIUM", "HIGH",
                target=url, evidence=f"Reflected Origin in Access-Control-Allow-Origin: {acao}",
                impact="Reflecting any Origin can enable cross-origin data theft.",
                recommendation="Validate Origin against an allowlist.",
                module=self.name, case_id=auth.case_id))

    def _check_server_leak(self, resp, url: str, result: ScanResult,
                          auth: AuthorizationContext) -> None:
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        leaks = [v for v in (server, powered) if any(ch.isdigit() for ch in v)]
        if leaks:
            result.add(make_finding(
                "Server version disclosure", "WEB_SECURITY", "LOW", "MEDIUM", target=url,
                evidence="; ".join(filter(None, [f"Server: {server}" if server else "",
                                                 f"X-Powered-By: {powered}" if powered else ""])),
                impact="Precise version banners help attackers match known exploits.",
                recommendation="Suppress or genericize version banners.",
                module=self.name, case_id=auth.case_id))

    def _check_robots_sitemap(self, client: HttpClient, url: str, result: ScanResult,
                             auth: AuthorizationContext) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in ("/robots.txt", "/sitemap.xml"):
            try:
                resp = client.get(base + path)
                if resp.status_code == 200 and resp.text.strip():
                    result.raw.setdefault("discovery", {})[path] = resp.text[:2000]
                    if path == "/robots.txt":
                        disallow = [ln for ln in resp.text.splitlines()
                                    if ln.lower().startswith("disallow")]
                        if disallow:
                            result.add(make_finding(
                                "robots.txt discloses paths", "WEB_SECURITY", "INFO", "HIGH",
                                target=base + path,
                                evidence="; ".join(disallow[:10]),
                                impact="Disallowed paths can hint at sensitive locations.",
                                recommendation="Do not rely on robots.txt to protect sensitive paths.",
                                module=self.name, case_id=auth.case_id))
            except Exception:
                continue

    def _fingerprint(self, resp, url: str, result: ScanResult,
                    auth: AuthorizationContext) -> None:
        tech: Dict[str, str] = {}
        for key, label in TECH_SIGNATURES.items():
            if key in {k.lower() for k in resp.headers}:
                value = resp.headers.get(key) or resp.headers.get(label, "")
                if value:
                    tech[label] = value
        if tech:
            result.raw["technology"] = tech
