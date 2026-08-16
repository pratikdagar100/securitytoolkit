"""XSS exposure detection module (reflection analysis).

Prioritizes passive reflection analysis: it sends a unique benign marker per
parameter and inspects whether/where it is reflected and whether it appears
unencoded in a dangerous HTML context. It never executes browser payloads;
active DOM/browser testing is reserved for AUTHORIZED_LAB tooling.
"""
from __future__ import annotations

import html
import uuid
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule, HttpClient, normalize_url


class XssModule(SecurityModule):
    name = "xss"
    description = "Reflected XSS exposure check (reflection/context analysis)"
    operation_class = "assessment"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        auth.authorize(target, "xss exposure check", self.operation_class)
        url = normalize_url(target, default_scheme="http")
        result = ScanResult(module=self.name, target=url, profile=auth.profile)

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            result.add(make_finding(
                "No testable URL parameters", "XSS", "INFO", "HIGH", target=url,
                evidence="The URL has no query parameters to analyze.",
                recommendation="Provide a URL with parameters to test reflection.",
                module=self.name, case_id=auth.case_id))
            return result

        client = HttpClient(self.config)
        for param in params:
            self._test_param(client, parsed, params, param, result, auth)
        return result

    def _test_param(self, client: HttpClient, parsed, params: Dict[str, List[str]],
                    param: str, result: ScanResult, auth: AuthorizationContext) -> None:
        marker = "cs" + uuid.uuid4().hex[:10] + "xz"
        # A marker with harmless-but-distinctive chars to test HTML encoding.
        probe = f'{marker}<">'
        test_params = {k: v[:] for k, v in params.items()}
        test_params[param] = [probe]
        query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=query))
        try:
            resp = client.get(test_url)
        except Exception as exc:
            result.errors.append(f"{param}: {exc}")
            return
        body = resp.text
        if marker not in body:
            return  # not reflected

        raw_reflected = probe in body               # angle brackets survived unencoded
        encoded_reflected = html.escape(probe) in body
        if raw_reflected:
            result.add(make_finding(
                f"Unencoded reflection of parameter '{param}'", "XSS", "HIGH", "MEDIUM",
                target=result.target,
                evidence=f"Injected marker with '<\">' characters was reflected "
                         f"WITHOUT HTML encoding.",
                impact="Unencoded reflection of user input is a strong indicator of a "
                       "reflected XSS exposure.",
                recommendation="Apply context-aware output encoding; validate input. Confirm "
                               "in an authorized lab before declaring exploitable.",
                reference="OWASP XSS Prevention Cheat Sheet",
                module=self.name, case_id=auth.case_id))
        elif encoded_reflected:
            result.add(make_finding(
                f"Input reflected but HTML-encoded in '{param}'", "XSS", "INFO", "HIGH",
                target=result.target,
                evidence="Marker reflected with HTML entities encoded (defensive behavior).",
                recommendation="Reflection is encoded; verify all output contexts remain safe.",
                module=self.name, case_id=auth.case_id))
        else:
            result.add(make_finding(
                f"Marker reflected in '{param}' (partial)", "XSS", "LOW", "LOW",
                target=result.target,
                evidence="Marker string reflected; special characters not observed intact.",
                recommendation="Review the reflection context manually.",
                module=self.name, case_id=auth.case_id))
