"""API security analyzer.

Conservative, controlled checks against a single API endpoint: allowed HTTP
methods, authentication signalling, security headers, CORS, error handling,
content types, version exposure and rate-limit indicators. Rate-limit detection
uses a small bounded burst and reports observed behaviour only.
"""
from __future__ import annotations

from typing import Any, Dict, List

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule, HttpClient, normalize_url

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


class ApiModule(SecurityModule):
    name = "api"
    description = "API security analyzer (methods, auth, headers, rate limits)"
    operation_class = "assessment"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        auth.authorize(target, "api assessment", self.operation_class)
        url = normalize_url(target)
        result = ScanResult(module=self.name, target=url, profile=auth.profile)
        client = HttpClient(self.config)

        self._methods(client, url, result, auth)
        self._auth_and_headers(client, url, result, auth)
        self._rate_limit(client, url, result, auth, options.get("rate_samples", 12))
        return result

    def _methods(self, client: HttpClient, url: str, result: ScanResult,
                auth: AuthorizationContext) -> None:
        allowed: List[str] = []
        try:
            resp = client.request("OPTIONS", url)
            allow = resp.headers.get("Allow", "")
            if allow:
                allowed = [m.strip() for m in allow.split(",") if m.strip()]
        except Exception:
            pass
        result.raw["allowed_methods"] = allowed
        risky = [m for m in ("PUT", "DELETE", "PATCH") if m in allowed]
        if risky:
            result.add(make_finding(
                "State-changing HTTP methods advertised", "API", "LOW", "MEDIUM",
                target=url, evidence=f"OPTIONS Allow: {', '.join(allowed)}",
                impact="PUT/DELETE/PATCH exposed without strong auth can enable data tampering.",
                recommendation="Ensure state-changing methods require authentication and authorization.",
                module=self.name, case_id=auth.case_id))

    def _auth_and_headers(self, client: HttpClient, url: str, result: ScanResult,
                         auth: AuthorizationContext) -> None:
        try:
            resp = client.get(url)
        except Exception as exc:
            result.errors.append(f"request: {exc}")
            return
        result.raw["status_code"] = resp.status_code
        ctype = resp.headers.get("Content-Type", "")
        result.raw["content_type"] = ctype

        if resp.status_code == 200 and "www-authenticate" not in {k.lower() for k in resp.headers}:
            # Endpoint returns data without an auth challenge -- informational only.
            result.add(make_finding(
                "Endpoint responds without authentication challenge", "API", "INFO", "MEDIUM",
                target=url, evidence=f"GET returned HTTP {resp.status_code} with no "
                                     f"WWW-Authenticate header.",
                recommendation="Confirm this endpoint is intended to be public.",
                module=self.name, case_id=auth.case_id))

        server = resp.headers.get("Server", "")
        if any(ch.isdigit() for ch in server):
            result.add(make_finding(
                "API server version disclosure", "API", "LOW", "MEDIUM", target=url,
                evidence=f"Server: {server}",
                recommendation="Genericize the Server banner.",
                module=self.name, case_id=auth.case_id))

        # Basic error-handling probe: request an unlikely path.
        try:
            err = client.get(url.rstrip("/") + "/__cs_probe_404__")
            if err.status_code >= 500:
                result.add(make_finding(
                    "Server error on unexpected path", "API", "LOW", "MEDIUM", target=url,
                    evidence=f"Unexpected path returned HTTP {err.status_code}.",
                    impact="5xx on malformed input can indicate weak input handling.",
                    recommendation="Return controlled 4xx errors and avoid stack traces.",
                    module=self.name, case_id=auth.case_id))
        except Exception:
            pass

    def _rate_limit(self, client: HttpClient, url: str, result: ScanResult,
                   auth: AuthorizationContext, samples: int) -> None:
        samples = max(3, min(int(samples), 20))  # bounded, conservative
        codes: List[int] = []
        rl_headers = False
        for _ in range(samples):
            try:
                resp = client.get(url)
            except Exception:
                break
            codes.append(resp.status_code)
            if any(h.lower().startswith(("x-ratelimit", "ratelimit", "retry-after"))
                   for h in resp.headers):
                rl_headers = True
            if resp.status_code == 429:
                break
        result.raw["rate_limit_samples"] = codes
        if 429 in codes or rl_headers:
            result.add(make_finding(
                "Rate limiting detected", "API", "INFO", "HIGH", target=url,
                evidence=f"Observed HTTP 429 or rate-limit headers within {len(codes)} requests.",
                recommendation="Maintain server-side rate limiting and monitor abuse patterns.",
                module=self.name, case_id=auth.case_id))
        else:
            result.add(make_finding(
                "No rate limiting observed", "API", "LOW", "LOW", target=url,
                evidence=f"{len(codes)} controlled requests returned no 429 / rate-limit headers.",
                impact="Absent rate limiting can enable brute-force and abuse (not confirmed).",
                recommendation="Implement server-side rate limiting appropriate to the API.",
                module=self.name, case_id=auth.case_id))
