"""SQL injection *exposure* detection module.

SAFE MODE (default): identifies URL parameters, sends a small set of benign
probe characters and looks for database *error signatures* and response
differentials. It never extracts data, dumps credentials, modifies databases,
or bypasses authentication.

AUTHORIZED LAB MODE: a separate, explicitly gated path for intentionally
vulnerable systems. It still only performs error/differential analysis here --
data extraction is intentionally out of scope and delegated to dedicated,
authorized tooling.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from security_toolkit.core.authorization import AuthorizationContext, AUTHORIZED_LAB
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule, HttpClient, normalize_url

# Benign probes: a lone quote and a couple of boolean pairs. No data extraction.
SAFE_PROBES = ["'", "''", "' AND '1'='1", "' AND '1'='2"]

DB_ERROR_SIGNATURES = [
    (r"sql syntax.*mysql", "MySQL"),
    (r"warning.*mysqli?_", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"pg_query\(\)|postgresql.*error", "PostgreSQL"),
    (r"sqlite3?.*(error|exception)", "SQLite"),
    (r"ora-\d{5}", "Oracle"),
    (r"you have an error in your sql syntax", "MySQL"),
]


class SqlInjectionModule(SecurityModule):
    name = "sqli"
    description = "SQL injection exposure check (safe error/differential analysis)"
    operation_class = "assessment"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        lab = bool(options.get("lab")) and auth.profile == AUTHORIZED_LAB
        op_class = "intrusive" if lab else "assessment"
        auth.authorize(target, "sql injection exposure check", op_class)

        url = normalize_url(target, default_scheme="http")
        result = ScanResult(module=self.name, target=url, profile=auth.profile)
        result.raw["mode"] = "AUTHORIZED_LAB" if lab else "SAFE"

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            result.add(make_finding(
                "No testable URL parameters", "SQLI", "INFO", "HIGH", target=url,
                evidence="The URL has no query parameters to analyze.",
                recommendation="Provide a URL with parameters, e.g. ?id=1.",
                module=self.name, case_id=auth.case_id))
            return result

        client = HttpClient(self.config)
        try:
            baseline = client.get(url)
            base_len = len(baseline.text)
        except Exception as exc:
            result.errors.append(f"baseline: {exc}")
            return result

        for param in params:
            self._test_param(client, parsed, params, param, base_len, result, auth)
        return result

    def _test_param(self, client: HttpClient, parsed, params: Dict[str, List[str]],
                    param: str, base_len: int, result: ScanResult,
                    auth: AuthorizationContext) -> None:
        error_hit = None
        lengths: Dict[str, int] = {}
        for probe in SAFE_PROBES:
            test_params = {k: v[:] for k, v in params.items()}
            test_params[param] = [probe]
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))
            try:
                resp = client.get(test_url)
            except Exception:
                continue
            lengths[probe] = len(resp.text)
            for pattern, dbms in DB_ERROR_SIGNATURES:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    error_hit = (dbms, probe, pattern)
                    break
            if error_hit:
                break

        if error_hit:
            dbms, probe, _ = error_hit
            result.add(make_finding(
                f"Database error signature in parameter '{param}'", "SQLI",
                "HIGH", "MEDIUM", target=result.target,
                evidence=f"Probe {probe!r} elicited a {dbms} error signature in the response.",
                impact="Error leakage on crafted input is a strong indicator of unsafe "
                       "query construction (possible SQL injection).",
                recommendation="Use parameterized queries / prepared statements and suppress "
                               "database error details in responses. Confirm in an authorized "
                               "lab before treating as a confirmed vulnerability.",
                reference="OWASP SQL Injection Prevention Cheat Sheet",
                module=self.name, case_id=auth.case_id))
            return

        # Boolean differential: true-condition vs false-condition length divergence.
        t = lengths.get("' AND '1'='1")
        f = lengths.get("' AND '1'='2")
        if t is not None and f is not None and abs(t - f) > max(40, int(0.05 * base_len)):
            result.add(make_finding(
                f"Response differential on boolean payloads in '{param}'", "SQLI",
                "MEDIUM", "LOW", target=result.target,
                evidence=f"true-condition len={t}, false-condition len={f} "
                         f"(baseline={base_len}).",
                impact="A significant true/false response difference *may* indicate "
                       "boolean-based SQL injection, but can also be normal app behavior.",
                recommendation="Manually verify in an authorized environment; do not treat "
                               "as confirmed based on differential alone.",
                reference="OWASP Testing Guide - SQL Injection",
                module=self.name, case_id=auth.case_id))
