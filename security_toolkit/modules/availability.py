"""Availability / DoS *symptom* analysis module.

This is NOT a DoS generator. It performs a small, controlled sample of requests
and reports latency/failure statistics and a stability classification. It never
declares a confirmed DoS from client-side latency alone.
"""
from __future__ import annotations

import statistics
import time
from typing import Any, List

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule, HttpClient, normalize_url

NORMAL, DEGRADED, UNSTABLE, UNAVAILABLE = "NORMAL", "DEGRADED", "UNSTABLE", "UNAVAILABLE"


class AvailabilityModule(SecurityModule):
    name = "availability"
    description = "Availability / service-degradation symptom analysis"
    operation_class = "assessment"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        auth.authorize(target, "availability analysis", self.operation_class)
        url = normalize_url(target)
        result = ScanResult(module=self.name, target=url, profile=auth.profile)

        samples = int(options.get("samples") or
                      (self.config.get("availability.samples", 15) if self.config else 15))
        samples = max(5, min(samples, 50))
        client = HttpClient(self.config)

        times: List[float] = []
        codes: List[int] = []
        failures = 0
        for _ in range(samples):
            start = time.monotonic()
            try:
                resp = client.get(url)
                times.append(time.monotonic() - start)
                codes.append(resp.status_code)
            except Exception:
                failures += 1

        failure_rate = failures / samples
        code_dist: dict = {}
        for c in codes:
            code_dist[c] = code_dist.get(c, 0) + 1

        stats = {
            "samples": samples,
            "failures": failures,
            "failure_rate": round(failure_rate, 3),
            "status_codes": code_dist,
        }
        if times:
            stats.update({
                "avg_ms": round(statistics.mean(times) * 1000, 1),
                "min_ms": round(min(times) * 1000, 1),
                "max_ms": round(max(times) * 1000, 1),
                "stdev_ms": round((statistics.stdev(times) if len(times) > 1 else 0) * 1000, 1),
            })
        result.raw["availability"] = stats

        status = self._classify(failure_rate, stats)
        result.raw["status"] = status

        sev = {"NORMAL": "INFO", "DEGRADED": "LOW", "UNSTABLE": "MEDIUM",
               "UNAVAILABLE": "HIGH"}[status]
        evidence = (f"{samples} controlled requests: failure_rate={failure_rate:.0%}, "
                    f"avg={stats.get('avg_ms', 'n/a')}ms, codes={code_dist}.")
        if status in (UNSTABLE, UNAVAILABLE, DEGRADED):
            result.add(make_finding(
                f"Possible service degradation ({status})", "AVAILABILITY", sev, "LOW",
                target=url, evidence=evidence,
                impact="Client-side symptoms only. Additional server-side evidence is "
                       "required to confirm a DoS/DDoS incident.",
                recommendation="Correlate with server metrics/logs before concluding an incident.",
                module=self.name, case_id=auth.case_id))
        else:
            result.add(make_finding(
                "Service appears stable", "AVAILABILITY", "INFO", "MEDIUM", target=url,
                evidence=evidence, recommendation="No action required from this sample.",
                module=self.name, case_id=auth.case_id))
        return result

    @staticmethod
    def _classify(failure_rate: float, stats: dict) -> str:
        if failure_rate >= 0.8:
            return UNAVAILABLE
        avg = stats.get("avg_ms", 0)
        stdev = stats.get("stdev_ms", 0)
        if failure_rate >= 0.3 or (avg and stdev > avg):
            return UNSTABLE
        if (avg and avg > 2000) or failure_rate >= 0.1:
            return DEGRADED
        return NORMAL
