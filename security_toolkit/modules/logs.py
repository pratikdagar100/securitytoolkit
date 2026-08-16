"""Log & SOC analysis module (mini SIEM).

Parses SSH/auth logs and web access logs (and CSV/JSON of events) and detects
brute-force sources, credential-stuffing indicators, repeated auth failures,
and HTTP scanning patterns. Produces normalized timeline events and findings.
"""
from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult, Event
from security_toolkit.core.risk_engine import make_finding

# sshd: "Failed password for [invalid user ]<user> from <ip> port .."
SSH_FAIL = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd.*Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
SSH_OK = re.compile(
    r"(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd.*Accepted \w+ for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
# common/combined access log
ACCESS = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})')

SCAN_PATHS = ["/.env", "/wp-login", "/phpmyadmin", "/admin", "/.git",
              "/config", "/xmlrpc.php", "/shell", "/.aws", "/actuator"]


class LogAnalysisModule:
    name = "logs"
    description = "Log & SOC analysis (brute-force, scanning, suspicious IPs)"
    operation_class = "passive"

    def __init__(self, config=None) -> None:
        self.config = config

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        # target is a local log file path -- passive analysis, no network.
        path = Path(target)
        result = ScanResult(module=self.name, target=str(path), profile=auth.profile)
        if not path.is_file():
            result.errors.append(f"log file not found: {path}")
            return result

        text = path.read_text(encoding="utf-8", errors="replace")
        fmt = options.get("format") or self._detect_format(path, text)
        result.raw["format"] = fmt

        if fmt == "json":
            events = self._parse_json(text)
        elif fmt == "csv":
            events = self._parse_csv(text)
        elif fmt == "access":
            events = self._parse_access(text)
        else:
            events = self._parse_ssh(text)

        result.raw["parsed_events"] = len(events)
        self._detect_bruteforce(events, result, auth)
        self._detect_scanning(events, result, auth)
        return result

    # -- format detection & parsing -------------------------------------
    def _detect_format(self, path: Path, text: str) -> str:
        suffix = path.suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix == ".csv":
            return "csv"
        head = "\n".join(text.splitlines()[:20])
        if ACCESS.search(head):
            return "access"
        return "ssh"

    def _parse_ssh(self, text: str) -> List[Dict[str, Any]]:
        events = []
        for line in text.splitlines():
            m = SSH_FAIL.search(line)
            if m:
                events.append({"kind": "auth_fail", "ip": m.group("ip"),
                               "user": m.group("user"), "ts": m.group("ts"),
                               "status": "fail"})
                continue
            m = SSH_OK.search(line)
            if m:
                events.append({"kind": "auth_ok", "ip": m.group("ip"),
                               "user": m.group("user"), "ts": m.group("ts"),
                               "status": "ok"})
        return events

    def _parse_access(self, text: str) -> List[Dict[str, Any]]:
        events = []
        for line in text.splitlines():
            m = ACCESS.search(line)
            if m:
                events.append({"kind": "http", "ip": m.group("ip"),
                               "path": m.group("path"), "method": m.group("method"),
                               "status": m.group("status"), "ts": m.group("ts")})
        return events

    def _parse_csv(self, text: str) -> List[Dict[str, Any]]:
        events = []
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            low = {k.lower(): v for k, v in row.items()}
            events.append({
                "kind": low.get("kind", "generic"),
                "ip": low.get("ip") or low.get("source") or low.get("src_ip", ""),
                "user": low.get("user") or low.get("username", ""),
                "status": (low.get("status") or low.get("result", "")).lower(),
                "path": low.get("path", ""),
                "ts": low.get("timestamp") or low.get("time") or low.get("ts", ""),
            })
        return events

    def _parse_json(self, text: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(text)
        except Exception:
            # try JSON-lines
            data = [json.loads(l) for l in text.splitlines() if l.strip()]
        if isinstance(data, dict):
            data = data.get("events", [data])
        events = []
        for row in data:
            low = {k.lower(): v for k, v in row.items()}
            events.append({
                "kind": low.get("kind", "generic"),
                "ip": low.get("ip") or low.get("source") or low.get("src_ip", ""),
                "user": low.get("user") or low.get("username", ""),
                "status": str(low.get("status") or low.get("result", "")).lower(),
                "path": low.get("path", ""),
                "ts": str(low.get("timestamp") or low.get("time") or low.get("ts", "")),
            })
        return events

    # -- detections ------------------------------------------------------
    def _detect_bruteforce(self, events: List[Dict[str, Any]], result: ScanResult,
                          auth: AuthorizationContext, threshold: int = 8) -> None:
        by_ip_fail: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        by_ip_users: Dict[str, set] = defaultdict(set)
        success_after: Dict[str, bool] = defaultdict(bool)

        for ev in events:
            ip = ev.get("ip") or ""
            if not ip:
                continue
            status = ev.get("status", "")
            if ev.get("kind") == "auth_fail" or status in ("fail", "failed", "401", "403"):
                by_ip_fail[ip].append(ev)
                if ev.get("user"):
                    by_ip_users[ip].add(ev["user"])
            if ev.get("kind") == "auth_ok" or status in ("ok", "success", "200"):
                if by_ip_fail.get(ip):
                    success_after[ip] = True

        for ip, fails in by_ip_fail.items():
            if len(fails) < threshold:
                continue
            users = by_ip_users.get(ip, set())
            stuffing = len(users) >= 5
            severity = "HIGH" if (success_after.get(ip) or stuffing) else "MEDIUM"
            confidence = "HIGH" if len(fails) >= threshold * 2 else "MEDIUM"
            title = ("Credential-stuffing indicator" if stuffing
                     else "Potential brute-force source")
            first_ts = fails[0].get("ts", "")
            last_ts = fails[-1].get("ts", "")
            result.add(make_finding(
                f"{title}: {ip}", "SOC", severity, confidence, target=ip,
                evidence=(f"{len(fails)} failed authentications from {ip} targeting "
                          f"{len(users)} account(s) [{', '.join(list(users)[:6])}] "
                          f"between {first_ts} and {last_ts}."
                          + (" A successful login followed the failures." if success_after.get(ip) else "")),
                impact="Repeated failures from one source indicate automated guessing.",
                recommendation="Block/throttle the source IP, enforce account lockout and MFA, "
                               "and review any subsequent successful logins.",
                reference="MITRE ATT&CK T1110 (Brute Force)",
                module=self.name, case_id=auth.case_id))
            result.events.append(Event(
                case_id=auth.case_id, timestamp=last_ts or "", source=result.target,
                category="BRUTE_FORCE", severity=severity, confidence=confidence,
                target=ip, evidence=f"{len(fails)} failed logins"))

    def _detect_scanning(self, events: List[Dict[str, Any]], result: ScanResult,
                        auth: AuthorizationContext) -> None:
        by_ip_paths: Dict[str, set] = defaultdict(set)
        by_ip_404: Dict[str, int] = defaultdict(int)
        by_ip_sensitive: Dict[str, set] = defaultdict(set)
        for ev in events:
            if ev.get("kind") != "http":
                continue
            ip = ev.get("ip", "")
            path = ev.get("path", "")
            by_ip_paths[ip].add(path)
            if ev.get("status") in ("404", "403"):
                by_ip_404[ip] += 1
            if any(s in path.lower() for s in SCAN_PATHS):
                by_ip_sensitive[ip].add(path)

        for ip, paths in by_ip_paths.items():
            sensitive = by_ip_sensitive.get(ip, set())
            noise = by_ip_404.get(ip, 0)
            if len(sensitive) >= 2 or (len(paths) >= 25 and noise >= 15):
                sev = "MEDIUM" if sensitive else "LOW"
                result.add(make_finding(
                    f"HTTP scanning pattern from {ip}", "SOC", sev, "MEDIUM", target=ip,
                    evidence=(f"{len(paths)} distinct paths, {noise} 4xx responses; "
                              f"sensitive probes: {', '.join(list(sensitive)[:6]) or 'none'}."),
                    impact="One source probing many/sensitive paths indicates reconnaissance.",
                    recommendation="Rate-limit or block the source; ensure sensitive paths are "
                                   "not exposed; monitor for follow-up activity.",
                    reference="MITRE ATT&CK T1595 (Active Scanning)",
                    module=self.name, case_id=auth.case_id))
                result.events.append(Event(
                    case_id=auth.case_id, timestamp="", source=result.target,
                    category="SCANNING", severity=sev, confidence="MEDIUM",
                    target=ip, evidence=f"{len(paths)} paths / {noise} 4xx"))
