"""Local device security assessment (authorized host).

Collects processes, listening ports, network connections, users and basic
security configuration from the *local* machine. Findings clearly distinguish
Observed / Suspicious / Confirmed / Unknown -- nothing is called malware merely
for being unfamiliar. Uses ``psutil`` when available and degrades gracefully.
"""
from __future__ import annotations

import getpass
import platform
import socket
from typing import Any, Dict, List

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

# Ports that are reasonable to flag as "listening on all interfaces" for review.
SENSITIVE_LISTEN = {23, 21, 3389, 445, 3306, 5432, 6379, 27017, 9200, 11211}


class HostModule:
    name = "host"
    description = "Local device security assessment (processes, ports, users)"
    operation_class = "passive"

    def __init__(self, config=None) -> None:
        self.config = config

    def run(self, target: str = "localhost", auth: AuthorizationContext = None,
            **options: Any) -> ScanResult:
        result = ScanResult(module=self.name, target=platform.node() or "localhost",
                            profile=auth.profile if auth else "PASSIVE")
        result.raw["system"] = {
            "os": platform.platform(),
            "hostname": platform.node(),
            "user": getpass.getuser(),
            "python": platform.python_version(),
        }
        if psutil is None:
            result.errors.append("install 'psutil' for full host assessment "
                                 "(processes, connections, users)")
            self._basic_ports(result, auth)
            return result

        self._listening_ports(result, auth)
        self._processes(result, auth)
        self._users(result, auth)
        return result

    def _basic_ports(self, result: ScanResult, auth) -> None:
        # Fallback: probe a handful of local ports without psutil.
        open_ports = []
        for port in sorted(SENSITIVE_LISTEN | {80, 443, 8080}):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    open_ports.append(port)
        result.raw["local_open_ports"] = open_ports

    def _listening_ports(self, result: ScanResult, auth) -> None:
        listeners: List[Dict[str, Any]] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as exc:
            result.errors.append(f"connections: {exc} (may require elevation)")
            return
        for c in conns:
            if c.status == psutil.CONN_LISTEN and c.laddr:
                entry = {"ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid}
                listeners.append(entry)
                if c.laddr.port in SENSITIVE_LISTEN and c.laddr.ip in ("0.0.0.0", "::"):
                    pname = self._proc_name(c.pid)
                    result.add(make_finding(
                        f"Sensitive service listening on all interfaces: "
                        f"{c.laddr.port}/tcp", "HOST", "MEDIUM", "HIGH",
                        target=f"{c.laddr.ip}:{c.laddr.port}",
                        evidence=f"Process '{pname}' (pid {c.pid}) listening on "
                                 f"{c.laddr.ip}:{c.laddr.port}.",
                        impact="Sensitive services bound to all interfaces increase exposure.",
                        recommendation="Bind to localhost or restrict via firewall if remote "
                                       "access is not required. Status: Observed.",
                        module=self.name, case_id=auth.case_id if auth else ""))
        result.raw["listening_ports"] = listeners

    def _processes(self, result: ScanResult, auth) -> None:
        procs: List[Dict[str, Any]] = []
        for p in psutil.process_iter(attrs=["pid", "name", "username", "exe"]):
            try:
                info = p.info
                procs.append({"pid": info.get("pid"), "name": info.get("name"),
                              "user": info.get("username"), "exe": info.get("exe")})
            except Exception:
                continue
        result.raw["process_count"] = len(procs)
        result.raw["processes"] = procs[:500]

    def _users(self, result: ScanResult, auth) -> None:
        try:
            users = [{"name": u.name, "host": u.host, "started": u.started}
                     for u in psutil.users()]
            result.raw["logged_in_users"] = users
        except Exception:
            pass

    @staticmethod
    def _proc_name(pid) -> str:
        if psutil is None or pid is None:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except Exception:
            return "unknown"
