"""Network assessment module.

Native, non-aggressive TCP connect scanning with a bounded thread pool and
banner sampling. When Nmap is installed it is used as the backend for richer
service/OS detection via the integrations layer; the toolkit normalizes either
source into the same finding schema.

Scan profiles: QUICK / STANDARD / DETAILED / FORENSIC. Aggressive scans are
never run automatically.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding
from security_toolkit.modules.base import SecurityModule

# Common ports sampled per profile (native scanner). Nmap covers the full range.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
                445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306,
                3389, 5432, 5601, 5900, 5985, 6379, 8000, 8080, 8443, 9000,
                9200, 11211, 27017]

PROFILE_PORTS = {
    "QUICK": COMMON_PORTS[:12],
    "STANDARD": COMMON_PORTS,
    "DETAILED": COMMON_PORTS,   # nmap adds coverage when present
    "FORENSIC": COMMON_PORTS,
}

RISKY_PORTS = {
    23: ("Telnet", "Cleartext remote administration protocol exposed."),
    3389: ("RDP", "Remote Desktop exposed; a frequent brute-force target."),
    445: ("SMB", "SMB exposed; historically abused by worms/ransomware."),
    3306: ("MySQL", "Database port reachable; should not be internet-exposed."),
    5432: ("PostgreSQL", "Database port reachable; should not be internet-exposed."),
    6379: ("Redis", "Redis often unauthenticated by default; high risk if exposed."),
    27017: ("MongoDB", "MongoDB exposed; check authentication."),
    9200: ("Elasticsearch", "Elasticsearch exposed; often unauthenticated."),
    11211: ("Memcached", "Memcached exposed; usable in amplification attacks."),
}


class NetworkModule(SecurityModule):
    name = "network"
    description = "Network host/service discovery (native TCP + optional Nmap)"
    operation_class = "assessment"

    def run(self, target: str, auth: AuthorizationContext, **options: Any) -> ScanResult:
        auth.authorize(target, "network scan", self.operation_class)
        profile = (options.get("profile") or auth.profile or "STANDARD").upper()
        result = ScanResult(module=self.name, target=target, profile=profile)

        use_nmap = bool(options.get("use_nmap", True))
        nmap_result = None
        if use_nmap:
            nmap_result = self._try_nmap(target, profile, result, auth)

        if nmap_result is None:
            self._native_scan(target, profile, result, auth)

        return result

    # -- nmap backend ----------------------------------------------------
    def _try_nmap(self, target: str, profile: str, result: ScanResult,
                  auth: AuthorizationContext) -> Optional[Dict[str, Any]]:
        try:
            from security_toolkit.integrations.nmap import NmapAdapter
        except Exception:
            return None
        adapter = NmapAdapter(self.config)
        if not adapter.available():
            result.raw["nmap"] = "not installed (using native scanner)"
            return None
        try:
            parsed = adapter.scan(target, profile)
        except Exception as exc:
            result.errors.append(f"nmap: {exc}")
            return None
        result.raw["backend"] = "nmap"
        result.raw["nmap_version"] = adapter.version()
        result.raw["hosts"] = parsed
        for host in parsed:
            for port in host.get("ports", []):
                self._port_finding(result, auth, host["address"],
                                   port["port"], port.get("service", ""),
                                   port.get("product", ""))
        return parsed

    # -- native scanner --------------------------------------------------
    def _native_scan(self, target: str, profile: str, result: ScanResult,
                     auth: AuthorizationContext) -> None:
        from security_toolkit.core import target_validator
        classified = target_validator.classify(target)
        hosts: List[str]
        if classified.target_type == "cidr":
            import ipaddress
            net = ipaddress.ip_network(classified.normalized, strict=False)
            hosts = [str(h) for h in list(net.hosts())[:256]]
        else:
            hosts = [target_validator._host_of(target)]

        ports = PROFILE_PORTS.get(profile, COMMON_PORTS)
        result.raw["backend"] = "native-tcp-connect"
        result.raw["hosts"] = []

        for host in hosts:
            open_ports = self._scan_host(host, ports)
            if open_ports:
                result.raw["hosts"].append({"address": host, "ports": open_ports})
                for p in open_ports:
                    self._port_finding(result, auth, host, p["port"],
                                       p.get("service", ""), p.get("banner", ""))

    def _scan_host(self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        open_ports: List[Dict[str, Any]] = []
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return open_ports

        def probe(port: int) -> Optional[Dict[str, Any]]:
            try:
                with socket.create_connection((ip, port), timeout=1.5) as sock:
                    banner = self._grab_banner(sock)
                    return {"port": port, "state": "open",
                            "service": _service_name(port), "banner": banner}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=min(64, len(ports))) as pool:
            futures = [pool.submit(probe, p) for p in ports]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    open_ports.append(res)
        return sorted(open_ports, key=lambda x: x["port"])

    @staticmethod
    def _grab_banner(sock: socket.socket) -> str:
        try:
            sock.settimeout(1.0)
            data = sock.recv(128)
            return data.decode("latin-1", "replace").strip()
        except Exception:
            return ""

    def _port_finding(self, result: ScanResult, auth: AuthorizationContext,
                      host: str, port: int, service: str, extra: str) -> None:
        if port in RISKY_PORTS:
            svc, impact = RISKY_PORTS[port]
            result.add(make_finding(
                f"Exposed service: {svc} ({port}/tcp)", "NETWORK", "MEDIUM", "HIGH",
                target=f"{host}:{port}",
                evidence=f"TCP port {port} open. {('banner: ' + extra) if extra else ''}".strip(),
                impact=impact,
                recommendation="Restrict access via firewall/ACL; require authentication; "
                               "expose only through a controlled gateway.",
                reference="OWASP / CIS network hardening guidance",
                module=self.name, case_id=auth.case_id))
        else:
            result.add(make_finding(
                f"Open port {port}/tcp ({service or 'unknown'})", "NETWORK",
                "INFO", "HIGH", target=f"{host}:{port}",
                evidence=f"TCP port {port} open. {('banner: ' + extra) if extra else ''}".strip(),
                recommendation="Confirm the service is intended to be reachable.",
                module=self.name, case_id=auth.case_id))


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return ""
