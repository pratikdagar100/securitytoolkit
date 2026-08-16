"""Module registry.

Maps CLI/plugin names to module classes. Third-party plugins can register
additional modules via ``register`` or the ``security_toolkit.modules`` entry
point group.
"""
from __future__ import annotations

from typing import Dict, Type

from security_toolkit.modules.recon import ReconModule
from security_toolkit.modules.network import NetworkModule
from security_toolkit.modules.web import WebModule
from security_toolkit.modules.sqli import SqlInjectionModule
from security_toolkit.modules.xss import XssModule
from security_toolkit.modules.api import ApiModule
from security_toolkit.modules.availability import AvailabilityModule
from security_toolkit.modules.logs import LogAnalysisModule
from security_toolkit.modules.host import HostModule
from security_toolkit.modules.malware import MalwareModule
from security_toolkit.modules.device import DeviceModule

_REGISTRY: Dict[str, Type] = {
    "recon": ReconModule,
    "network": NetworkModule,
    "web": WebModule,
    "sqli": SqlInjectionModule,
    "xss": XssModule,
    "api": ApiModule,
    "availability": AvailabilityModule,
    "logs": LogAnalysisModule,
    "host": HostModule,
    "file": MalwareModule,
    "malware": MalwareModule,
    "device": DeviceModule,
}


def register(name: str, cls: Type) -> None:
    _REGISTRY[name] = cls


def get_module(name: str):
    return _REGISTRY.get(name)


def available_modules() -> Dict[str, Type]:
    return dict(_REGISTRY)


def load_plugins() -> None:
    """Discover third-party modules exposed via entry points (best-effort)."""
    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        group = eps.select(group="security_toolkit.modules") if hasattr(eps, "select") \
            else eps.get("security_toolkit.modules", [])
        for ep in group:
            try:
                register(ep.name, ep.load())
            except Exception:
                continue
    except Exception:
        pass
