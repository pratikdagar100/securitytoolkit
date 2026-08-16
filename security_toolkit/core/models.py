"""Shared data models used across every module.

A single common ``Finding`` schema keeps output consistent regardless of which
module produced it, which is what makes the reports reproducible and auditable.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Severity model (ordered low -> high). Observation/Informational collapse to INFO.
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHT = {"INFO": 0, "LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}
CONFIDENCE_LEVELS = ["LOW", "MEDIUM", "HIGH"]


@dataclass
class Finding:
    """The one common finding format for every module."""

    title: str
    category: str
    severity: str = "INFO"
    confidence: str = "MEDIUM"
    target: str = ""
    evidence: str = ""
    impact: str = ""
    recommendation: str = ""
    reference: str = ""
    finding_id: str = field(default_factory=lambda: "F-" + uuid.uuid4().hex[:8])
    case_id: str = ""
    module: str = ""
    timestamp: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        self.severity = (self.severity or "INFO").upper()
        if self.severity not in SEVERITY_ORDER:
            self.severity = "INFO"
        self.confidence = (self.confidence or "MEDIUM").upper()
        if self.confidence not in CONFIDENCE_LEVELS:
            self.confidence = "MEDIUM"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Case:
    case_id: str
    name: str
    purpose: str = "Authorized security investigation"
    authorized_by: str = ""
    status: str = "ACTIVE"  # ACTIVE / CLOSED / SUSPENDED
    created_by: str = "local"
    created_at: str = field(default_factory=_now)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Target:
    case_id: str
    value: str
    target_type: str = "unknown"  # ip / cidr / domain / url / host / file
    authorized: bool = False
    scope: str = ""
    notes: str = ""
    target_id: str = field(default_factory=lambda: "T-" + uuid.uuid4().hex[:8])
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    case_id: str
    evidence_id: str
    source: str
    description: str
    sha256: str
    path: str = ""
    collector: str = "local"
    collected_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Event:
    """A normalized SOC/timeline event."""

    case_id: str
    timestamp: str
    source: str
    category: str
    severity: str = "INFO"
    confidence: str = "MEDIUM"
    target: str = ""
    evidence: str = ""
    event_id: str = field(default_factory=lambda: "E-" + uuid.uuid4().hex[:8])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Container returned by every module's ``run`` method."""

    module: str
    target: str
    profile: str = "PASSIVE"
    started_at: str = field(default_factory=_now)
    findings: List[Finding] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "findings": [f.to_dict() for f in self.findings],
            "events": [e.to_dict() for e in self.events],
            "raw": self.raw,
            "errors": self.errors,
        }
