"""Case & workspace management.

The ``Workspace`` ties together config, database, logging and the evidence
store. ``CaseManager`` creates/loads investigation cases and their targets and
is the entry point most modules receive.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from security_toolkit.core.config import Config, load_config
from security_toolkit.core.database import Database
from security_toolkit.core.evidence import EvidenceStore
from security_toolkit.core.logger import setup_logging, get_logger, audit
from security_toolkit.core.models import Case, Target
from security_toolkit.core import target_validator


class Workspace:
    """Resolved environment: directories, config, db, logging."""

    def __init__(self, config: Optional[Config] = None, user: str = "local") -> None:
        self.config = config or load_config()
        self.user = user
        self.root = self.config.workspace
        self.cases_dir = self.root / "cases"
        self.logs_dir = self.root / "logs"
        for d in (self.root, self.cases_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)
        setup_logging(self.logs_dir, self.config.get("logging.level", "INFO"))
        self.db = Database(self.root / "toolkit.db")
        self.log = get_logger()

    def case_dir(self, case_id: str) -> Path:
        d = self.cases_dir / case_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def evidence_store(self, case_id: str) -> EvidenceStore:
        return EvidenceStore(self.db, self.case_dir(case_id), user=self.user)

    def close(self) -> None:
        self.db.close()


class CaseManager:
    def __init__(self, workspace: Workspace) -> None:
        self.ws = workspace
        self.db = workspace.db

    def _next_case_id(self) -> str:
        year = datetime.now(timezone.utc).year
        existing = [c["case_id"] for c in self.db.list_cases()
                    if c["case_id"].startswith(f"CASE-{year}-")]
        seq = len(existing) + 1
        return f"CASE-{year}-{seq:03d}"

    def create_case(self, name: str, *, purpose: str = "Authorized security investigation",
                    authorized_by: str = "", notes: str = "") -> Case:
        case = Case(
            case_id=self._next_case_id(), name=name, purpose=purpose,
            authorized_by=authorized_by, created_by=self.ws.user, notes=notes,
        )
        self.db.save_case(case.to_dict())
        self.ws.case_dir(case.case_id)
        # write a case.json manifest into the case folder
        manifest = self.ws.case_dir(case.case_id) / "case.json"
        manifest.write_text(__import__("json").dumps(case.to_dict(), indent=2), encoding="utf-8")
        audit("case.create", case_id=case.case_id, user=self.ws.user,
              module="case_manager", result=name)
        return case

    def get_case(self, case_id: str) -> Optional[Dict]:
        return self.db.get_case(case_id)

    def list_cases(self) -> List[Dict]:
        return self.db.list_cases()

    def set_status(self, case_id: str, status: str) -> bool:
        case = self.db.get_case(case_id)
        if not case:
            return False
        case["status"] = status.upper()
        self.db.save_case(case)
        audit("case.status", case_id=case_id, user=self.ws.user,
              module="case_manager", result=status)
        return True

    def add_target(self, case_id: str, value: str, *, authorized: bool = False,
                   scope: str = "", notes: str = "") -> Target:
        classified = target_validator.classify(value)
        target = Target(
            case_id=case_id,
            value=classified.normalized or value,
            target_type=classified.target_type,
            authorized=authorized,
            scope=scope or (classified.normalized if authorized else ""),
            notes=notes,
        )
        self.db.save_target(target.to_dict())
        audit("target.add", case_id=case_id, user=self.ws.user,
              module="case_manager", target=target.value,
              result=f"{target.target_type} authorized={authorized}")
        return target

    def list_targets(self, case_id: str) -> List[Dict]:
        return self.db.list_targets(case_id)

    def authorized_scopes(self, case_id: str) -> List[str]:
        scopes: List[str] = []
        for t in self.db.list_targets(case_id):
            if t.get("authorized"):
                scopes.append(t.get("scope") or t.get("value"))
        return [s for s in scopes if s]
