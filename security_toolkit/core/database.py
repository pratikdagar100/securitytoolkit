"""SQLite persistence layer.

Uses the standard-library ``sqlite3`` (no heavy ORM) so the toolkit installs
cleanly everywhere. Every record carries id / case_id / timestamp / created_by.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    purpose TEXT,
    authorized_by TEXT,
    status TEXT,
    created_by TEXT,
    created_at TEXT,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS targets (
    target_id TEXT PRIMARY KEY,
    case_id TEXT,
    value TEXT,
    target_type TEXT,
    authorized INTEGER,
    scope TEXT,
    notes TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT,
    module TEXT,
    category TEXT,
    title TEXT,
    severity TEXT,
    confidence TEXT,
    target TEXT,
    evidence TEXT,
    impact TEXT,
    recommendation TEXT,
    reference TEXT,
    created_by TEXT,
    timestamp TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT,
    source TEXT,
    description TEXT,
    sha256 TEXT,
    path TEXT,
    collector TEXT,
    created_by TEXT,
    collected_at TEXT
);
CREATE TABLE IF NOT EXISTS custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT,
    case_id TEXT,
    action TEXT,
    user TEXT,
    source TEXT,
    hash_before TEXT,
    hash_after TEXT,
    description TEXT,
    timestamp TEXT
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT,
    timestamp TEXT,
    source TEXT,
    category TEXT,
    severity TEXT,
    confidence TEXT,
    target TEXT,
    evidence TEXT,
    created_by TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    module TEXT,
    target TEXT,
    profile TEXT,
    result_json TEXT,
    created_by TEXT,
    timestamp TEXT
);
CREATE TABLE IF NOT EXISTS tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    version TEXT,
    path TEXT,
    detected_at TEXT
);
"""


class Database:
    def __init__(self, db_path: Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- generic helpers -------------------------------------------------
    def _insert(self, table: str, row: Dict[str, Any]) -> None:
        cols = ", ".join(row.keys())
        placeholders = ", ".join(["?"] * len(row))
        self.conn.execute(
            f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({placeholders})",
            list(row.values()),
        )
        self.conn.commit()

    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        cur = self.conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    # -- typed writers ---------------------------------------------------
    def save_case(self, case: Dict[str, Any]) -> None:
        self._insert("cases", case)

    def save_target(self, target: Dict[str, Any]) -> None:
        row = dict(target)
        row["authorized"] = 1 if row.get("authorized") else 0
        self._insert("targets", row)

    def save_finding(self, finding: Dict[str, Any], created_by: str = "local") -> None:
        row = {
            "finding_id": finding["finding_id"],
            "case_id": finding.get("case_id", ""),
            "module": finding.get("module", ""),
            "category": finding.get("category", ""),
            "title": finding.get("title", ""),
            "severity": finding.get("severity", "INFO"),
            "confidence": finding.get("confidence", "MEDIUM"),
            "target": finding.get("target", ""),
            "evidence": finding.get("evidence", ""),
            "impact": finding.get("impact", ""),
            "recommendation": finding.get("recommendation", ""),
            "reference": finding.get("reference", ""),
            "created_by": created_by,
            "timestamp": finding.get("timestamp", ""),
        }
        self._insert("findings", row)

    def save_event(self, event: Dict[str, Any], created_by: str = "local") -> None:
        row = dict(event)
        row["created_by"] = created_by
        self._insert("events", row)

    def save_scan(self, case_id: str, module: str, target: str, profile: str,
                  result: Dict[str, Any], created_by: str = "local", timestamp: str = "") -> None:
        self._insert("scans", {
            "case_id": case_id, "module": module, "target": target,
            "profile": profile, "result_json": json.dumps(result, default=str),
            "created_by": created_by, "timestamp": timestamp,
        })

    def record_tool(self, name: str, version: str, path: str, detected_at: str) -> None:
        self._insert("tools", {"name": name, "version": version, "path": path,
                               "detected_at": detected_at})

    # -- readers ---------------------------------------------------------
    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        rows = self.query("SELECT * FROM cases WHERE case_id = ?", (case_id,))
        return rows[0] if rows else None

    def list_cases(self) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM cases ORDER BY created_at DESC")

    def list_targets(self, case_id: str) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM targets WHERE case_id = ?", (case_id,))

    def list_findings(self, case_id: str) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM findings WHERE case_id = ? ORDER BY timestamp", (case_id,))

    def list_events(self, case_id: str) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM events WHERE case_id = ? ORDER BY timestamp", (case_id,))

    def list_evidence(self, case_id: str) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM evidence WHERE case_id = ? ORDER BY collected_at", (case_id,))

    def list_custody(self, case_id: str) -> List[Dict[str, Any]]:
        return self.query("SELECT * FROM custody WHERE case_id = ? ORDER BY timestamp", (case_id,))

    def close(self) -> None:
        self.conn.close()
