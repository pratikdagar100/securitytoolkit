"""Evidence collection engine + chain of custody.

Every important operation can produce evidence. Evidence files are hashed
(SHA-256) and written under the case's ``evidence/`` folder; a chain-of-custody
record is appended for every action. Evidence is never silently overwritten --
each stored blob is content-addressed by an evidence id and its hash.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from security_toolkit.core.database import Database


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def file_hashes(path: Path) -> Dict[str, str]:
    """Return md5/sha1/sha256 for a file in a single pass."""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EvidenceStore:
    def __init__(self, db: Database, case_dir: Path, user: str = "local") -> None:
        self.db = db
        self.case_dir = Path(case_dir)
        self.user = user
        for sub in ("evidence", "logs", "network", "hashes", "reports", "screenshots"):
            (self.case_dir / sub).mkdir(parents=True, exist_ok=True)

    def _new_id(self) -> str:
        return "EVD-" + uuid.uuid4().hex[:10]

    def _custody(self, evidence_id: str, case_id: str, action: str, source: str,
                 hash_before: str, hash_after: str, description: str) -> None:
        self.db.conn.execute(
            "INSERT INTO custody (evidence_id, case_id, action, user, source, "
            "hash_before, hash_after, description, timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
            (evidence_id, case_id, action, self.user, source, hash_before,
             hash_after, description, _now()),
        )
        self.db.conn.commit()

    def store_bytes(self, case_id: str, data: bytes, *, source: str,
                    description: str, suffix: str = ".bin") -> Dict[str, Any]:
        evidence_id = self._new_id()
        digest = sha256_bytes(data)
        out = self.case_dir / "evidence" / f"{evidence_id}{suffix}"
        out.write_bytes(data)
        record = {
            "evidence_id": evidence_id, "case_id": case_id, "source": source,
            "description": description, "sha256": digest, "path": str(out),
            "collector": self.user, "created_by": self.user, "collected_at": _now(),
        }
        self.db._insert("evidence", record)
        self._custody(evidence_id, case_id, "COLLECT", source, "", digest, description)
        return record

    def store_json(self, case_id: str, obj: Any, *, source: str,
                   description: str) -> Dict[str, Any]:
        data = json.dumps(obj, indent=2, default=str).encode("utf-8")
        return self.store_bytes(case_id, data, source=source,
                                description=description, suffix=".json")

    def ingest_file(self, case_id: str, path: Path, *, source: str,
                    description: str) -> Dict[str, Any]:
        """Register an existing file as evidence (copied into the case)."""
        path = Path(path)
        data = path.read_bytes()
        record = self.store_bytes(case_id, data, source=source,
                                  description=f"{description} (original: {path.name})",
                                  suffix=path.suffix or ".bin")
        return record

    def verify(self, evidence_id: str) -> Optional[bool]:
        """Re-hash a stored evidence blob and compare to its recorded hash."""
        rows = self.db.query("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
        if not rows:
            return None
        rec = rows[0]
        p = Path(rec["path"])
        if not p.exists():
            return False
        ok = sha256_file(p) == rec["sha256"]
        self._custody(evidence_id, rec["case_id"], "VERIFY", rec["source"],
                      rec["sha256"], sha256_file(p) if p.exists() else "",
                      "integrity check " + ("PASS" if ok else "FAIL"))
        return ok
