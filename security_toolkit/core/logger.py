"""Structured logging with separate application / audit / error streams.

Credentials and API keys must never reach the logs; callers are responsible for
not passing secrets, and the audit logger records only operational metadata.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_CONFIGURED = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Note: 'module' is a reserved LogRecord attribute, so we carry the
        # component name under 'st_component' and surface it as 'module'.
        for field, out_key in (("case_id", "case_id"), ("user", "user"),
                               ("st_component", "module"), ("operation", "operation"),
                               ("target", "target"), ("status", "status"),
                               ("duration", "duration"), ("result", "result")):
            value = getattr(record, field, None)
            if value is not None:
                payload[out_key] = value
        return json.dumps(payload, default=str)


def setup_logging(log_dir: Path, level: str = "INFO") -> None:
    """Configure the application/audit/error log files (idempotent)."""
    global _CONFIGURED
    log_dir.mkdir(parents=True, exist_ok=True)

    app_logger = logging.getLogger("security_toolkit")
    app_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not _CONFIGURED:
        app_handler = logging.FileHandler(log_dir / "application.log", encoding="utf-8")
        app_handler.setFormatter(_JsonFormatter())
        app_logger.addHandler(app_handler)

        error_handler = logging.FileHandler(log_dir / "error.log", encoding="utf-8")
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(_JsonFormatter())
        app_logger.addHandler(error_handler)

        audit_logger = logging.getLogger("security_toolkit.audit")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False
        audit_handler = logging.FileHandler(log_dir / "audit.log", encoding="utf-8")
        audit_handler.setFormatter(_JsonFormatter())
        audit_logger.addHandler(audit_handler)

        _CONFIGURED = True


def get_logger(name: str = "security_toolkit") -> logging.Logger:
    return logging.getLogger(name)


def audit(operation: str, *, case_id: Optional[str] = None, user: str = "local",
          module: str = "", target: str = "", status: str = "OK",
          duration: Optional[float] = None, result: str = "") -> None:
    """Write one structured audit record (the auditable trail of actions)."""
    logging.getLogger("security_toolkit.audit").info(
        operation,
        extra={
            "case_id": case_id, "user": user, "st_component": module,
            "operation": operation, "target": target, "status": status,
            "duration": duration, "result": result,
        },
    )
