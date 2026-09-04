"""
PassGuardian — Rotating JSONL audit logger.
Thread-safe, async-compatible, structured event logging.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from datetime import datetime, timezone
from enum import auto, StrEnum
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Event severity
# ──────────────────────────────────────────────────────────────────────────────
class Severity(StrEnum):
    DEBUG   = auto()
    INFO    = auto()
    WARNING = auto()
    ERROR   = auto()
    AUDIT   = auto()   # always persisted regardless of level filter


# ──────────────────────────────────────────────────────────────────────────────
# Log record
# ──────────────────────────────────────────────────────────────────────────────
class LogRecord:
    """Immutable, serialisable audit record."""

    __slots__ = (
        "timestamp", "severity", "event", "session_id",
        "pid", "payload",
    )

    def __init__(
        self,
        severity: Severity,
        event: str,
        session_id: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.timestamp  = datetime.now(timezone.utc).isoformat()
        self.severity   = severity
        self.event      = event
        self.session_id = session_id
        self.pid        = os.getpid()
        self.payload    = payload or {}

    # ── dunder protocol ──────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return f"LogRecord(severity={self.severity!r}, event={self.event!r})"

    def __str__(self) -> str:
        return f"[{self.timestamp}] [{self.severity.upper()}] {self.event}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LogRecord):
            return NotImplemented
        return (self.severity, self.event, self.session_id) == (
            other.severity, other.event, other.session_id
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp":  self.timestamp,
            "severity":   str(self.severity),
            "event":      self.event,
            "session_id": self.session_id,
            "pid":        self.pid,
            "payload":    self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


# ──────────────────────────────────────────────────────────────────────────────
# Rotating JSONL logger
# ──────────────────────────────────────────────────────────────────────────────
class AuditLogger:
    """
    Rotating JSONL audit logger.

    Features
    --------
    - Thread-safe via ``threading.Lock``
    - Async helper ``alog`` for use inside coroutines
    - Automatic log rotation when file exceeds ``max_bytes``
    - Keeps the last ``backup_count`` rotated files
    - Filters events below ``min_severity`` (AUDIT events always persist)
    """

    _SEVERITY_ORDER = {
        Severity.DEBUG:   0,
        Severity.INFO:    1,
        Severity.WARNING: 2,
        Severity.ERROR:   3,
        Severity.AUDIT:   99,  # always passes
    }

    def __init__(
        self,
        log_dir: str | Path = "logs",
        session_id: str | None = None,
        max_bytes: int = 5 * 1024 * 1024,  # 5 MB
        backup_count: int = 5,
        min_severity: Severity = Severity.INFO,
        echo: bool = True,
    ) -> None:
        self._log_dir     = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._session_id  = session_id or self._make_session_id()
        self._max_bytes   = max_bytes
        self._backup_count = backup_count
        self._min_severity = min_severity
        self._echo        = echo
        self._lock        = threading.Lock()
        self._log_path    = self._log_dir / "passguardian_audit.jsonl"
        self._file        = self._open()

    # ── public API ────────────────────────────────────────────────────────────
    def log(
        self,
        severity: Severity,
        event: str,
        **payload: Any,
    ) -> LogRecord:
        record = LogRecord(severity, event, self._session_id, payload)
        if self._passes_filter(severity):
            self._write(record)
        if self._echo:
            print(str(record), flush=True)
        return record

    async def alog(self, severity: Severity, event: str, **payload: Any) -> LogRecord:
        """Async-friendly log — offloads blocking I/O to executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: self.log(severity, event, **payload)
        )

    def close(self) -> None:
        with self._lock:
            if self._file and not self._file.closed:
                self._file.flush()
                self._file.close()

    # convenience shortcuts
    def debug(self, event: str, **kw: Any)   -> LogRecord: return self.log(Severity.DEBUG, event, **kw)
    def info(self, event: str, **kw: Any)    -> LogRecord: return self.log(Severity.INFO, event, **kw)
    def warning(self, event: str, **kw: Any) -> LogRecord: return self.log(Severity.WARNING, event, **kw)
    def error(self, event: str, **kw: Any)   -> LogRecord: return self.log(Severity.ERROR, event, **kw)
    def audit(self, event: str, **kw: Any)   -> LogRecord: return self.log(Severity.AUDIT, event, **kw)

    # ── context manager ───────────────────────────────────────────────────────
    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── internals ─────────────────────────────────────────────────────────────
    def _passes_filter(self, severity: Severity) -> bool:
        return self._SEVERITY_ORDER[severity] >= self._SEVERITY_ORDER[self._min_severity]

    def _write(self, record: LogRecord) -> None:
        with self._lock:
            self._rotate_if_needed()
            self._file.write(record.to_json() + "\n")
            self._file.flush()

    def _rotate_if_needed(self) -> None:
        if self._log_path.exists() and self._log_path.stat().st_size >= self._max_bytes:
            self._file.close()
            # shift old backups
            for i in range(self._backup_count - 1, 0, -1):
                src = self._log_path.with_suffix(f".jsonl.{i}")
                dst = self._log_path.with_suffix(f".jsonl.{i + 1}")
                if src.exists():
                    src.rename(dst)
            self._log_path.rename(self._log_path.with_suffix(".jsonl.1"))
            self._file = self._open()

    def _open(self):  # noqa: ANN201
        return self._log_path.open("a", encoding="utf-8", buffering=1)

    @staticmethod
    def _make_session_id() -> str:
        import uuid
        return str(uuid.uuid4())[:8]
