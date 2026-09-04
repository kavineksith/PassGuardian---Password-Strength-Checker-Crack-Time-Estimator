"""
PassGuardian — Custom exception hierarchy.
All errors carry a numeric code for structured logging and CLI exit codes.
"""

from __future__ import annotations
from enum import IntEnum


# ──────────────────────────────────────────────────────────────────────────────
# Error code registry
# ──────────────────────────────────────────────────────────────────────────────
class ErrorCode(IntEnum):
    # General
    UNKNOWN             = 1
    INVALID_ARGUMENT    = 2
    IO_ERROR            = 3
    ENCODING_ERROR      = 4

    # Password analysis
    EMPTY_PASSWORD      = 10
    PASSWORD_TOO_LONG   = 11
    ANALYSIS_FAILED     = 12

    # Input / file
    FILE_NOT_FOUND      = 20
    UNSUPPORTED_FORMAT  = 21
    PARSE_ERROR         = 22
    WRITE_ERROR         = 23

    # Bulk operations
    BULK_PARTIAL_FAIL   = 30
    BULK_ALL_FAILED     = 31


# ──────────────────────────────────────────────────────────────────────────────
# Base exception
# ──────────────────────────────────────────────────────────────────────────────
class PassGuardianError(Exception):
    """Base class for all PassGuardian errors."""

    # Subclasses may fix this at the class level
    default_code: ErrorCode = ErrorCode.UNKNOWN

    _registry: dict[ErrorCode, type[PassGuardianError]] = {}

    def __init__(
        self,
        message: str,
        code: ErrorCode | None = None,
        *,
        context: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.message  = message
        self.code     = code if code is not None else self.default_code
        self.context  = context or {}

    # ── dunder protocol ──────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code!r}, "
            f"message={self.message!r})"
        )

    def __str__(self) -> str:
        return f"[{self.code.name}] {self.message}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PassGuardianError):
            return NotImplemented
        return self.code == other.code and self.message == other.message

    def __hash__(self) -> int:
        return hash((self.code, self.message))

    # ── class-level registry ──────────────────────────────────────────────────
    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "default_code") and cls.default_code not in PassGuardianError._registry:
            PassGuardianError._registry[cls.default_code] = cls

    @classmethod
    def from_code(cls, code: ErrorCode, message: str, **kwargs: object) -> PassGuardianError:
        """Factory: return the most-specific registered subclass for *code*."""
        target = PassGuardianError._registry.get(code, PassGuardianError)
        if target is PassGuardianError:
            return PassGuardianError(message, code=code, **kwargs)
        return target(message, **kwargs)  # type: ignore[arg-type]

    def to_dict(self) -> dict:
        return {
            "error_type": type(self).__name__,
            "code": int(self.code),
            "code_name": self.code.name,
            "message": self.message,
            "context": self.context,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Concrete subclasses
# ──────────────────────────────────────────────────────────────────────────────
class EmptyPasswordError(PassGuardianError):
    default_code = ErrorCode.EMPTY_PASSWORD

    def __init__(self, message: str = "Password must not be empty.", **kw: object) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


class PasswordTooLongError(PassGuardianError):
    default_code = ErrorCode.PASSWORD_TOO_LONG

    def __init__(self, length: int, limit: int = 1024, **kw: object) -> None:
        super().__init__(
            f"Password length {length} exceeds the limit of {limit} characters.",
            context={"length": length, "limit": limit},
            **kw,  # type: ignore[arg-type]
        )


class AnalysisFailedError(PassGuardianError):
    default_code = ErrorCode.ANALYSIS_FAILED

    def __init__(self, reason: str, **kw: object) -> None:
        super().__init__(f"Analysis failed: {reason}", **kw)  # type: ignore[arg-type]


class FileNotFoundError_(PassGuardianError):
    """Renamed to avoid shadowing built-in FileNotFoundError."""
    default_code = ErrorCode.FILE_NOT_FOUND

    def __init__(self, path: str, **kw: object) -> None:
        super().__init__(f"File not found: {path}", context={"path": path}, **kw)  # type: ignore[arg-type]


class UnsupportedFormatError(PassGuardianError):
    default_code = ErrorCode.UNSUPPORTED_FORMAT

    def __init__(self, fmt: str, **kw: object) -> None:
        super().__init__(
            f"Unsupported format: '{fmt}'. Supported: json, csv, xlsx, txt.",
            context={"format": fmt},
            **kw,  # type: ignore[arg-type]
        )


class ParseError(PassGuardianError):
    default_code = ErrorCode.PARSE_ERROR

    def __init__(self, detail: str, **kw: object) -> None:
        super().__init__(f"Parse error: {detail}", **kw)  # type: ignore[arg-type]


class WriteError(PassGuardianError):
    default_code = ErrorCode.WRITE_ERROR

    def __init__(self, path: str, reason: str, **kw: object) -> None:
        super().__init__(
            f"Cannot write to '{path}': {reason}",
            context={"path": path, "reason": reason},
            **kw,  # type: ignore[arg-type]
        )


class BulkPartialFailError(PassGuardianError):
    default_code = ErrorCode.BULK_PARTIAL_FAIL

    def __init__(self, failed: int, total: int, **kw: object) -> None:
        super().__init__(
            f"{failed}/{total} passwords failed during bulk analysis.",
            context={"failed": failed, "total": total},
            **kw,  # type: ignore[arg-type]
        )
