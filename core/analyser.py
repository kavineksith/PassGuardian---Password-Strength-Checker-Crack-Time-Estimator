"""
PassGuardian — Password strength analysis engine.

Checks character-class diversity, common pattern penalties, entropy,
crack-time estimates, and generates human-readable feedback.
"""

from __future__ import annotations

import math
import re
import string
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Generator, Iterator

from .exceptions import (
    EmptyPasswordError,
    PasswordTooLongError,
    AnalysisFailedError,
)


# ──────────────────────────────────────────────────────────────────────────────
# Strength tier
# ──────────────────────────────────────────────────────────────────────────────
class StrengthTier(IntEnum):
    VERY_WEAK  = 0
    WEAK       = 1
    FAIR       = 2
    STRONG     = 3
    VERY_STRONG = 4

    def label(self) -> str:
        return self.name.replace("_", " ").title()

    def colour_code(self) -> str:
        """ANSI colour for terminal output."""
        return {
            StrengthTier.VERY_WEAK:   "\033[91m",  # bright red
            StrengthTier.WEAK:        "\033[31m",   # red
            StrengthTier.FAIR:        "\033[33m",   # yellow
            StrengthTier.STRONG:      "\033[32m",   # green
            StrengthTier.VERY_STRONG: "\033[92m",   # bright green
        }[self]


# ──────────────────────────────────────────────────────────────────────────────
# Cracking scenario
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, order=True)
class CrackScenario:
    """A single offline / online cracking scenario."""
    name:         str
    guesses_per_second: float   # e.g. 1e10 for fast GPU offline
    description:  str

    def estimate_seconds(self, keyspace: float) -> float:
        """Expected brute-force time in seconds (assumes avg = keyspace/2)."""
        return (keyspace / 2.0) / max(self.guesses_per_second, 1.0)

    def human_time(self, keyspace: float) -> str:
        return _seconds_to_human(self.estimate_seconds(keyspace))


CRACK_SCENARIOS: list[CrackScenario] = [
    CrackScenario("Online (throttled)",        100,      "100 guess/s rate-limited service"),
    CrackScenario("Online (unthrottled)",      1_000,    "1 K guess/s unthrottled web form"),
    CrackScenario("Offline (slow hash)",       1_000_000,"1 M guess/s — bcrypt/scrypt"),
    CrackScenario("Offline (fast hash, CPU)",  1_000_000_000, "1 B guess/s — SHA-256 CPU"),
    CrackScenario("Offline (GPU cluster)",     100_000_000_000, "100 B guess/s — GPU farm"),
    CrackScenario("Nation-state (ASIC)",       1_000_000_000_000, "1 T guess/s — ASIC array"),
]


def _seconds_to_human(seconds: float) -> str:
    """Convert raw seconds to a readable string."""
    if seconds < 1:
        return "less than a second"
    minutes = seconds / 60
    hours   = minutes / 60
    days    = hours   / 24
    years   = days    / 365.25
    centuries = years / 100

    if centuries >= 1e9:
        return "longer than the age of the universe"
    if centuries >= 1_000_000:
        return f"{centuries / 1_000_000:.1f} million centuries"
    if centuries >= 1_000:
        return f"{centuries / 1_000:.1f} millennia"
    if years >= 1:
        return f"{years:.1f} year{'s' if years != 1 else ''}"
    if days >= 1:
        return f"{days:.1f} day{'s' if days != 1 else ''}"
    if hours >= 1:
        return f"{hours:.1f} hour{'s' if hours != 1 else ''}"
    if minutes >= 1:
        return f"{minutes:.1f} minute{'s' if minutes != 1 else ''}"
    return f"{int(seconds)} second{'s' if seconds != 1 else ''}"


# ──────────────────────────────────────────────────────────────────────────────
# Common-pattern detection
# ──────────────────────────────────────────────────────────────────────────────
_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "password1", "qwerty", "abc123", "letmein",
    "monkey", "1234567890", "password123", "iloveyou", "admin", "welcome",
    "login", "princess", "solo", "dragon", "passw0rd", "master", "hello",
    "shadow", "sunshine", "superman", "michael", "football", "baseball",
    "trustno1", "123456789", "12345678", "12345", "1234", "111111",
    "000000", "654321", "!@#$%^&*", "charlie", "donald", "password2",
})

_KEYBOARD_WALKS = re.compile(
    r"(qwerty|asdf|zxcv|qazwsx|1qaz|2wsx|!qaz|@wsx|yuiop|hjkl|bnm,|"
    r"qwertyuiop|asdfghjkl|zxcvbnm)", re.IGNORECASE
)
_REPEATS      = re.compile(r"(.)\1{2,}")
_SEQUENCES    = re.compile(r"(0123|1234|2345|3456|4567|5678|6789|7890|abcd|"
                            r"bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|"
                            r"klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|"
                            r"tuvw|uvwx|vwxy|wxyz)", re.IGNORECASE)
_LEET         = re.compile(r"[@!0]")
_DATE_PATTERN = re.compile(r"\b(19|20)\d{2}\b|\b\d{1,2}[/\-]\d{1,2}([/\-]\d{2,4})?\b")


# ──────────────────────────────────────────────────────────────────────────────
# Analysis result model
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class AnalysisResult:
    """Full analysis result for a single password."""

    # identity
    password_masked:  str = ""    # e.g. "pa*****rd"

    # character composition
    length:           int   = 0
    has_upper:        bool  = False
    has_lower:        bool  = False
    has_digit:        bool  = False
    has_special:      bool  = False
    unique_chars:     int   = 0
    char_classes_used: int  = 0

    # entropy
    alphabet_size:    int   = 0
    entropy_bits:     float = 0.0

    # crack times
    crack_times:      dict[str, str] = field(default_factory=dict)

    # penalties
    penalties:        list[str] = field(default_factory=list)

    # score / tier
    score:            int   = 0   # 0–100
    tier:             StrengthTier = StrengthTier.VERY_WEAK

    # suggestions
    suggestions:      list[str] = field(default_factory=list)

    # analysis meta
    analysis_duration_ms: float = 0.0

    # ── dunder protocol ──────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"AnalysisResult(tier={self.tier.label()!r}, "
            f"score={self.score}, entropy={self.entropy_bits:.1f} bits)"
        )

    def __str__(self) -> str:
        return self._pretty()

    def __bool__(self) -> bool:
        return self.tier >= StrengthTier.STRONG

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, AnalysisResult):
            return NotImplemented
        return self.score < other.score

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AnalysisResult):
            return NotImplemented
        return self.score == other.score

    def __iter__(self) -> Iterator[tuple[str, object]]:
        """Yield key-value pairs for easy serialisation."""
        yield from self.to_dict().items()

    def __len__(self) -> int:
        return self.length

    def _pretty(self) -> str:
        reset = "\033[0m"
        col   = self.tier.colour_code()
        lines = [
            f"  Password   : {self.password_masked}",
            f"  Length     : {self.length}",
            f"  Entropy    : {self.entropy_bits:.1f} bits",
            f"  Strength   : {col}{self.tier.label()}{reset}  (score {self.score}/100)",
        ]
        if self.crack_times:
            lines.append("  Crack times:")
            for scenario, t in self.crack_times.items():
                lines.append(f"    • {scenario:<30} {t}")
        if self.penalties:
            lines.append("  ⚠ Penalties:")
            for p in self.penalties:
                lines.append(f"    - {p}")
        if self.suggestions:
            lines.append("  💡 Suggestions:")
            for s in self.suggestions:
                lines.append(f"    → {s}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "password_masked":    self.password_masked,
            "length":             self.length,
            "has_uppercase":      self.has_upper,
            "has_lowercase":      self.has_lower,
            "has_digit":          self.has_digit,
            "has_special":        self.has_special,
            "unique_chars":       self.unique_chars,
            "char_classes_used":  self.char_classes_used,
            "alphabet_size":      self.alphabet_size,
            "entropy_bits":       round(self.entropy_bits, 2),
            "score":              self.score,
            "strength_tier":      self.tier.label(),
            "crack_times":        self.crack_times,
            "penalties":          self.penalties,
            "suggestions":        self.suggestions,
            "analysis_duration_ms": round(self.analysis_duration_ms, 3),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Mask helper
# ──────────────────────────────────────────────────────────────────────────────
def _mask_password(pw: str) -> str:
    if len(pw) <= 4:
        return "*" * len(pw)
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]


# ──────────────────────────────────────────────────────────────────────────────
# Core analyser
# ──────────────────────────────────────────────────────────────────────────────
class PasswordAnalyser:
    """
    Synchronous password strength analyser.
    Intended to be called from async context via run_in_executor.
    """

    MAX_LENGTH = 1024

    def analyse(self, password: str) -> AnalysisResult:
        """Run full analysis pipeline on *password*."""
        t0 = time.perf_counter()

        # ── validation ────────────────────────────────────────────────────────
        if not isinstance(password, str) or len(password) == 0:
            raise EmptyPasswordError()
        if len(password) > self.MAX_LENGTH:
            raise PasswordTooLongError(len(password), self.MAX_LENGTH)

        result = AnalysisResult(
            password_masked=_mask_password(password),
            length=len(password),
        )

        try:
            self._check_composition(password, result)
            self._calculate_entropy(password, result)
            self._calculate_crack_times(result)
            self._check_penalties(password, result)
            self._calculate_score(result)
            self._generate_suggestions(result)
        except Exception as exc:
            raise AnalysisFailedError(str(exc)) from exc

        result.analysis_duration_ms = (time.perf_counter() - t0) * 1000
        return result

    # ── pipeline stages ───────────────────────────────────────────────────────
    def _check_composition(self, pw: str, r: AnalysisResult) -> None:
        r.has_upper   = any(c in string.ascii_uppercase for c in pw)
        r.has_lower   = any(c in string.ascii_lowercase for c in pw)
        r.has_digit   = any(c in string.digits for c in pw)
        r.has_special = any(c in string.punctuation for c in pw)
        r.unique_chars = len(set(pw))
        r.char_classes_used = sum([r.has_upper, r.has_lower, r.has_digit, r.has_special])

    def _calculate_entropy(self, pw: str, r: AnalysisResult) -> None:
        alphabet = 0
        if r.has_lower:   alphabet += 26
        if r.has_upper:   alphabet += 26
        if r.has_digit:   alphabet += 10
        if r.has_special: alphabet += 32
        if alphabet == 0: alphabet = 26  # fallback

        r.alphabet_size = alphabet
        r.entropy_bits  = math.log2(alphabet) * len(pw)

    def _calculate_crack_times(self, r: AnalysisResult) -> None:
        keyspace = (r.alphabet_size ** r.length)
        for s in CRACK_SCENARIOS:
            r.crack_times[s.name] = s.human_time(keyspace)

    def _check_penalties(self, pw: str, r: AnalysisResult) -> None:
        pw_lower = pw.lower()

        if pw_lower in _COMMON_PASSWORDS:
            r.penalties.append("Password is in the common-passwords list")
            r.score = max(r.score - 50, 0)

        if _KEYBOARD_WALKS.search(pw_lower):
            r.penalties.append("Contains keyboard walk pattern (e.g. qwerty, asdf)")

        if _REPEATS.search(pw):
            r.penalties.append("Contains 3+ repeated characters in a row")

        if _SEQUENCES.search(pw_lower):
            r.penalties.append("Contains sequential character run (e.g. 1234, abcd)")

        if _DATE_PATTERN.search(pw):
            r.penalties.append("Contains date-like pattern — easy to guess")

        if _LEET.search(pw) and pw.lower().replace("@", "a").replace("0", "o").replace("!", "i") in _COMMON_PASSWORDS:
            r.penalties.append("Leet-speak substitution of a common word detected")

        if r.unique_chars < max(len(pw) // 2, 3):
            r.penalties.append(f"Low character diversity — only {r.unique_chars} unique chars")

    def _calculate_score(self, r: AnalysisResult) -> None:
        score = 0

        # length contribution (up to 40 pts)
        score += min(r.length * 2, 40)

        # character class diversity (up to 30 pts)
        score += r.char_classes_used * 7

        # entropy bonus (up to 20 pts)
        score += min(int(r.entropy_bits / 5), 20)

        # unique char bonus (up to 10 pts)
        score += min(r.unique_chars, 10)

        # penalty deductions
        score -= len(r.penalties) * 10

        r.score = max(0, min(100, score))

        if   r.score >= 80: r.tier = StrengthTier.VERY_STRONG
        elif r.score >= 60: r.tier = StrengthTier.STRONG
        elif r.score >= 40: r.tier = StrengthTier.FAIR
        elif r.score >= 20: r.tier = StrengthTier.WEAK
        else:               r.tier = StrengthTier.VERY_WEAK

    def _generate_suggestions(self, r: AnalysisResult) -> None:
        if r.length < 12:
            r.suggestions.append("Use at least 12 characters (16+ is ideal).")
        if not r.has_upper:
            r.suggestions.append("Add uppercase letters (A–Z).")
        if not r.has_lower:
            r.suggestions.append("Add lowercase letters (a–z).")
        if not r.has_digit:
            r.suggestions.append("Include digits (0–9).")
        if not r.has_special:
            r.suggestions.append("Add special characters (!@#$%^&*).")
        if r.unique_chars < 8:
            r.suggestions.append("Increase character variety — avoid repeats.")
        if not r.suggestions and r.tier < StrengthTier.VERY_STRONG:
            r.suggestions.append("Good password! Making it longer further increases security.")


# ──────────────────────────────────────────────────────────────────────────────
# Async batch generator
# ──────────────────────────────────────────────────────────────────────────────
async def analyse_passwords_stream(
    passwords: list[str],
    concurrency: int = 8,
) -> Generator[AnalysisResult, None, None]:
    """
    Async generator that yields AnalysisResult objects as they complete.
    Uses a semaphore to cap concurrent executor tasks.
    """
    import asyncio

    analyser  = PasswordAnalyser()
    semaphore = asyncio.Semaphore(concurrency)
    loop      = asyncio.get_event_loop()

    async def _analyse_one(pw: str) -> AnalysisResult:
        async with semaphore:
            return await loop.run_in_executor(None, analyser.analyse, pw)

    tasks = [asyncio.ensure_future(_analyse_one(pw)) for pw in passwords]
    for coro in asyncio.as_completed(tasks):
        yield await coro
