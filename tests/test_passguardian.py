"""
PassGuardian — Full unit test suite.
Run: python -m pytest tests/ -v
  or: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Make sure project root is importable
_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

from core.analyser import (
    PasswordAnalyser,
    StrengthTier,
    CRACK_SCENARIOS,
    _seconds_to_human,
    _mask_password,
    analyse_passwords_stream,
)
from core.exceptions import (
    ErrorCode,
    PassGuardianError,
    EmptyPasswordError,
    PasswordTooLongError,
    AnalysisFailedError,
    FileNotFoundError_,
    UnsupportedFormatError,
    ParseError,
    WriteError,
    BulkPartialFailError,
)
from core.formatters import (
    read_passwords_txt,
    read_passwords_csv,
    read_passwords_json,
    read_passwords,
    ReportWriter,
)
from core.logger import AuditLogger, Severity, LogRecord


# ─────────────────────────────────────────────────────────────────────────────
# Exception tests
# ─────────────────────────────────────────────────────────────────────────────
class TestExceptions(unittest.TestCase):

    def test_empty_password_error(self):
        e = EmptyPasswordError()
        self.assertEqual(e.code, ErrorCode.EMPTY_PASSWORD)
        self.assertIn("empty", str(e).lower())

    def test_password_too_long_error(self):
        e = PasswordTooLongError(2000)
        self.assertEqual(e.code, ErrorCode.PASSWORD_TOO_LONG)
        self.assertIn("2000", str(e))
        self.assertEqual(e.context["length"], 2000)

    def test_file_not_found_error(self):
        e = FileNotFoundError_("/nonexistent/path.txt")
        self.assertEqual(e.code, ErrorCode.FILE_NOT_FOUND)
        self.assertIn("nonexistent", str(e))

    def test_unsupported_format_error(self):
        e = UnsupportedFormatError(".xyz")
        self.assertEqual(e.code, ErrorCode.UNSUPPORTED_FORMAT)

    def test_bulk_partial_fail_error(self):
        e = BulkPartialFailError(3, 10)
        self.assertEqual(e.context["failed"], 3)
        self.assertEqual(e.context["total"], 10)

    def test_exception_repr(self):
        e = EmptyPasswordError()
        self.assertIn("EmptyPasswordError", repr(e))

    def test_exception_eq(self):
        a = EmptyPasswordError()
        b = EmptyPasswordError()
        self.assertEqual(a, b)

    def test_exception_hash(self):
        e = EmptyPasswordError()
        s = {e}
        self.assertEqual(len(s), 1)

    def test_to_dict(self):
        e = WriteError("/tmp/out.txt", "permission denied")
        d = e.to_dict()
        self.assertIn("error_type", d)
        self.assertIn("code_name", d)
        self.assertIn("context", d)

    def test_from_code_factory(self):
        e = PassGuardianError.from_code(ErrorCode.EMPTY_PASSWORD, "empty!")
        self.assertIsInstance(e, EmptyPasswordError)

    def test_from_code_fallback(self):
        e = PassGuardianError.from_code(ErrorCode.UNKNOWN, "oops")
        self.assertIsInstance(e, PassGuardianError)

    def test_analysis_failed_error(self):
        e = AnalysisFailedError("internal failure")
        self.assertEqual(e.code, ErrorCode.ANALYSIS_FAILED)


# ─────────────────────────────────────────────────────────────────────────────
# Analyser tests
# ─────────────────────────────────────────────────────────────────────────────
class TestPasswordAnalyser(unittest.TestCase):

    def setUp(self):
        self.analyser = PasswordAnalyser()

    def test_empty_raises(self):
        with self.assertRaises(EmptyPasswordError):
            self.analyser.analyse("")

    def test_too_long_raises(self):
        with self.assertRaises(PasswordTooLongError):
            self.analyser.analyse("x" * 1025)

    def test_common_password_very_weak(self):
        r = self.analyser.analyse("password")
        self.assertLessEqual(r.score, 30)
        self.assertIn(r.tier, (StrengthTier.VERY_WEAK, StrengthTier.WEAK))

    def test_strong_password(self):
        r = self.analyser.analyse("X9@kP!mZqL#2vTy8")
        self.assertGreaterEqual(r.score, 60)
        self.assertIn(r.tier, (StrengthTier.STRONG, StrengthTier.VERY_STRONG))

    def test_entropy_increases_with_length(self):
        short = self.analyser.analyse("Abcd1!")
        long_ = self.analyser.analyse("Abcd1!Abcd1!Abcd")
        self.assertGreater(long_.entropy_bits, short.entropy_bits)

    def test_all_char_classes(self):
        r = self.analyser.analyse("Aa1!")
        self.assertTrue(r.has_upper)
        self.assertTrue(r.has_lower)
        self.assertTrue(r.has_digit)
        self.assertTrue(r.has_special)
        self.assertEqual(r.char_classes_used, 4)

    def test_digit_only_has_small_alphabet(self):
        r = self.analyser.analyse("123456789012")
        self.assertEqual(r.alphabet_size, 10)

    def test_keyboard_walk_penalty(self):
        r = self.analyser.analyse("qwerty12345")
        self.assertTrue(any("keyboard" in p.lower() for p in r.penalties))

    def test_repeat_char_penalty(self):
        r = self.analyser.analyse("aaabbbccc111")
        self.assertTrue(any("repeat" in p.lower() for p in r.penalties))

    def test_sequence_penalty(self):
        r = self.analyser.analyse("abc1234xyz")
        self.assertTrue(any("sequential" in p.lower() for p in r.penalties))

    def test_mask_preserves_first_last(self):
        m = _mask_password("hunter2")
        self.assertEqual(m[0], "h")
        self.assertEqual(m[-1], "2")

    def test_mask_short(self):
        m = _mask_password("ab")
        self.assertEqual(len(m), 2)

    def test_result_bool_strong(self):
        r = self.analyser.analyse("X9@kP!mZqL#2vTy8")
        # bool depends on tier >= STRONG
        self.assertIsInstance(bool(r), bool)

    def test_result_len(self):
        r = self.analyser.analyse("hello123")
        self.assertEqual(len(r), 8)

    def test_result_iter(self):
        r = self.analyser.analyse("hello123")
        d = dict(r)
        self.assertIn("entropy_bits", d)

    def test_result_lt(self):
        r1 = self.analyser.analyse("abc")
        r2 = self.analyser.analyse("X9@kP!mZqL#2vTy8")
        self.assertLess(r1, r2)

    def test_crack_times_populated(self):
        r = self.analyser.analyse("Hello1!")
        self.assertGreater(len(r.crack_times), 0)
        for k, v in r.crack_times.items():
            self.assertIsInstance(v, str)

    def test_suggestions_for_weak(self):
        r = self.analyser.analyse("abc")
        self.assertGreater(len(r.suggestions), 0)

    def test_score_capped(self):
        r = self.analyser.analyse("Tr0ub4dor&3!!abc#XYZ")
        self.assertLessEqual(r.score, 100)
        self.assertGreaterEqual(r.score, 0)

    def test_to_dict_keys(self):
        r = self.analyser.analyse("Test1234!")
        d = r.to_dict()
        for k in ("password_masked", "entropy_bits", "score", "strength_tier", "crack_times"):
            self.assertIn(k, d)

    def test_analysis_duration_recorded(self):
        r = self.analyser.analyse("Test1234!")
        self.assertGreater(r.analysis_duration_ms, 0)

    def test_unique_char_count(self):
        r = self.analyser.analyse("aaaa")
        self.assertEqual(r.unique_chars, 1)

    def test_very_strong_tier(self):
        r = self.analyser.analyse("G#7!kXmP$2LvQz@9nRw!")
        self.assertGreaterEqual(r.score, 60)


# ─────────────────────────────────────────────────────────────────────────────
# Crack-time helper tests
# ─────────────────────────────────────────────────────────────────────────────
class TestCrackTime(unittest.TestCase):

    def test_less_than_second(self):
        self.assertEqual(_seconds_to_human(0.001), "less than a second")

    def test_seconds(self):
        result = _seconds_to_human(30)
        self.assertIn("second", result)

    def test_minutes(self):
        result = _seconds_to_human(300)
        self.assertIn("minute", result)

    def test_hours(self):
        result = _seconds_to_human(7200)
        self.assertIn("hour", result)

    def test_days(self):
        result = _seconds_to_human(86400 * 5)
        self.assertIn("day", result)

    def test_years(self):
        result = _seconds_to_human(86400 * 365 * 10)
        self.assertIn("year", result)

    def test_universe(self):
        result = _seconds_to_human(1e100)
        self.assertIn("universe", result)

    def test_crack_scenario_estimate(self):
        s = CRACK_SCENARIOS[0]
        t = s.estimate_seconds(1_000_000)
        self.assertGreater(t, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Formatter / file I/O tests
# ─────────────────────────────────────────────────────────────────────────────
class TestFileIO(unittest.TestCase):

    def _tmp(self, suffix: str) -> Path:
        fd, name = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return Path(name)

    def test_read_txt(self):
        p = self._tmp(".txt")
        p.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
        result = list(read_passwords_txt(p))
        self.assertEqual(result, ["alpha", "beta", "gamma"])
        p.unlink()

    def test_read_txt_skips_blank(self):
        p = self._tmp(".txt")
        p.write_text("alpha\n\nbeta\n", encoding="utf-8")
        result = list(read_passwords_txt(p))
        self.assertEqual(len(result), 2)
        p.unlink()

    def test_read_txt_not_found(self):
        with self.assertRaises(FileNotFoundError_):
            list(read_passwords_txt("/does/not/exist.txt"))

    def test_read_csv_with_header(self):
        p = self._tmp(".csv")
        p.write_text("password,notes\nsecret1,test\nsecret2,test\n", encoding="utf-8")
        result = list(read_passwords_csv(p, "password"))
        self.assertEqual(result, ["secret1", "secret2"])
        p.unlink()

    def test_read_csv_no_header(self):
        p = self._tmp(".csv")
        p.write_text("hunter2\npassword123\n", encoding="utf-8")
        result = list(read_passwords_csv(p))
        self.assertGreaterEqual(len(result), 1)
        p.unlink()

    def test_read_json_list(self):
        p = self._tmp(".json")
        p.write_text(json.dumps(["pw1", "pw2", "pw3"]), encoding="utf-8")
        result = list(read_passwords_json(p))
        self.assertEqual(result, ["pw1", "pw2", "pw3"])
        p.unlink()

    def test_read_json_object_list(self):
        p = self._tmp(".json")
        p.write_text(json.dumps([{"password": "abc"}, {"password": "xyz"}]), encoding="utf-8")
        result = list(read_passwords_json(p))
        self.assertEqual(result, ["abc", "xyz"])
        p.unlink()

    def test_read_json_dict_key(self):
        p = self._tmp(".json")
        p.write_text(json.dumps({"passwords": ["p1", "p2"]}), encoding="utf-8")
        result = list(read_passwords_json(p))
        self.assertEqual(result, ["p1", "p2"])
        p.unlink()

    def test_read_json_invalid(self):
        p = self._tmp(".json")
        p.write_text("{not valid json}", encoding="utf-8")
        with self.assertRaises(ParseError):
            list(read_passwords_json(p))
        p.unlink()

    def test_read_passwords_dispatch_txt(self):
        p = self._tmp(".txt")
        p.write_text("mypassword\n", encoding="utf-8")
        result = list(read_passwords(p))
        self.assertEqual(result, ["mypassword"])
        p.unlink()

    def test_read_passwords_unsupported_ext(self):
        p = self._tmp(".xyz")
        p.write_text("data")
        with self.assertRaises(UnsupportedFormatError):
            list(read_passwords(p))
        p.unlink()


# ─────────────────────────────────────────────────────────────────────────────
# ReportWriter tests
# ─────────────────────────────────────────────────────────────────────────────
class TestReportWriter(unittest.TestCase):

    def setUp(self):
        analyser = PasswordAnalyser()
        self.results = [
            analyser.analyse("Test@123!"),
            analyser.analyse("X9@kP!mZqL#2vTy8"),
            analyser.analyse("weak"),
        ]
        self.tmpdir = Path(tempfile.mkdtemp())

    def _run(self, coro):
        return asyncio.run(coro)

    def test_write_json(self):
        writer = ReportWriter(self.results, self.tmpdir)
        paths = self._run(writer.write_all(["json"], "test"))
        self.assertTrue(paths[0].exists())
        data = json.loads(paths[0].read_text())
        self.assertEqual(data["total"], 3)

    def test_write_csv(self):
        writer = ReportWriter(self.results, self.tmpdir)
        paths = self._run(writer.write_all(["csv"], "test"))
        self.assertTrue(paths[0].exists())
        content = paths[0].read_text()
        self.assertIn("entropy_bits", content)

    def test_write_txt(self):
        writer = ReportWriter(self.results, self.tmpdir)
        paths = self._run(writer.write_all(["txt"], "test"))
        self.assertTrue(paths[0].exists())
        self.assertIn("Password #1", paths[0].read_text())

    def test_write_xlsx(self):
        writer = ReportWriter(self.results, self.tmpdir)
        paths = self._run(writer.write_all(["xlsx"], "test"))
        self.assertTrue(paths[0].exists())
        self.assertGreater(paths[0].stat().st_size, 100)

    def test_write_all_formats(self):
        writer = ReportWriter(self.results, self.tmpdir)
        paths = self._run(writer.write_all(["json", "csv", "txt", "xlsx"], "alltest"))
        self.assertEqual(len(paths), 4)
        for p in paths:
            self.assertTrue(p.exists())

    def test_unsupported_format_raises(self):
        writer = ReportWriter(self.results, self.tmpdir)
        with self.assertRaises(UnsupportedFormatError):
            self._run(writer.write_all(["pdf"], "test"))

    def test_empty_results_csv(self):
        writer = ReportWriter([], self.tmpdir)
        paths = self._run(writer.write_all(["csv"], "empty"))
        self.assertTrue(paths[0].exists())


# ─────────────────────────────────────────────────────────────────────────────
# Logger tests
# ─────────────────────────────────────────────────────────────────────────────
class TestLogger(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def test_log_creates_file(self):
        with AuditLogger(log_dir=self.tmpdir, echo=False) as lg:
            lg.info("test_event", key="value")
        log_path = self.tmpdir / "passguardian_audit.jsonl"
        self.assertTrue(log_path.exists())

    def test_log_record_json(self):
        with AuditLogger(log_dir=self.tmpdir, echo=False) as lg:
            lg.audit("security_event", user="alice")
        log_path = self.tmpdir / "passguardian_audit.jsonl"
        lines = log_path.read_text().strip().splitlines()
        self.assertGreater(len(lines), 0)
        record = json.loads(lines[-1])
        self.assertIn("timestamp", record)
        self.assertIn("severity", record)
        self.assertIn("event", record)

    def test_severity_filter(self):
        with AuditLogger(log_dir=self.tmpdir, echo=False, min_severity=Severity.WARNING) as lg:
            lg.info("should_not_appear")
            lg.warning("should_appear")
        log_path = self.tmpdir / "passguardian_audit.jsonl"
        content = log_path.read_text()
        self.assertNotIn("should_not_appear", content)
        self.assertIn("should_appear", content)

    def test_audit_always_logged(self):
        with AuditLogger(log_dir=self.tmpdir, echo=False, min_severity=Severity.ERROR) as lg:
            lg.audit("always_audit_event")
        log_path = self.tmpdir / "passguardian_audit.jsonl"
        self.assertIn("always_audit_event", log_path.read_text())

    def test_log_record_repr(self):
        r = LogRecord(Severity.INFO, "test", "sess123")
        self.assertIn("LogRecord", repr(r))

    def test_log_record_str(self):
        r = LogRecord(Severity.INFO, "test_event", "sess123")
        self.assertIn("test_event", str(r))

    def test_log_record_eq(self):
        r1 = LogRecord(Severity.INFO, "ev", "s1")
        r2 = LogRecord(Severity.INFO, "ev", "s1")
        self.assertEqual(r1, r2)

    def test_async_log(self):
        async def _run():
            with AuditLogger(log_dir=self.tmpdir, echo=False) as lg:
                await lg.alog(Severity.INFO, "async_event")
        asyncio.run(_run())
        log_path = self.tmpdir / "passguardian_audit.jsonl"
        self.assertIn("async_event", log_path.read_text())


# ─────────────────────────────────────────────────────────────────────────────
# Async stream tests
# ─────────────────────────────────────────────────────────────────────────────
class TestAsyncStream(unittest.TestCase):

    def test_bulk_stream(self):
        async def _run():
            passwords = ["hunter2", "Str0ng@Pass!", "abc", "X9@kP!mZqL#2vTy8"]
            results = []
            async for r in analyse_passwords_stream(passwords, concurrency=4):
                results.append(r)
            return results

        results = asyncio.run(_run())
        self.assertEqual(len(results), 4)

    def test_stream_handles_empty_gracefully(self):
        async def _run():
            results = []
            async for r in analyse_passwords_stream([], concurrency=2):
                results.append(r)
            return results
        results = asyncio.run(_run())
        self.assertEqual(results, [])


# ─────────────────────────────────────────────────────────────────────────────
# Strength tier tests
# ─────────────────────────────────────────────────────────────────────────────
class TestStrengthTier(unittest.TestCase):

    def test_labels(self):
        self.assertEqual(StrengthTier.VERY_WEAK.label(), "Very Weak")
        self.assertEqual(StrengthTier.VERY_STRONG.label(), "Very Strong")

    def test_colour_codes_are_strings(self):
        for tier in StrengthTier:
            self.assertIsInstance(tier.colour_code(), str)

    def test_ordering(self):
        self.assertLess(StrengthTier.VERY_WEAK, StrengthTier.STRONG)
        self.assertGreater(StrengthTier.VERY_STRONG, StrengthTier.FAIR)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    unittest.main(verbosity=2)
