"""
PassGuardian — CLI entry point.

Usage modes
-----------
  Interactive  : passguardian                     (prompts for passwords)
  Single       : passguardian -p "MyP@ssw0rd"
  Bulk file    : passguardian -f passwords.csv --output-dir results -F json csv xlsx
  Non-interactive pipe: echo "secret" | passguardian --stdin

  For full help:  passguardian --help
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Ensure package root is on sys.path when running directly
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from core.analyser import PasswordAnalyser, analyse_passwords_stream
from core.exceptions import (
    PassGuardianError,
    BulkPartialFailError,
    EmptyPasswordError,
)
from core.formatters import read_passwords, ReportWriter
from core.logger import AuditLogger, Severity


# ─────────────────────────────────────────────────────────────────────────────
BANNER = r"""
 ____               ____                     _ _
|  _ \ __ _ ___ ___|  _ \ _   _  __ _ _ __ | (_) __ _ _ __
| |_) / _` / __/ __| |_) | | | |/ _` | '_ \| | |/ _` | '_ \
|  __/ (_| \__ \__ \  __/| |_| | (_| | | | | | | (_| | | | |
|_|   \__,_|___/___/_|    \__,_|\__,_|_| |_|_|_|\__,_|_| |_|

  Password Strength Checker  |  Security Portfolio Tool
  ⚠  For authorised security testing and personal use only.
"""
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GREEN  = "\033[92m"


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="passguardian",
        description="PassGuardian — Password strength analyser with entropy, crack-time estimation, and bulk reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  passguardian                             # interactive mode
  passguardian -p "MyP@ssw0rd"            # single password
  passguardian -f passwords.txt           # bulk from file
  passguardian -f passwords.csv -F json csv xlsx --output-dir out/
  echo "hunter2" | passguardian --stdin   # non-interactive pipe
""",
    )

    # input
    inp = p.add_argument_group("Input")
    inp.add_argument("-p", "--password",  metavar="PASSWORD",  help="Analyse a single password")
    inp.add_argument("-f", "--file",      metavar="FILE",      help="Bulk input file (txt/csv/json)")
    inp.add_argument("--stdin",           action="store_true", help="Read one password per line from stdin")
    inp.add_argument("--csv-column",      default="password",  metavar="COL",
                     help="CSV column name for passwords (default: password)")

    # output
    out = p.add_argument_group("Output")
    out.add_argument("-F", "--formats",   nargs="+", default=["txt"],
                     choices=["json", "csv", "txt", "xlsx"],
                     metavar="FMT",
                     help="Output format(s): json csv txt xlsx  (default: txt)")
    out.add_argument("-o", "--output-dir", default=".", metavar="DIR",
                     help="Directory for report files (default: current dir)")
    out.add_argument("--base-name",       default="passguardian_report", metavar="NAME",
                     help="Base filename for reports (default: passguardian_report)")
    out.add_argument("--no-banner",       action="store_true",  help="Suppress banner")
    out.add_argument("--quiet",           action="store_true",  help="Suppress per-password output")

    # performance
    perf = p.add_argument_group("Performance")
    perf.add_argument("--concurrency",    type=int, default=8, metavar="N",
                      help="Max parallel analysis tasks (default: 8)")

    # logging
    log = p.add_argument_group("Logging")
    log.add_argument("--log-dir",         default="logs", metavar="DIR",
                     help="Directory for audit logs (default: ./logs)")
    log.add_argument("--log-level",       default="info",
                     choices=["debug", "info", "warning", "error"],
                     help="Minimum log severity (default: info)")

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Interactive mode
# ─────────────────────────────────────────────────────────────────────────────
def _interactive_loop(analyser: PasswordAnalyser, logger: AuditLogger) -> None:
    print(f"{CYAN}Interactive mode — type a password and press Enter.{RESET}")
    print(f"{YELLOW}Type 'quit' or 'exit' to leave, 'help' for tips.{RESET}\n")
    while True:
        try:
            pw = input(f"{BOLD}Password:{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if pw.lower() in ("quit", "exit", "q"):
            print("Goodbye.")
            break
        if pw.lower() == "help":
            _print_tips()
            continue
        if not pw:
            print(f"{RED}(empty — enter a password or type 'quit'){RESET}")
            continue

        try:
            result = analyser.analyse(pw)
            print(str(result))
            print()
            logger.audit("interactive_analysis", score=result.score, tier=result.tier.label())
        except PassGuardianError as exc:
            print(f"{RED}{exc}{RESET}")
            logger.error("interactive_error", error=str(exc))


def _print_tips() -> None:
    tips = [
        "• Use 16+ characters.",
        "• Mix uppercase, lowercase, digits, and symbols.",
        "• Avoid dictionary words and keyboard patterns.",
        "• Consider a passphrase: 'correct-horse-battery-staple'.",
        "• Use a unique password per account.",
    ]
    print(f"\n{CYAN}Strong password tips:{RESET}")
    for t in tips:
        print(f"  {t}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Async main logic
# ─────────────────────────────────────────────────────────────────────────────
async def _run(args: argparse.Namespace, logger: AuditLogger) -> int:
    analyser = PasswordAnalyser()
    results: list = []
    failed  = 0

    # ── Single password ───────────────────────────────────────────────────────
    if args.password:
        try:
            r = analyser.analyse(args.password)
            results.append(r)
            if not args.quiet:
                print(str(r))
            logger.audit("single_analysis", score=r.score, tier=r.tier.label())
        except PassGuardianError as exc:
            print(f"{RED}{exc}{RESET}", file=sys.stderr)
            logger.error("single_analysis_error", error=str(exc))
            return int(exc.code)

    # ── stdin ─────────────────────────────────────────────────────────────────
    elif args.stdin:
        passwords = [line.rstrip("\n\r") for line in sys.stdin if line.strip()]
        async for r in analyse_passwords_stream(passwords, args.concurrency):
            results.append(r)
            if not args.quiet:
                print(str(r))
        logger.audit("stdin_bulk", total=len(passwords), completed=len(results))

    # ── File bulk ─────────────────────────────────────────────────────────────
    elif args.file:
        try:
            passwords = list(read_passwords(args.file, column=args.csv_column))
        except PassGuardianError as exc:
            print(f"{RED}{exc}{RESET}", file=sys.stderr)
            logger.error("file_read_error", error=str(exc))
            return int(exc.code)

        print(f"{CYAN}Analysing {len(passwords)} passwords …{RESET}")
        async for r in analyse_passwords_stream(passwords, args.concurrency):
            results.append(r)
            if not args.quiet:
                col = r.tier.colour_code()
                print(f"  {col}{r.tier.label():12}{RESET}  {r.password_masked}")

        logger.audit("file_bulk", file=args.file, total=len(passwords), completed=len(results))

    # ── Interactive ───────────────────────────────────────────────────────────
    else:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _interactive_loop, analyser, logger)
        return 0

    # ── Write reports ─────────────────────────────────────────────────────────
    if results and (args.file or args.stdin or args.password):
        writer = ReportWriter(results, output_dir=args.output_dir)
        try:
            paths = await writer.write_all(args.formats, base_name=args.base_name)
            print(f"\n{GREEN}Reports saved:{RESET}")
            for p in paths:
                print(f"  • {p}")
        except PassGuardianError as exc:
            print(f"{RED}Report write error: {exc}{RESET}", file=sys.stderr)
            logger.error("report_write_error", error=str(exc))

    # ── Summary ───────────────────────────────────────────────────────────────
    if results and not args.quiet:
        tiers = {}
        for r in results:
            label = r.tier.label()
            tiers[label] = tiers.get(label, 0) + 1
        print(f"\n{BOLD}Summary ({len(results)} passwords):{RESET}")
        for label, count in sorted(tiers.items()):
            print(f"  {label:<12} : {count}")

    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    log_severity = Severity[args.log_level.upper()]
    with AuditLogger(
        log_dir=args.log_dir,
        min_severity=log_severity,
        echo=False,
    ) as logger:
        logger.audit("session_start", mode="passguardian")
        exit_code = asyncio.run(_run(args, logger))
        logger.audit("session_end", exit_code=exit_code)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
