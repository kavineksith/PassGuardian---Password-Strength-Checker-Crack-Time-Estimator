#!/usr/bin/env bash
# ============================================================================
#  passguardian.sh — Bash wrapper for PassGuardian
#
#  Usage:
#    ./passguardian.sh [all passguardian options]
#    ./passguardian.sh --help
#
#  This wrapper:
#    1. Locates the Python interpreter (3.10+)
#    2. Ensures the script is run from the correct directory
#    3. Validates the environment before launching main.py
#    4. Logs the invocation command for audit traceability
#    5. Forwards all arguments to main.py verbatim
# ============================================================================

set -euo pipefail

# ── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Locate script directory ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Locate Python 3.10+ ──────────────────────────────────────────────────────
find_python() {
    local candidates=("python3.13" "python3.12" "python3.11" "python3.10" "python3" "python")
    for cmd in "${candidates[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
            if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
                echo "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON=$(find_python) || die "Python 3.10+ is required but was not found on PATH."
info "Using Python: $PYTHON ($(${PYTHON} --version 2>&1))"

# ── Validate main.py exists ──────────────────────────────────────────────────
MAIN="${SCRIPT_DIR}/main.py"
[[ -f "$MAIN" ]] || die "main.py not found in ${SCRIPT_DIR}. Are you in the PassGuardian directory?"

# ── Create logs directory ─────────────────────────────────────────────────────
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"

# ── Audit: log the raw invocation ────────────────────────────────────────────
INVOCATION_LOG="${LOG_DIR}/invocations.log"
{
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [BASH] PID=$$ USER=$(whoami) CMD=passguardian.sh $*"
} >> "$INVOCATION_LOG"

# ── Check for --help / -h shortcuts ─────────────────────────────────────────
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    exec "$PYTHON" "$MAIN" --help
fi

# ── Check for --run-tests shortcut ──────────────────────────────────────────
if [[ "${1:-}" == "--run-tests" ]]; then
    info "Running PassGuardian test suite …"
    cd "$SCRIPT_DIR"
    exec "$PYTHON" -m unittest discover -s tests -v
fi

# ── Check for --list-algos shortcut (for parity with HashForge) ─────────────
if [[ "${1:-}" == "--list-tiers" ]]; then
    echo -e "\n${CYAN}Strength Tiers (score ranges):${RESET}"
    echo "  Very Weak   0–19"
    echo "  Weak       20–39"
    echo "  Fair       40–59"
    echo "  Strong     60–79"
    echo "  Very Strong 80–100"
    exit 0
fi

# ── Forward everything else to Python ───────────────────────────────────────
info "Launching PassGuardian …"
cd "$SCRIPT_DIR"
exec "$PYTHON" "$MAIN" "$@"
