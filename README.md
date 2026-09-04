# PassGuardian

**Password Strength Checker & Crack-Time Estimator**
*Security Portfolio Tool — CLI | Async | Pure-stdlib Python*

---

## Problem Statement

Organisations and individuals routinely underestimate the risk posed by weak passwords. Password policies are often poorly enforced and users have no reliable, self-hosted tool to audit the quality of their credentials before committing them to a system. Third-party online checkers require you to submit the actual password to a remote server — a serious security anti-pattern.

**PassGuardian** solves this by providing a fully local, zero-external-dependency CLI tool that:

- Rates password strength on a deterministic, multi-factor score (0–100)
- Calculates Shannon entropy based on character-set diversity
- Estimates realistic brute-force crack times across six attack scenarios (from rate-limited web login to nation-state ASIC farms)
- Detects structural weaknesses: dictionary words, keyboard walks, sequences, date patterns, leet-speak substitutions, and low character diversity
- Offers actionable, human-readable improvement suggestions
- Processes bulk password lists from TXT / CSV / JSON files with async parallel analysis
- Exports results to JSON, CSV, plain text, and Excel (XLSX) — no third-party packages

---

## Architecture

```
PassGuardian/
├── main.py                  CLI entry point (argparse + asyncio)
├── passguardian.sh          Bash launcher with env validation & audit logging
├── core/
│   ├── __init__.py
│   ├── exceptions.py        Custom exception hierarchy (IntEnum codes, factory, registry)
│   ├── logger.py            Rotating JSONL audit logger (thread-safe, async-compatible)
│   ├── analyser.py          Password analysis engine + async batch generator
│   └── formatters.py        File I/O readers + multi-format report writers (OOXML)
├── tests/
│   ├── __init__.py
│   └── test_passguardian.py 74 unit tests
└── logs/                    Audit logs written here (auto-created)
```

### Key Engineering Patterns

| Pattern | Where Used |
|---|---|
| `async/await` + `asyncio.gather` | Parallel bulk analysis via `analyse_passwords_stream()` |
| `asyncio.Semaphore` | Caps concurrent executor tasks (default 8) |
| `asyncio.as_completed` | Yields results as they finish, not in submission order |
| Generator / `yield` | `read_passwords_*` functions — zero full-file load into memory |
| Custom exception hierarchy | `PassGuardianError` → 9 typed subclasses, `IntEnum` codes, `from_code` factory |
| `__slots__` + dunder protocol | `LogRecord`: `__repr__`, `__str__`, `__eq__`, `to_dict` |
| Dataclass + dunder protocol | `AnalysisResult`: `__str__`, `__bool__`, `__lt__`, `__eq__`, `__iter__`, `__len__` |
| Pure-stdlib OOXML | `_write_xlsx_ooxml()` — generates `.xlsx` via `zipfile` with no pip dependencies |
| Rotating JSONL logger | Thread-lock + backup rotation, `AUDIT` severity bypasses level filter |
| Context manager | `AuditLogger.__enter__` / `__exit__` for guaranteed flush on exit |

---

## Requirements

- Python 3.10 or later
- No `pip install` required — pure standard library
- Bash 4+ (for the `.sh` wrapper)
- Linux / macOS / WSL2

---

## Installation

```bash
git clone <repo>
cd PassGuardian
chmod +x passguardian.sh
```

---

## Usage

### Interactive mode (default)

```bash
./passguardian.sh
# or
python main.py
```

Type any password at the prompt. Type `help` for tips, `quit` to exit.

### Single password

```bash
./passguardian.sh -p "MyP@ssw0rd123!"
python main.py -p "hunter2"
```

### Bulk file analysis

```bash
# Plain-text file (one password per line)
./passguardian.sh -f passwords.txt

# CSV file (uses "password" column by default)
./passguardian.sh -f users.csv --csv-column pwd

# JSON file (list of strings or list of objects with "password" key)
./passguardian.sh -f export.json
```

### Non-interactive stdin pipe

```bash
echo "secret123" | python main.py --stdin
cat wordlist.txt  | python main.py --stdin --quiet -F json
```

### Output formats

```bash
# Single format
./passguardian.sh -f passwords.txt -F json

# Multiple formats simultaneously
./passguardian.sh -f passwords.txt -F json csv xlsx txt --output-dir results/

# Custom report base name
./passguardian.sh -f passwords.txt -F json --base-name audit_2024_q4
```

### Tuning concurrency

```bash
./passguardian.sh -f big_list.txt --concurrency 16
```

### Suppress banner / quiet mode

```bash
./passguardian.sh -p "password" --no-banner --quiet
```

### Run the test suite

```bash
./passguardian.sh --run-tests
# or
python -m unittest discover -s tests -v
```

---

## Understanding the Output

```
  Password   : h*****2              ← masked (never stored or logged in clear)
  Length     : 7
  Entropy    : 41.4 bits
  Strength   : Very Weak  (score 4/100)
  Crack times:
    • Online (throttled)             3.9 years
    • Online (unthrottled)           142.7 days
    • Offline (slow hash)            3.4 hours
    • Offline (fast hash, CPU)       less than a second
    • Offline (GPU cluster)          less than a second
    • Nation-state (ASIC)            less than a second
  ⚠ Penalties:
    - Password is in the common-passwords list
  💡 Suggestions:
    - Use at least 12 characters (16+ is ideal).
    - Add special characters (!@#$%^&*).
```

### Strength Tiers

| Score | Tier |
|---|---|
| 0–19 | Very Weak |
| 20–39 | Weak |
| 40–59 | Fair |
| 60–79 | Strong |
| 80–100 | Very Strong |

### Entropy

Shannon entropy = log₂(alphabet_size) × length. Larger alphabet (mixing upper, lower, digits, symbols) multiplies entropy faster than length alone.

### Crack-Time Scenarios

| Scenario | Speed | Represents |
|---|---|---|
| Online (throttled) | 100 /s | Rate-limited web login |
| Online (unthrottled) | 1 K /s | Unprotected web form |
| Offline (slow hash) | 1 M /s | bcrypt / scrypt |
| Offline (fast hash, CPU) | 1 B /s | SHA-256 on CPU |
| Offline (GPU cluster) | 100 B /s | GPU farm (e.g. Hashcat) |
| Nation-state (ASIC) | 1 T /s | Dedicated ASIC array |

---

## Output File Formats

| Format | Content |
|---|---|
| `.txt` | Human-readable, colour-free |
| `.csv` | Flat table, importable to Excel/Sheets |
| `.json` | Structured, machine-readable |
| `.xlsx` | Excel workbook — bold headers, no pip dependencies |

---

## Logging

All sessions are logged to `logs/passguardian_audit.jsonl`. Each line is a JSON record:

```json
{
  "timestamp": "2024-06-15T14:22:31.123456+00:00",
  "severity": "audit",
  "event": "single_analysis",
  "session_id": "a1b2c3d4",
  "pid": 12345,
  "payload": { "score": 72, "tier": "Strong" }
}
```

Logs rotate automatically at 5 MB, keeping 5 backup files. Passwords are **never** written to logs — only masked values or metadata.

---

## Troubleshooting

**`python: command not found`**
Install Python 3.10+ from https://www.python.org/downloads/ or via your system package manager (`apt`, `brew`, etc.).

**`Permission denied: ./passguardian.sh`**
Run `chmod +x passguardian.sh`.

**XLSX file won't open**
Ensure you have a compatible spreadsheet application (LibreOffice, Excel 2007+). The `.xlsx` is generated as a raw OOXML ZIP.

**Bulk analysis is slow**
Increase `--concurrency` (default 8). On a modern machine, 32–64 works well for I/O-bound workloads.

**Empty results for CSV input**
If your CSV doesn't have a `password` column, specify the correct column name with `--csv-column <name>`.

**JSON parse error**
Accepted JSON shapes:
- `["pw1", "pw2"]`
- `[{"password": "pw1"}, {"password": "pw2"}]`
- `{"passwords": ["pw1", "pw2"]}`

---

## Security Notes

- All analysis is performed **locally**. No data leaves your machine.
- Passwords are **masked** in all output (`h*****2`) and are never written to logs.
- The tool uses Shannon entropy as an approximation. Real-world cracking tools exploit patterns entropy cannot capture — always use a password manager.
- Crack-time estimates assume pure brute-force with no prior knowledge. Dictionary/hybrid attacks are significantly faster against patterned passwords.

---

## Disclaimer

> **PassGuardian is provided for educational and authorised security testing purposes only.**
>
> This tool is designed to help security professionals and individuals evaluate the strength of passwords they own or have explicit permission to test. Use of this tool against systems, accounts, or credentials you do not own or have written authorisation to test may violate local, national, and international laws including — but not limited to — the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent legislation in other jurisdictions.
>
> The author(s) accept no liability for misuse. By using this tool, you accept sole responsibility for ensuring your use complies with all applicable laws and regulations.

---

## Licence

MIT — see `LICENSE` file.
