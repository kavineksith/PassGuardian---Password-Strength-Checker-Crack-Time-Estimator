"""
PassGuardian — File I/O helpers and multi-format report writers.

Supported output formats: json, csv, txt, xlsx (pure-stdlib OOXML).
Supported input formats: json, csv, txt (one password per line).
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import struct
import zipfile
from pathlib import Path
from typing import AsyncGenerator, Generator

from .analyser import AnalysisResult
from .exceptions import (
    FileNotFoundError_,
    ParseError,
    UnsupportedFormatError,
    WriteError,
)


# ──────────────────────────────────────────────────────────────────────────────
# Input readers (generators — memory-efficient streaming)
# ──────────────────────────────────────────────────────────────────────────────
def read_passwords_txt(path: str | Path) -> Generator[str, None, None]:
    """Stream passwords one-per-line from a plain-text file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError_(str(p))
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if pw:
                yield pw


def read_passwords_csv(path: str | Path, column: str = "password") -> Generator[str, None, None]:
    """Stream passwords from a CSV file. Tries *column* header, else first column."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError_(str(p))
    try:
        with p.open("r", encoding="utf-8", newline="", errors="replace") as fh:
            reader = csv.DictReader(fh)
            # if no header row detected, fall back to indexed access
            if reader.fieldnames and column in reader.fieldnames:
                for row in reader:
                    pw = (row.get(column) or "").strip()
                    if pw:
                        yield pw
            else:
                fh.seek(0)
                plain = csv.reader(fh)
                for row in plain:
                    if row:
                        yield row[0].strip()
    except csv.Error as exc:
        raise ParseError(str(exc)) from exc


def read_passwords_json(path: str | Path) -> Generator[str, None, None]:
    """
    Stream passwords from JSON.
    Accepts:
      - list of strings:          ["pass1", "pass2"]
      - list of objects with key: [{"password": "pass1"}, ...]
      - object with list value:   {"passwords": ["pass1", ...]}
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError_(str(p))
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON: {exc}") from exc

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str) and item:
                yield item
            elif isinstance(item, dict):
                for key in ("password", "pass", "pwd", "Password"):
                    if key in item and item[key]:
                        yield str(item[key])
                        break
    elif isinstance(data, dict):
        for key in ("passwords", "password", "pass", "pwd"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if item:
                        yield str(item)
                break


def read_passwords(path: str | Path, column: str = "password") -> Generator[str, None, None]:
    """Dispatch to correct reader based on file extension."""
    ext = Path(path).suffix.lower()
    if ext in (".txt", ".list", ""):
        yield from read_passwords_txt(path)
    elif ext == ".csv":
        yield from read_passwords_csv(path, column)
    elif ext == ".json":
        yield from read_passwords_json(path)
    else:
        raise UnsupportedFormatError(ext)


# ──────────────────────────────────────────────────────────────────────────────
# Output writers
# ──────────────────────────────────────────────────────────────────────────────
class ReportWriter:
    """
    Write analysis results to one or more output formats concurrently.
    All write operations are async; blocking I/O is offloaded to executor.
    """

    SUPPORTED = {"json", "csv", "txt", "xlsx"}

    def __init__(self, results: list[AnalysisResult], output_dir: str | Path = ".") -> None:
        self._results    = results
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    async def write_all(self, formats: list[str], base_name: str = "report") -> list[Path]:
        """Write all formats concurrently; return list of produced paths."""
        tasks = []
        for fmt in formats:
            fmt = fmt.lower()
            if fmt not in self.SUPPORTED:
                raise UnsupportedFormatError(fmt)
            tasks.append(self._dispatch(fmt, base_name))
        paths = await asyncio.gather(*tasks)
        return list(paths)

    async def _dispatch(self, fmt: str, base_name: str) -> Path:
        loop = asyncio.get_event_loop()
        fn   = {
            "json": self._write_json,
            "csv":  self._write_csv,
            "txt":  self._write_txt,
            "xlsx": self._write_xlsx,
        }[fmt]
        path = self._output_dir / f"{base_name}.{fmt}"
        await loop.run_in_executor(None, fn, path)
        return path

    # ── format writers ────────────────────────────────────────────────────────
    def _write_json(self, path: Path) -> None:
        try:
            data = {
                "tool": "PassGuardian",
                "total": len(self._results),
                "results": [r.to_dict() for r in self._results],
            }
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            raise WriteError(str(path), str(exc)) from exc

    def _write_csv(self, path: Path) -> None:
        try:
            if not self._results:
                path.write_text("", encoding="utf-8")
                return
            rows = [r.to_dict() for r in self._results]
            # Flatten nested fields
            for row in rows:
                row["crack_times"] = "; ".join(f"{k}: {v}" for k, v in row["crack_times"].items())
                row["penalties"]   = "; ".join(row["penalties"])
                row["suggestions"] = "; ".join(row["suggestions"])
            with path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        except OSError as exc:
            raise WriteError(str(path), str(exc)) from exc

    def _write_txt(self, path: Path) -> None:
        try:
            lines = []
            for i, r in enumerate(self._results, 1):
                lines.append(f"{'─' * 60}")
                lines.append(f"  Password #{i}")
                lines.append(str(r))
            lines.append(f"{'─' * 60}")
            path.write_text("\n".join(lines), encoding="utf-8")
        except OSError as exc:
            raise WriteError(str(path), str(exc)) from exc

    def _write_xlsx(self, path: Path) -> None:
        """Pure-stdlib OOXML writer (no openpyxl dependency)."""
        try:
            if not self._results:
                return
            rows = [r.to_dict() for r in self._results]
            for row in rows:
                row["crack_times"] = "; ".join(f"{k}: {v}" for k, v in row["crack_times"].items())
                row["penalties"]   = "; ".join(row["penalties"])
                row["suggestions"] = "; ".join(row["suggestions"])

            headers = list(rows[0].keys())
            _write_xlsx_ooxml(path, "PassGuardian Report", headers, rows)
        except OSError as exc:
            raise WriteError(str(path), str(exc)) from exc


# ──────────────────────────────────────────────────────────────────────────────
# Pure-stdlib OOXML helper
# ──────────────────────────────────────────────────────────────────────────────
def _escape_xml(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _cell_xml(col: int, row: int, value: object, bold: bool = False) -> str:
    col_letter = chr(ord("A") + col)
    ref = f"{col_letter}{row}"
    v   = _escape_xml(str(value))
    if bold:
        return f'<c r="{ref}" t="inlineStr" s="1"><is><t>{v}</t></is></c>'
    return f'<c r="{ref}" t="inlineStr"><is><t>{v}</t></is></c>'


def _write_xlsx_ooxml(
    path: Path,
    sheet_name: str,
    headers: list[str],
    rows: list[dict],
) -> None:
    # ── sheet XML ─────────────────────────────────────────────────────────────
    sheet_rows = []
    # header row
    header_cells = "".join(
        _cell_xml(c, 1, h, bold=True) for c, h in enumerate(headers)
    )
    sheet_rows.append(f'<row r="1">{header_cells}</row>')

    for r_idx, row in enumerate(rows, start=2):
        cells = "".join(
            _cell_xml(c, r_idx, row.get(h, ""))
            for c, h in enumerate(headers)
        )
        sheet_rows.append(f'<row r="{r_idx}">{cells}</row>')

    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>' + "".join(sheet_rows) + "</sheetData>"
        "</worksheet>"
    )

    # ── styles XML (bold style index 1) ───────────────────────────────────────
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<fonts><font/><font><b/></font></fonts>"
        "<fills><fill/><fill/></fills>"
        "<borders><border/></borders>"
        "<cellStyleXfs><xf/></cellStyleXfs>"
        "<cellXfs><xf/><xf><font><b/></font></xf></cellXfs>"
        "</styleSheet>"
    )

    # ── workbook XML ──────────────────────────────────────────────────────────
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        "<sheets>"
        f'<sheet name="{_escape_xml(sheet_name)}" sheetId="1" r:id="rId1"/>'
        "</sheets></workbook>"
    )

    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
        "</Relationships>"
    )

    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        "</Types>"
    )

    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        zf.writestr("xl/styles.xml", styles_xml)
