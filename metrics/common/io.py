"""Standardized read/write helpers shared across metric pipelines.

Public API:
    load_baseline(path)   — read the baseline XLSX, picking the right sheet
    load_extraction(path) — read an extraction file (.json or .xlsx)
    write_xlsx(path, sheets) — write a multi-sheet XLSX in one call

Extractions are accepted as either ``.json`` (the tool's native output —
preferred, no conversion needed) or ``.xlsx`` (legacy / human-readable).
Baselines are always XLSX since they're hand-curated ground truth.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, Mapping, Union

import pandas as pd

from metrics.common.sheet_resolver import resolve_baseline_sheet


# Fields that the V3 schema expects as dict / list, but XLSX cannot natively
# represent — so they round-trip through pandas as the literal string `"{...}"`
# or `"[...]"`. We parse them back on load so downstream metrics see the
# right Python types without each pipeline having to handle the quirk.
_STRUCTURED_FIELDS: tuple[str, ...] = (
    "plugin_details",  # dict — Tenable populates real keys; OpenVAS always {}
    "instances",       # list[dict] — Tenable HTTP request data; OpenVAS always []
    "cvss",            # list[str] — Tenable schema (CVSSV3/V4 score+vector strings).
                       # OpenVAS rows are float and won't trigger the parser
                       # (`_parse_xlsx_struct` short-circuits on non-string input).
)


def _parse_xlsx_struct(value: Any) -> Any:
    """Convert an XLSX-stored stringified dict/list back to the real Python type.

    Tries ``json.loads`` first (handles double-quoted JSON), falls back to
    ``ast.literal_eval`` (handles single-quoted Python repr). Returns the
    value untouched if it isn't a stringified container.
    """
    if not isinstance(value, str):
        return value
    s = value.strip()
    if not s or s[0] not in "{[":
        return value
    try:
        return json.loads(s)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return ast.literal_eval(s)
    except (ValueError, SyntaxError):
        return value  # leave as string; downstream will see the type mismatch


def _read_resolved_xlsx(path: Path) -> pd.DataFrame:
    xls = pd.ExcelFile(path, engine="openpyxl")
    df = pd.read_excel(path, sheet_name=resolve_baseline_sheet(xls), engine="openpyxl")
    # Restore Python types for fields that XLSX flattened to strings.
    for col in _STRUCTURED_FIELDS:
        if col in df.columns:
            df[col] = df[col].map(_parse_xlsx_struct)
    return df


# Type expectations the baseline XLSX must satisfy (post-_parse_xlsx_struct).
# Subset of V3_SCHEMA — covers the fields metric pipelines actually rely on.
# Accepts the union of OpenVAS (cvss as float) and Tenable (cvss as list of
# CVSSV3/V4 strings) shapes — both are legitimate, the differentiator is the
# scanner profile. Validator is intentionally permissive on cvss for that reason.
_BASELINE_EXPECTED_TYPES: dict[str, tuple[type, ...]] = {
    "cvss":           (int, float, list, type(None)),
    "port":           (int, str, type(None)),
    "protocol":       (str, type(None)),
    "severity":       (str,),
    "plugin_details": (dict, type(None)),
    "instances":      (list, type(None)),
}


def validate_baseline(df: pd.DataFrame, *, raise_on_error: bool = False) -> list[str]:
    """Sanity check that the baseline DataFrame matches the V3 schema.

    Returns a list of issue strings (one per offending column). When
    ``raise_on_error`` is True and issues are found, raises ``ValueError``;
    otherwise the caller can ``print`` / ``log`` the list to stderr.

    Skips NaN/None values (legitimate "field not applicable") — only flags
    cells that are non-null but the wrong Python type. ``plugin_details``
    being a string ``"{}"`` instead of dict ``{}`` is the canonical failure
    this catches.
    """
    issues: list[str] = []
    for col, allowed in _BASELINE_EXPECTED_TYPES.items():
        if col not in df.columns:
            continue
        for idx, value in df[col].items():
            # Treat NaN as None — pandas-ism, legitimate "not applicable"
            if value is None or (isinstance(value, float) and pd.isna(value)):
                continue
            if not isinstance(value, allowed):
                expected = "|".join(t.__name__ for t in allowed if t is not type(None))
                issues.append(
                    f"row {idx} col '{col}': expected {expected}, got "
                    f"{type(value).__name__} ({value!r:.60})"
                )
                break  # one example per column is enough for the diagnostic
    if issues and raise_on_error:
        raise ValueError("Baseline does not match V3 schema:\n  " + "\n  ".join(issues))
    return issues


def load_baseline(path: Union[str, Path], *, validate: bool = True) -> pd.DataFrame:
    """Read the baseline XLSX. Resolves the canonical sheet automatically.

    Side-effect: ``plugin_details`` and ``instances`` columns are JSON-decoded
    in-flight (XLSX can't represent dict/list natively, so they're stored as
    strings — see ``_STRUCTURED_FIELDS``).

    When ``validate`` is True (default), runs ``validate_baseline()`` and
    prints any type-mismatch warnings to stderr — useful catch for
    hand-curated baselines drifting from the canonical V3 schema.
    """
    df = _read_resolved_xlsx(Path(path))
    if validate:
        issues = validate_baseline(df)
        if issues:
            import sys
            print(f"[BASELINE] {Path(path).name} has type mismatches vs V3 schema:",
                  file=sys.stderr)
            for issue in issues:
                print(f"  ⚠ {issue}", file=sys.stderr)
    return df


def load_extraction(path: Union[str, Path]) -> pd.DataFrame:
    """Read an extraction file. Accepts ``.json`` (native) or ``.xlsx`` (legacy).

    JSON is expected to be a flat list of vulnerability dicts — exactly what
    ``main.py`` writes. Each dict becomes a DataFrame row. Other shapes
    (``{"vulnerabilities": [...]}``, single dict) are detected and unwrapped.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".json":
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for key in ("vulnerabilities", "data", "items"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
            else:
                data = [data]
        if not isinstance(data, list):
            raise ValueError(f"Unexpected JSON shape in {path}: {type(data).__name__}")
        return pd.DataFrame(data)
    if suffix in (".xlsx", ".xls"):
        return _read_resolved_xlsx(path)
    raise ValueError(f"Unsupported extraction format: {path.suffix} (use .json or .xlsx)")


def write_xlsx(path: Union[str, Path], sheets: Mapping[str, pd.DataFrame]) -> Path:
    """Write a multi-sheet XLSX in one call.

    Creates parent directories if needed. Index is written for sheets
    that have a non-default index (typical for confusion matrices), and
    skipped otherwise — matching what each pipeline did inline.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with pd.ExcelWriter(path) as writer:
        for sheet_name, df in sheets.items():
            with_index = df.index.name is not None and df.index.name != "index"
            df.to_excel(writer, sheet_name=sheet_name, index=with_index)
    return path
