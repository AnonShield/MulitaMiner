"""Build the remediation queue from extracted records and write it out.

One row per finding (the unit of remediation: a finding already binds a host;
its multiple CVEs are aggregated — worst-case exploitation, all CVEs listed).
Every signal that fed the decision is a column, so the category is re-derivable
by hand — the "explainable & reproducible" property. See PLANO_PRIORIZACAO.md.
"""
from __future__ import annotations

import csv
from pathlib import Path

from .decision import CATEGORY_ORDER, decide
from .signals import (
    exploitation,
    exposure,
    extract_cve_ids,
    host_of,
    max_epss,
    severity_band,
)

# Fixed column order: rank, identity, decision, then the raw signals behind it.
QUEUE_COLUMNS = [
    "rank",
    "name",
    "host",
    "category",
    "exposure",
    "exploitation",
    "severity",
    "kev",
    "epss",
    "cvss",
    "cves",
    "justification",
    "snapshot_date",
]


def build_queue(
    records: list[dict],
    kev: set[str],
    epss: dict[str, float],
    snapshot_date: str | None = None,
) -> list[dict]:
    """Score every record and return the ranked queue (most urgent first).

    Order: category (Act>Attend>Track*>Track), then EPSS desc, then CVSS desc.
    """
    rows: list[dict] = []
    for record in records:
        cves = extract_cve_ids(record)
        expo = exposure(record)
        expl = exploitation(cves, kev, epss)
        sev = severity_band(record)
        category = decide(expl, expo, sev)
        score = max_epss(cves, epss)
        rows.append(
            {
                "name": record.get("Name") or record.get("name") or "",
                "host": host_of(record) or "",
                "category": category,
                "exposure": expo,
                "exploitation": expl,
                "severity": sev,
                "kev": any(cve in kev for cve in cves),
                "epss": round(score, 5),
                "cvss": record.get("cvss"),
                "cves": ", ".join(cves),
                "justification": _justify(expl, expo, sev),
                "snapshot_date": snapshot_date or "",
            }
        )

    rows.sort(key=lambda r: (CATEGORY_ORDER[r["category"]], -r["epss"], -_as_float(r["cvss"])))
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank
    return rows


def write_csv(rows: list[dict], path: Path) -> Path:
    """Write the queue to CSV (utf-8-sig so Excel opens it cleanly)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=QUEUE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_xlsx(rows: list[dict], path: Path) -> Path:
    """Write the queue to a single-sheet XLSX (Excel is how specialists review)."""
    import pandas as pd

    path.parent.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows, columns=QUEUE_COLUMNS)
    df.to_excel(path, index=False, sheet_name="Prioritization")
    return path


def write_queue(rows: list[dict], base_path: Path) -> dict[str, Path]:
    """Write both ``<base>.csv`` and ``<base>.xlsx``; return their paths.

    Appends the extension explicitly — ``with_suffix`` would mangle a base whose
    name contains dots (e.g. a version like ``...5.11.0_run1``).
    """
    return {
        "csv": write_csv(rows, base_path.parent / f"{base_path.name}.csv"),
        "xlsx": write_xlsx(rows, base_path.parent / f"{base_path.name}.xlsx"),
    }


# --------------------------------------------------------------------------- #
# internals
# --------------------------------------------------------------------------- #
def _justify(expl: str, expo: str, sev: str) -> str:
    exploit_phrase = {
        "active": "active exploitation (KEV)",
        "likely": "likely exploitation (EPSS)",
        "none": "no known exploitation",
        "unknown": "no CVE to assess exploitation",
    }[expl]
    expo_phrase = "internet-exposed" if expo == "exposed" else "internal asset"
    return f"{exploit_phrase}; {expo_phrase}; {sev} severity"


def _as_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
