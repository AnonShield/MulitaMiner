"""Local KEV + EPSS feeds for prioritization.

Sync is *decoupled* from extraction: ``sync_feeds`` downloads the two small
public files (~5 MB total) into ``resources/feeds/``; the prioritization code
only ever *reads* the local snapshot via ``load_kev`` / ``load_epss``. Run the
sync periodically (manual, cron, or ``tools/sync_feeds.py``); nothing is fetched
at prioritization time. ``feed_age_days`` lets callers warn on a stale snapshot.

The directory is gitignored (regenerable cache that changes daily).
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import requests

FEEDS_DIR = Path("resources/feeds")

# CISA Known Exploited Vulnerabilities — single JSON, re-fetched whole (small).
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST EPSS — current scores, gzipped CSV.
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

KEV_FILE = "kev.json"
EPSS_FILE = "epss.csv.gz"
META_FILE = "meta.json"

# Feeds update daily; refresh the local snapshot once it is older than this.
DEFAULT_MAX_AGE_DAYS = 1.0

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_DOWNLOAD_TIMEOUT = 60


def sync_feeds(dest: Path = FEEDS_DIR) -> dict:
    """Download KEV + EPSS into ``dest`` and write a ``meta.json`` snapshot stamp.

    Returns the meta dict. Raises ``requests.HTTPError`` on a failed download
    (fail loud — a half-synced feed dir is worse than a missing one).
    """
    dest.mkdir(parents=True, exist_ok=True)

    # Atomic writes (temp + replace): parallel experiment runs may sync at once,
    # and a half-written feed read by another process is worse than a stale one.
    kev_bytes = _get(KEV_URL)
    _atomic_write(dest / KEV_FILE, kev_bytes)

    epss_bytes = _get(EPSS_URL)
    _atomic_write(dest / EPSS_FILE, epss_bytes)

    meta = {
        "synced_at": datetime.now(UTC).isoformat(),
        "kev_count": len(load_kev(dest)),
        "epss_count": len(load_epss(dest)),
        "epss_score_date": _epss_score_date(epss_bytes),
    }
    _atomic_write(dest / META_FILE, json.dumps(meta, indent=2).encode("utf-8"))
    return meta


def ensure_fresh_feeds(dest: Path = FEEDS_DIR, max_age_days: float = DEFAULT_MAX_AGE_DAYS) -> bool:
    """Sync the feeds only if they are missing or older than ``max_age_days``.

    Network-tolerant: a failed download is swallowed (warned) so callers fall back
    to whatever local snapshot exists — extraction must never break on this.
    Returns ``True`` if a sync actually ran.
    """
    age = feed_age_days(dest)
    if age is not None and age <= max_age_days:
        return False
    try:
        sync_feeds(dest)
        return True
    except Exception as e:  # offline / air-gapped / transient — keep going
        print(f"[PRIORITIZATION] Feed auto-sync skipped ({e}); using local snapshot.")
        return False


def load_kev(dest: Path = FEEDS_DIR) -> set[str]:
    """CVE IDs in the KEV catalog, upper-cased. Empty set if not synced."""
    path = dest / KEV_FILE
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        v["cveID"].upper()
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }


def load_kev_dates(dest: Path = FEEDS_DIR) -> dict[str, str]:
    """Map CVE ID (upper-cased) -> KEV ``dateAdded`` (``YYYY-MM-DD``).

    Backtesting needs the dates to reconstruct the KEV as of a past report date
    and to label which CVEs entered KEV *after* it. Empty dict if not synced.
    """
    path = dest / KEV_FILE
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        v["cveID"].upper(): v.get("dateAdded", "")
        for v in data.get("vulnerabilities", [])
        if v.get("cveID")
    }


def load_epss(dest: Path = FEEDS_DIR) -> dict[str, float]:
    """Map CVE ID (upper-cased) -> EPSS score (0..1). Empty dict if not synced."""
    path = dest / EPSS_FILE
    if not path.exists():
        return {}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return _parse_epss(fh)


def feed_age_days(dest: Path = FEEDS_DIR) -> float | None:
    """Days since the last sync, or ``None`` if never synced. For staleness warnings."""
    path = dest / META_FILE
    if not path.exists():
        return None
    meta = json.loads(path.read_text(encoding="utf-8"))
    synced = datetime.fromisoformat(meta["synced_at"])
    return (datetime.now(UTC) - synced).total_seconds() / 86400


def feed_snapshot_date(dest: Path = FEEDS_DIR) -> str | None:
    """EPSS score date of the local snapshot (stamped into the queue output)."""
    path = dest / META_FILE
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8")).get("epss_score_date")


# --------------------------------------------------------------------------- #
# internals
# --------------------------------------------------------------------------- #
def _get(url: str) -> bytes:
    resp = requests.get(url, timeout=_DOWNLOAD_TIMEOUT)
    resp.raise_for_status()
    return resp.content


def _atomic_write(path: Path, data: bytes) -> None:
    # Write to a per-process temp file, then atomically replace the target, so a
    # concurrent reader never sees a partial file.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _parse_epss(fh) -> dict[str, float]:
    # EPSS CSV starts with a ``#model_version:...,score_date:...`` comment line
    # before the ``cve,epss,percentile`` header — skip comment lines first.
    rows = (line for line in fh if not line.startswith("#"))
    reader = csv.DictReader(rows)
    out: dict[str, float] = {}
    for row in reader:
        cve = (row.get("cve") or "").upper()
        if cve:
            out[cve] = float(row["epss"])
    return out


def _epss_score_date(epss_bytes: bytes) -> str | None:
    # The score date lives in the leading comment line: ``#...,score_date:2026-06-20T...``
    with gzip.open(io.BytesIO(epss_bytes), "rt", encoding="utf-8") as fh:
        first = fh.readline()
    m = re.search(r"score_date:([0-9T:\-]+)", first)
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# CLI (``python tools/sync_feeds.py`` wrapper / ``mulita-sync-feeds`` entry)
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download the KEV + EPSS feeds for prioritization."
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=FEEDS_DIR,
        help=f"feeds directory (default: {FEEDS_DIR})",
    )
    args = parser.parse_args()

    meta = sync_feeds(args.dest)
    print(f"Synced feeds to {args.dest}/")
    print(f"  KEV entries:  {meta['kev_count']}")
    print(f"  EPSS entries: {meta['epss_count']} (score_date: {meta['epss_score_date']})")
    print(f"  synced_at:    {meta['synced_at']}")
