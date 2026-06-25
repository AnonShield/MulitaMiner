"""Tie the prioritization layer to an extraction output file.

This is the single entry point the pipeline calls after the JSON is written:
read the records, score them against the local feeds, and drop a
``<name>_prioritization.csv`` / ``.xlsx`` next to the JSON. Non-fatal by
contract — callers wrap it so a missing/stale feed never costs the extraction.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .feeds import (
    FEEDS_DIR,
    ensure_fresh_feeds,
    feed_age_days,
    feed_snapshot_date,
    load_epss,
    load_kev,
)
from .queue import build_queue, write_queue

STALE_FEED_DAYS = 7


def _autosync_enabled() -> bool:
    """Auto-refresh feeds before prioritizing unless explicitly disabled (e.g.
    air-gapped hosts that sync out-of-band): set ``MULITA_FEED_AUTOSYNC=0``."""
    return os.environ.get("MULITA_FEED_AUTOSYNC", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    )


def prioritize_extraction(
    json_path: str | Path,
    feeds_dir: Path = FEEDS_DIR,
) -> dict[str, Path] | None:
    """Write the remediation queue beside ``json_path``; return the output paths.

    Returns ``None`` (and prints why) when feeds are not synced — prioritization
    is skipped, not failed.
    """
    if _autosync_enabled():
        ensure_fresh_feeds(feeds_dir)

    kev = load_kev(feeds_dir)
    epss = load_epss(feeds_dir)
    if not kev and not epss:
        print(
            "[PRIORITIZATION] Skipped: KEV/EPSS feeds not found. "
            "Run `python tools/sync_feeds.py` first."
        )
        return None

    age = feed_age_days(feeds_dir)
    if age is not None and age > STALE_FEED_DAYS:
        print(
            f"[PRIORITIZATION] Warning: feeds are {age:.0f} days old; "
            "consider `python tools/sync_feeds.py`."
        )

    json_path = Path(json_path)
    records = json.loads(json_path.read_text(encoding="utf-8"))
    rows = build_queue(records, kev, epss, snapshot_date=feed_snapshot_date(feeds_dir))

    base = json_path.with_name(f"{json_path.stem}_prioritization")
    paths = write_queue(rows, base)
    print(
        f"[PRIORITIZATION] Queue written: {paths['csv'].name} (+ .xlsx) "
        f"— {len(rows)} findings ranked."
    )
    return paths
