"""Download the KEV + EPSS feeds for prioritization into ``resources/feeds/``.

Run periodically (manual, cron, or a CI/Docker step) — it is decoupled from
extraction. Usage::

    python tools/sync_feeds.py [--dest resources/feeds]
"""
from __future__ import annotations

import argparse
from pathlib import Path

from mulitaminer.prioritization.feeds import FEEDS_DIR, sync_feeds


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
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


if __name__ == "__main__":
    main()
