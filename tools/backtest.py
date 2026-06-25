"""Backtest the prioritization against future KEV.

Rank an old report as of its scan date and check whether the findings whose CVEs
later entered KEV were ranked near the top. Usage::

    python tools/backtest.py --input <extraction.json|baseline.xlsx> --date 2025-10-23

The current KEV (resources/feeds/kev.json) supplies the "future"; sync it first
(`python tools/sync_feeds.py`) so the after-date labels are up to date.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mulitaminer.prioritization.backtest import fetch_epss_for_date, run_backtest
from mulitaminer.prioritization.feeds import load_kev_dates


def _load_records(path: Path) -> list[dict]:
    if path.suffix.lower() == ".xlsx":
        import pandas as pd

        df = pd.read_excel(path)
        return [
            {k: (None if pd.isna(v) else v) for k, v in row.items()}
            for row in df.to_dict("records")
        ]
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="extraction JSON or XLSX")
    parser.add_argument("--date", required=True, help="report/scan date, YYYY-MM-DD")
    args = parser.parse_args()

    kev_dates = load_kev_dates()
    if not kev_dates:
        raise SystemExit("KEV feed not found — run `python tools/sync_feeds.py` first.")

    records = _load_records(args.input)
    print(f"Fetching EPSS snapshot for {args.date} …")
    epss = fetch_epss_for_date(args.date)
    result = run_backtest(records, args.date, kev_dates, epss)

    m = result["metrics"]
    print(f"\nBacktest — {args.input.name} as of {result['report_date']}")
    print(f"  findings:            {result['total']} ({result['with_cve']} with a CVE)")
    print(f"  KEV as of T:         {result['kev_at_count']} CVEs")
    print(f"  entered KEV after T: {result['later_kev_total']} CVEs (catalog-wide)")
    print(f"  positives (this report, newly exploited after T): {m['positives']}")

    if not m["positives"]:
        print("\n  No findings entered KEV after the scan date — no backtest signal on")
        print("  this report. (Expected for short time gaps or low-CVE reports.)")
        return

    print(f"  in Act/Attend:       {m['in_act_or_attend']}/{m['positives']} "
          f"(share {m['share_top_cats']})")
    print(f"  positive ranks:      {m['positive_ranks']} (median {m['median_rank']})")
    print(f"  precision@k:         {m['precision_at']}")
    print("\n  Newly-exploited findings (how the T-time queue ranked them):")
    for r in result["positives"]:
        dates = ", ".join(f"{c}→KEV {d}" for c, d in r["newly_kev_dates"].items())
        print(f"    #{r['rank']:<3} {r['category']:<7} epss={r['epss']:.3f} "
              f"cvss={r['cvss']} | {str(r['name'])[:40]} | {dates}")


if __name__ == "__main__":
    main()
