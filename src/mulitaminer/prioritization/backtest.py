"""Backtest the prioritization against *future* KEV.

Rank an old report using only what was known at its scan date T (EPSS snapshot of
T, KEV filtered to ``dateAdded <= T``), then check whether the CVEs that entered
KEV *after* T — i.e. the ones that demonstrably became actively exploited — were
ranked near the top. Pure evaluation; reuses ``build_queue`` unchanged (it already
takes the KEV/EPSS sets as arguments). See ``docs/PRIORITIZATION.md``.

Honest scope: only CVE-bearing findings can be scored (no-CVE findings have no KEV
future), and deliberately-vulnerable test apps yield few positives — results are
illustrative, not a powered study.
"""
from __future__ import annotations

import gzip
import io

import requests

from .decision import ACT, ATTEND
from .feeds import _parse_epss
from .queue import build_queue

EPSS_HISTORICAL_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
_TIMEOUT = 60


def fetch_epss_for_date(report_date: str) -> dict[str, float]:
    """Download and parse the EPSS snapshot for ``report_date`` (``YYYY-MM-DD``)."""
    resp = requests.get(EPSS_HISTORICAL_URL.format(date=report_date), timeout=_TIMEOUT)
    resp.raise_for_status()
    with gzip.open(io.BytesIO(resp.content), "rt", encoding="utf-8") as fh:
        return _parse_epss(fh)


def run_backtest(
    records: list[dict],
    report_date: str,
    kev_dates: dict[str, str],
    epss_at_date: dict[str, float],
) -> dict:
    """Rank ``records`` as of ``report_date`` and label rows by future KEV entry.

    ``kev_dates`` is the *current* KEV (CVE -> dateAdded); it is split into the KEV
    as-of-T (used for ranking) and the after-T entries (the ground-truth positives).
    """
    kev_at = {cve for cve, added in kev_dates.items() if added and added <= report_date}
    later = {cve: added for cve, added in kev_dates.items() if added and added > report_date}

    rows = build_queue(records, kev_at, epss_at_date, snapshot_date=report_date)

    for row in rows:
        cves = [c.strip() for c in row["cves"].split(",") if c.strip()]
        # A fair predictive positive: a CVE that enters KEV *after* T and was NOT
        # already active at T (the queue didn't already know it was exploited).
        newly = [c for c in cves if c in later and c not in kev_at]
        row["newly_exploited"] = bool(newly)
        row["newly_cves"] = newly
        row["newly_kev_dates"] = {c: later[c] for c in newly}

    positives = [r for r in rows if r["newly_exploited"]]
    return {
        "report_date": report_date,
        "total": len(rows),
        "with_cve": sum(1 for r in rows if r["cves"]),
        "kev_at_count": len(kev_at),
        "later_kev_total": len(later),
        "positives": positives,
        "rows": rows,
        "metrics": _metrics(rows, positives),
    }


def _metrics(rows: list[dict], positives: list[dict]) -> dict:
    """How well the queue surfaced the positives: category split + precision@k."""
    n_pos = len(positives)
    if not n_pos:
        return {"positives": 0}
    top = {ACT, ATTEND}
    in_top_cats = sum(1 for r in positives if r["category"] in top)
    ranks = [r["rank"] for r in positives]
    return {
        "positives": n_pos,
        "in_act_or_attend": in_top_cats,
        "share_top_cats": round(in_top_cats / n_pos, 3),
        "precision_at": {k: _precision_at(rows, k) for k in (5, 10, 20) if k <= len(rows)},
        "positive_ranks": sorted(ranks),
        "median_rank": sorted(ranks)[n_pos // 2],
    }


def _precision_at(rows: list[dict], k: int) -> float:
    hits = sum(1 for r in rows[:k] if r["newly_exploited"])
    return round(hits / k, 3)
