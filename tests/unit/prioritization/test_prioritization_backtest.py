"""Backtest scoring logic (deterministic; no network — feeds passed in)."""
from mulitaminer.prioritization.backtest import run_backtest

# T = report date. One CVE entered KEV *after* T (the positive), one was already
# in KEV at T (a gimme, must not count), one finding has no CVE.
REPORT_DATE = "2026-01-01"
KEV_DATES = {
    "CVE-2030-0001": "2026-03-01",  # after T  -> ground-truth positive
    "CVE-1999-0001": "2020-01-01",  # before T -> already active, not predictive
}
EPSS = {"CVE-2030-0001": 0.04, "CVE-1999-0001": 0.9}

RECORDS = [
    {"Name": "Future-exploited RCE", "host": "8.8.8.8", "cvss": 9.0,
     "references": ["cve: CVE-2030-0001"]},
    {"Name": "Already-known", "host": "8.8.8.8", "cvss": 9.0,
     "references": ["cve: CVE-1999-0001"]},
    {"Name": "No-CVE finding", "host": "10.0.0.1", "cvss": 3.0, "references": []},
    {"Name": "Filler A", "host": "10.0.0.2", "cvss": 2.0, "references": []},
    {"Name": "Filler B", "host": "10.0.0.3", "cvss": 2.0, "references": []},
]


def test_positive_is_the_after_T_cve_only():
    result = run_backtest(RECORDS, REPORT_DATE, KEV_DATES, EPSS)

    assert result["total"] == 5
    assert result["with_cve"] == 2
    assert result["kev_at_count"] == 1          # CVE-1999-0001 only
    assert result["later_kev_total"] == 1       # CVE-2030-0001 only

    positives = result["positives"]
    assert [p["name"] for p in positives] == ["Future-exploited RCE"]
    assert positives[0]["newly_cves"] == ["CVE-2030-0001"]
    # At T its EPSS was low and it wasn't yet in KEV, so the queue saw "none";
    # exposed + high still lifted it to Attend rather than burying it.
    assert positives[0]["category"] == "Attend"


def test_already_active_cve_is_not_a_positive():
    result = run_backtest(RECORDS, REPORT_DATE, KEV_DATES, EPSS)
    by_name = {r["name"]: r for r in result["rows"]}
    # It was in KEV at T, so it is ranked as active — but never a predictive hit.
    assert by_name["Already-known"]["exploitation"] == "active"
    assert by_name["Already-known"]["newly_exploited"] is False


def test_metrics_reflect_single_positive():
    m = run_backtest(RECORDS, REPORT_DATE, KEV_DATES, EPSS)["metrics"]
    assert m["positives"] == 1
    assert m["in_act_or_attend"] == 1           # Attend counts as a top category
    assert m["precision_at"][5] == round(1 / 5, 3)  # 1 positive in the top 5


def test_no_positives_when_nothing_enters_kev_later():
    result = run_backtest(RECORDS, "2040-01-01", KEV_DATES, EPSS)  # T in the far future
    assert result["positives"] == []
    assert result["metrics"] == {"positives": 0}
