"""Queue building + CSV/XLSX output (Fase 3, part 1).

Deterministic: synthetic records and fabricated KEV/EPSS, so the expected queue
is fixed and does not depend on the live feeds.
"""
import csv

from mulitaminer.prioritization.queue import (
    QUEUE_COLUMNS,
    build_queue,
    write_csv,
    write_queue,
)

KEV = {"CVE-2020-1938"}
EPSS = {"CVE-2020-1938": 0.99, "CVE-2015-9251": 0.30, "CVE-2000-0001": 0.01}

RECORDS = [
    # active (KEV) + exposed (public IP) + high  -> Act, top of queue
    {"Name": "Ghostcat", "host": "8.8.8.8", "cvss": 9.8, "references": ["cve: CVE-2020-1938"]},
    # likely (EPSS .30) + exposed (no host -> cautious) + medium -> Attend
    {"Name": "jQuery XSS", "host": None, "cvss": 6.1, "references": ["CVE-2015-9251"]},
    # none + internal (RFC1918) + low -> Track
    {"Name": "Info leak", "host": "10.0.0.5", "cvss": 3.1, "references": ["CVE-2000-0001"]},
    # no CVE (WAS-style) + exposed (public FQDN) + high -> unknown -> Act
    {"Name": "SQL Injection", "host": "app.example.com", "cvss": 9.0, "references": []},
]


def test_build_queue_orders_and_ranks():
    rows = build_queue(RECORDS, KEV, EPSS, snapshot_date="2026-06-20")

    assert [r["name"] for r in rows] == [
        "Ghostcat",       # Act, active, EPSS 0.99
        "SQL Injection",  # Act, unknown (no CVE) + exposed + high; EPSS 0.0 sorts below
        "jQuery XSS",     # Attend, likely, EPSS 0.30
        "Info leak",      # Track
    ]
    assert [r["rank"] for r in rows] == [1, 2, 3, 4]
    assert [r["category"] for r in rows] == ["Act", "Act", "Attend", "Track"]


def test_signals_are_auditable_columns():
    top = build_queue(RECORDS, KEV, EPSS, snapshot_date="2026-06-20")[0]
    assert top["kev"] is True
    assert top["exploitation"] == "active"
    assert top["exposure"] == "exposed"
    assert top["severity"] == "high"
    assert top["cves"] == "CVE-2020-1938"
    assert top["snapshot_date"] == "2026-06-20"
    assert "active exploitation (KEV)" in top["justification"]


def test_no_cve_finding_is_unknown_not_none():
    sqli = next(r for r in build_queue(RECORDS, KEV, EPSS) if r["name"] == "SQL Injection")
    assert sqli["cves"] == ""
    assert sqli["kev"] is False
    assert sqli["epss"] == 0.0
    assert sqli["exploitation"] == "unknown"
    assert sqli["category"] == "Act"  # severe + exposed, not discounted as safe


def test_write_csv_roundtrip(tmp_path):
    rows = build_queue(RECORDS, KEV, EPSS, snapshot_date="2026-06-20")
    path = write_csv(rows, tmp_path / "q.csv")

    with open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == QUEUE_COLUMNS
        read = list(reader)
    assert read[0]["name"] == "Ghostcat"
    assert read[0]["rank"] == "1"
    assert len(read) == len(RECORDS)


def test_write_queue_emits_both_formats(tmp_path):
    rows = build_queue(RECORDS, KEV, EPSS)
    paths = write_queue(rows, tmp_path / "report_prioritization")
    assert paths["csv"].exists() and paths["csv"].suffix == ".csv"
    assert paths["xlsx"].exists() and paths["xlsx"].suffix == ".xlsx"


def test_write_queue_keeps_dotted_base_name(tmp_path):
    # A base whose name has dots (e.g. a version) must not be truncated — the
    # extension is appended, not substituted via Path.with_suffix.
    rows = build_queue(RECORDS, KEV, EPSS)
    base = tmp_path / "openvas_artifactory-oss_5.11.0_run1_prioritization"
    paths = write_queue(rows, base)
    assert paths["csv"].name == "openvas_artifactory-oss_5.11.0_run1_prioritization.csv"
    assert paths["xlsx"].name == "openvas_artifactory-oss_5.11.0_run1_prioritization.xlsx"


def test_empty_report_yields_empty_queue(tmp_path):
    rows = build_queue([], KEV, EPSS)
    assert rows == []
    # writing an empty queue must still produce valid files with a header
    path = write_csv(rows, tmp_path / "empty.csv")
    with open(path, encoding="utf-8-sig", newline="") as fh:
        assert next(csv.reader(fh)) == QUEUE_COLUMNS
