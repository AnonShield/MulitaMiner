"""The pipeline entry point: prioritize an extraction JSON into CSV/XLSX."""
import json

from mulitaminer.prioritization import apply as apply_mod
from mulitaminer.prioritization.apply import prioritize_extraction


def _write_json(path, records):
    path.write_text(json.dumps(records), encoding="utf-8")
    return path


def test_skips_when_feeds_missing(tmp_path, capsys, monkeypatch):
    # Disable auto-sync so the "missing feeds" path is exercised offline.
    monkeypatch.setenv("MULITA_FEED_AUTOSYNC", "0")
    extraction = _write_json(tmp_path / "report.json", [{"Name": "x", "cvss": 5.0}])
    empty_feeds = tmp_path / "no_feeds"  # never synced

    result = prioritize_extraction(extraction, feeds_dir=empty_feeds)

    assert result is None
    assert "Skipped" in capsys.readouterr().out


def test_autosync_disabled_does_not_sync(tmp_path, monkeypatch):
    monkeypatch.setenv("MULITA_FEED_AUTOSYNC", "0")

    def boom(*a, **k):
        raise AssertionError("ensure_fresh_feeds must not run when auto-sync is off")

    monkeypatch.setattr(apply_mod, "ensure_fresh_feeds", boom)
    extraction = _write_json(tmp_path / "report.json", [{"Name": "x", "cvss": 5.0}])

    # No feeds + no sync attempt → graceful skip, no exception.
    assert prioritize_extraction(extraction, feeds_dir=tmp_path / "no_feeds") is None


def test_writes_queue_next_to_json(tmp_path, monkeypatch):
    monkeypatch.setenv("MULITA_FEED_AUTOSYNC", "0")  # use the fabricated feeds as-is
    extraction = _write_json(
        tmp_path / "OpenVAS_demo.json",
        [
            {"Name": "Ghostcat", "host": "8.8.8.8", "cvss": 9.8,
             "references": ["cve: CVE-2020-1938"]},
            {"Name": "Info leak", "host": "10.0.0.5", "cvss": 3.1, "references": []},
        ],
    )
    # Fabricate a synced feed dir so the run is deterministic.
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "kev.json").write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2020-1938"}]}), encoding="utf-8"
    )
    import gzip
    with gzip.open(feeds / "epss.csv.gz", "wt", encoding="utf-8") as fh:
        fh.write("#model_version,score_date:2026-06-20T00:00:00\n")
        fh.write("cve,epss,percentile\nCVE-2020-1938,0.99,0.99\n")
    (feeds / "meta.json").write_text(
        json.dumps({"synced_at": "2026-06-20T00:00:00+00:00",
                    "epss_score_date": "2026-06-20T00:00:00"}),
        encoding="utf-8",
    )

    paths = prioritize_extraction(extraction, feeds_dir=feeds)

    assert paths["csv"].name == "OpenVAS_demo_prioritization.csv"
    assert paths["csv"].parent == extraction.parent  # beside the JSON
    assert paths["csv"].exists() and paths["xlsx"].exists()
