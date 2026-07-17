"""save_results: consolidation owns validity filtering and the removed log.

Regression tests for the double-write bug: save.py used to re-run the
Name/description validity filter on already-filtered data and write
`_removed_log.txt` to the same path consolidation writes it, clobbering it.
"""
import json

from mulitaminer.pipeline.save import save_results


def test_invalid_records_filtered_and_logged_once(tmp_path):
    vulns = [
        {"Name": "Real Vuln", "description": ["something"], "severity": "HIGH"},
        {"Name": "No Description", "description": [], "severity": "LOW"},
    ]
    out = tmp_path / "out.json"

    result = save_results(vulns, str(out), profile_config=None, allow_duplicates=True)

    saved = json.loads(out.read_text(encoding="utf-8"))
    assert [v["Name"] for v in saved] == ["Real Vuln"]
    assert result == {
        "success": True,
        "extracted": 2,
        "after_consolidation": 1,
        "final": 1,
    }

    # The removed log exists and is consolidation's (save.py no longer writes one).
    log = (tmp_path / "out_removed_log.txt").read_text(encoding="utf-8")
    assert "LOG OF REMOVED VULNERABILITIES" in log
    assert "No Description" in log


def test_all_valid_records_write_no_removed_log(tmp_path):
    vulns = [{"Name": "Vuln", "description": ["d"], "severity": "HIGH"}]
    out = tmp_path / "out.json"

    save_results(vulns, str(out), profile_config=None, allow_duplicates=True)

    assert not (tmp_path / "out_removed_log.txt").exists()
    assert len(json.loads(out.read_text(encoding="utf-8"))) == 1
