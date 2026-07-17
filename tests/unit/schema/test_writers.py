"""Writers must speak the real record contract (single-source schema).

Regression tests for the stale-vocabulary bug: converters used to prioritize
columns that never exist in current output (Synopsis, Risk, CVSSv3 — Nessus-CSV
style) and count severity via item['Risk'], which always fell into the fallback.
"""
import csv
import json

import pytest

from mulitaminer.configs.vuln_schema import validation_types
from mulitaminer.writers.csv_converter import CSVConverter


def _sample_records():
    """Two minimal V3-style records as they appear in real extraction output."""
    return [
        {
            "Name": "Vuln A",
            "severity": "HIGH",
            "description": ["desc a"],
            "source": "OPENVAS",
            "port": 443,
            "protocol": "tcp",
            "zz_extra_field": "kept but deprioritized",
        },
        {
            "Name": "Vuln B",
            "severity": "HIGH",
            "description": ["desc b"],
            "source": "OPENVAS",
            "port": None,
            "protocol": None,
        },
    ]


@pytest.fixture
def json_input(tmp_path):
    path = tmp_path / "extraction.json"
    path.write_text(json.dumps(_sample_records()), encoding="utf-8")
    return path


def test_supported_fields_derive_from_schema():
    fields = CSVConverter().supported_fields
    assert fields == list(validation_types())
    # The stale Nessus-CSV vocabulary must be gone.
    for stale in ("Synopsis", "Risk", "CVSSv3", "See Also"):
        assert stale not in fields


def test_csv_headers_follow_contract_order(json_input, tmp_path):
    out = tmp_path / "extraction.csv"
    CSVConverter().convert(str(json_input), str(out))

    with open(out, encoding="utf-8-sig") as f:
        headers = next(csv.reader(f))

    # Contract fields come first, in model declaration order; extras go last.
    assert headers[0] == "Name"
    assert headers.index("severity") < headers.index("zz_extra_field")
    assert headers.index("description") < headers.index("port")


def test_metadata_counts_severity_from_contract_field(json_input, tmp_path):
    out = tmp_path / "extraction.csv"
    CSVConverter().convert(str(json_input), str(out))

    metadata = (tmp_path / "extraction_metadata.csv").read_text(encoding="utf-8-sig")
    # Both records are HIGH; the old code counted them all as 'Unknown'.
    assert "Severity HIGH,2" in metadata.replace('"', "")
    assert "Unknown" not in metadata
