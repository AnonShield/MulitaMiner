"""The post-LLM validator now actually runs in the save pipeline.

It lived in a dead module (profile_registry, deleted) and was never called, so
weak-model output reached disk unvalidated. Wiring it was verified as a no-op
on strong-model output (0/53 records changed in the DeepSeek control run);
these tests lock in both the no-op and the failure modes it must catch.
"""
import copy
import json

from mulitaminer.llm import validate_and_normalize_vulnerability
from mulitaminer.pipeline.save import save_results


def _complete_openvas_record():
    return {
        "Name": "OpenSSL Weak Cipher",
        "description": ["Weak ciphers accepted."],
        "solution": ["Disable weak ciphers."],
        "impact": [],
        "insight": [],
        "references": ["cve: CVE-2016-2183"],
        "detection_result": [],
        "detection_method": [],
        "product_detection_result": [],
        "log_method": ["Details: ..."],
        "plugin": None,
        "plugin_details": {},
        "instances": [],
        "cvss": 7.5,
        "severity": "HIGH",
        "port": 443,
        "protocol": "tcp",
        "source": "OPENVAS",
    }


def test_well_formed_record_is_a_noop():
    record = _complete_openvas_record()
    assert validate_and_normalize_vulnerability(copy.deepcopy(record)) == record


def test_section_header_garbage_name_is_dropped():
    garbage = {"Name": "VULNERABILITY HIGH PLUGIN ID 98056", "severity": "HIGH"}
    assert validate_and_normalize_vulnerability(garbage) is None
    assert validate_and_normalize_vulnerability({"Name": "  ", "severity": "LOW"}) is None


def test_info_severity_normalized_to_log():
    record = _complete_openvas_record()
    record["severity"] = "INFO"
    assert validate_and_normalize_vulnerability(record)["severity"] == "LOG"


def test_missing_fields_filled_with_typed_defaults():
    # Weak-model case: a sparse record gains the full field set with
    # type-appropriate defaults instead of reaching disk half-shaped.
    sparse = {"Name": "X", "severity": "HIGH", "source": "OPENVAS"}
    out = validate_and_normalize_vulnerability(sparse)
    assert out["description"] == []
    assert out["plugin_details"] == {}
    assert out["cvss"] is None


def test_save_results_drops_garbage_and_keeps_extracted_count(tmp_path):
    vulns = [
        {"Name": "Real", "description": ["d"], "severity": "HIGH", "source": "OPENVAS"},
        {"Name": "VULNERABILITY LOW PLUGIN ID 1", "description": ["hdr"], "severity": "LOW"},
    ]
    out = tmp_path / "out.json"
    result = save_results(vulns, str(out), profile_config=None, allow_duplicates=True)

    saved = json.loads(out.read_text(encoding="utf-8"))
    assert [v["Name"] for v in saved] == ["Real"]
    assert result["extracted"] == 2  # raw count, pre-validation
    assert result["final"] == 1


def test_cais_profile_bypasses_v3_validation(tmp_path):
    # CAIS records use dotted field names; the V3 normalizer must not touch them.
    cais_vuln = {
        "Name": "cais finding",
        "description": ["d"],
        "definition.name": "kept-as-is",
    }
    out = tmp_path / "out.json"
    save_results([cais_vuln], str(out), profile_config={"reader": "cais_openvas"},
                 allow_duplicates=True)

    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved[0]["definition.name"] == "kept-as-is"
    assert "plugin_details" not in saved[0]  # no V3 defaults injected
