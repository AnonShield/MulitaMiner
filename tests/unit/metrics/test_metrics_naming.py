"""Metric output naming must reflect real provenance, not just the --llm flag.

Regression tests for §9 of the tech-debt analysis: a DeepSeek extraction once
produced `schema_report_..._deepseek..._gpt4.json` because --metrics-only used
the default --llm; and metric consumers silently reported "no comparison file"
when their --llm differed by one character from the producer's.
"""
import json
import sys

from metrics.field_f1.field_f1 import find_metric_comparison_file
from metrics.pipelines import schema_check


def test_find_comparison_exact_label(tmp_path):
    target = tmp_path / "bert_comparison_vulnerabilities_deepseek.xlsx"
    target.touch()
    found, metric = find_metric_comparison_file(tmp_path, "deepseek")
    assert found == target
    assert metric == "bert"


def test_find_comparison_falls_back_to_single_candidate(tmp_path):
    # Produced under label 'deepseek', looked up under the default 'gpt4':
    # this used to be a silent "no comparison file".
    target = tmp_path / "bert_comparison_vulnerabilities_deepseek.xlsx"
    target.touch()
    found, metric = find_metric_comparison_file(tmp_path, "gpt4")
    assert found == target
    assert metric == "bert"


def test_find_comparison_refuses_ambiguous_candidates(tmp_path):
    (tmp_path / "bert_comparison_vulnerabilities_deepseek.xlsx").touch()
    (tmp_path / "bert_comparison_vulnerabilities_llama.xlsx").touch()
    found, metric = find_metric_comparison_file(tmp_path, "gpt4")
    assert (found, metric) == (None, None)


def test_schema_report_named_from_extraction_not_llm_flag(tmp_path, monkeypatch):
    # A DeepSeek-named extraction assessed with --llm gpt4 must NOT produce
    # a report labeled gpt4 — the stem is the provenance.
    extraction = tmp_path / "OpenVAS_bBWA_deepseek-v4-flash_run1.json"
    extraction.write_text(
        json.dumps([{"Name": "X", "severity": "HIGH", "source": "OPENVAS"}]),
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.xlsx"
    baseline.touch()  # only existence is checked by the common CLI parser

    monkeypatch.setattr(sys, "argv", [
        "schema_check",
        "--baseline-file", str(baseline),
        "--extraction-file", str(extraction),
        "--output-dir", str(tmp_path),
        "--llm", "gpt4",
    ])
    schema_check.main()

    expected = tmp_path / "schema_report_OpenVAS_bBWA_deepseek-v4-flash_run1.json"
    assert expected.exists()
    assert not list(tmp_path.glob("schema_report_*gpt4*"))
