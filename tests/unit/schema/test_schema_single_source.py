"""The vulnerability schema has one source of truth: configs/vuln_schema.py.

These tests lock that in:

  1. field_categories.json (metric config) must not drift from the model's
     field set. We guard rather than derive: which fields are "deterministic"
     vs "semantic" is a *metric* decision, a separate concern from the schema.

  2. The prompts stay hand-written (their exact wording/field-order matters), but
     must not drop a field the model declares — a guard, not generation. A
     regeneration experiment measurably hurt port/protocol extraction, so we keep
     the tuned prompts and just check them for drift here.

  3. The model accepts the real per-scanner shapes — including the exact drift
     the single source of truth fixed (Tenable's list cvss and int plugin, which
     the old hand-copied V3_SCHEMA wrongly rejected).
"""
import re
from pathlib import Path

import mulitaminer
from metrics.common.field_mapper import load_field_categories
from mulitaminer.configs.vuln_schema import (
    OpenVASRecord,
    TenableRecord,
    VulnRecord,
    expected_fields,
    parse_record,
    validation_types,
)

# Locate prompts via the installed package, not a relative parent count — the
# latter breaks the moment the test file moves (as it did into tests/unit/schema/).
_PROMPTS = Path(mulitaminer.__file__).parent / "configs" / "prompts"


def _aliases(model) -> set[str]:
    """The JSON field names of a model (alias where set, e.g. Name)."""
    return {f.alias or n for n, f in model.model_fields.items()}


def _prompt_field_names(prompt_file: str) -> set[str]:
    """The field names in a prompt's `JSON SCHEMA` block (the `"field":` keys)."""
    text = (_PROMPTS / prompt_file).read_text(encoding="utf-8")
    start = text.index("JSON SCHEMA")
    block = text[start : text.index("EXAMPLE", start)]  # schema line, before examples
    return set(re.findall(r'"(\w+)"\s*:', block))


def test_field_categories_field_set_matches_model():
    # Every JSON field the model declares, across base + subclasses, except
    # scanner_specific (a post-processing namespace metrics don't score).
    model_fields = (
        _aliases(VulnRecord) | _aliases(OpenVASRecord) | _aliases(TenableRecord)
    ) - {"scanner_specific"}

    fc = load_field_categories()
    # Internal computed keys (_Name_norm, _composite_key) aren't schema fields.
    fc_fields = (
        set(fc["deterministic"])
        | set(fc["semantic"])
        | {f for f in fc["excluded"] if not f.startswith("_")}
    )

    assert model_fields == fc_fields, (
        "field_categories.json drifted from the model. "
        f"Only in model: {sorted(model_fields - fc_fields)}. "
        f"Only in config: {sorted(fc_fields - model_fields)}."
    )


def test_prompts_cover_every_model_field():
    # Guard, not generation: each prompt's schema block must mention every field
    # the model says that scanner produces. Catches "added a field to the model
    # but forgot the prompt". The prompt may carry extras (e.g. OpenVAS host).
    for source, prompt_file in [
        ("OPENVAS", "openvas_prompt.txt"),
        ("TENABLEWAS", "tenable_prompt.txt"),
    ]:
        prompt_fields = _prompt_field_names(prompt_file)
        missing = set(expected_fields(source)) - prompt_fields
        assert not missing, f"{prompt_file} is missing model field(s): {sorted(missing)}"


def test_openvas_record_takes_numeric_cvss_and_null_plugin():
    rec = parse_record(
        {"Name": "X", "severity": "HIGH", "source": "OPENVAS",
         "cvss": 7.5, "plugin": None}
    )
    assert isinstance(rec, OpenVASRecord)
    assert rec.cvss == 7.5
    assert rec.plugin is None


def test_tenable_record_takes_list_cvss_and_int_plugin():
    # This is the exact shape the old V3_SCHEMA flagged as two type errors.
    rec = parse_record(
        {"Name": "Y", "severity": "MEDIUM", "source": "TENABLEWAS",
         "cvss": ["CVSSV3 BASE SCORE 6.5"], "plugin": 98056,
         "instances": [{"instance": "https://x"}]}
    )
    assert isinstance(rec, TenableRecord)
    assert rec.cvss == ["CVSSV3 BASE SCORE 6.5"]
    assert rec.plugin == 98056
    assert rec.instances[0].instance == "https://x"


def test_coverage_field_lists_stay_anchored_to_model():
    # coverage.py keeps its own lists ON PURPOSE (they answer metric questions,
    # not schema questions — see its docstring). This guard only pins them to
    # the model's field set, so a schema rename/removal fails loudly here
    # instead of silently zeroing a metric.
    from metrics.pipelines.coverage import CANONICAL_FIELDS, ERM_FIELDS

    assert set(CANONICAL_FIELDS) == set(expected_fields()), (
        "coverage.CANONICAL_FIELDS drifted from the model's LLM-produced fields"
    )
    assert set(ERM_FIELDS) <= set(CANONICAL_FIELDS)


def test_canonicalizer_fields_exist_in_model():
    from metrics.common.schema_canonicalizer import V2_TO_V3_COERCIBLE_FIELDS

    assert set(V2_TO_V3_COERCIBLE_FIELDS) <= set(expected_fields())


def test_aligner_composite_key_fields_exist_in_model():
    # aligner builds composite keys from these names inline; a model rename
    # would silently break record alignment without this guard.
    model_fields = _aliases(VulnRecord)
    for field in ("Name", "port", "protocol", "severity", "plugin", "source"):
        assert field in model_fields, f"aligner relies on '{field}' — missing from model"


def test_prioritization_host_fields_cover_model_names():
    # signals.py is deliberately loose (tries many names to support unknown
    # scanners) — but the names the CURRENT schema provides must be among them,
    # or host_of() goes blind after a schema rename with no failing test.
    from mulitaminer.configs.vuln_schema import Instance
    from mulitaminer.prioritization.signals import (
        HOST_FIELDS,
        INSTANCE_FIELDS,
        INSTANCE_HOST_KEYS,
    )

    model_fields = _aliases(VulnRecord)
    assert "host" in model_fields and "host" in HOST_FIELDS
    assert "instances" in model_fields and "instances" in INSTANCE_FIELDS
    assert "instance" in Instance.model_fields and "instance" in INSTANCE_HOST_KEYS


def test_baseline_types_are_union_of_registered_scanners():
    # io.py derives its baseline type checks from the model (union across
    # scanners, since one baseline mixes both shapes). Behavioral check:
    # both scanners' legitimate shapes pass, the canonical failure is flagged.
    import pandas as pd

    from metrics.common.io import validate_baseline

    # dtype=object keeps 443 an int (default inference would coerce the
    # int+None column to float64, a pandas-ism unrelated to what's tested).
    mixed = pd.DataFrame(
        [
            # OpenVAS shape: numeric cvss
            {"cvss": 7.5, "port": 443, "protocol": "tcp", "severity": "HIGH",
             "plugin_details": {}, "instances": []},
            # Tenable shape: list cvss, structured plugin_details
            {"cvss": ["CVSSV3 BASE SCORE 6.5"], "port": None, "protocol": None,
             "severity": "MEDIUM", "plugin_details": {"plugin_id": 1},
             "instances": [{"instance": "https://x"}]},
        ],
        dtype=object,
    )
    assert validate_baseline(mixed) == []

    # plugin_details stored as the string "{}" (XLSX flattening not un-done).
    broken = mixed.copy()
    broken["plugin_details"] = ["{}", "{}"]
    issues = validate_baseline(broken)
    assert issues and "plugin_details" in issues[0]


def test_validation_types_are_source_aware():
    # The drift fix: Tenable plugin is int (was str in the old copy),
    # Tenable cvss allows list, OpenVAS cvss is a number.
    assert int in validation_types("TENABLEWAS")["plugin"]
    assert list in validation_types("TENABLEWAS")["cvss"]
    assert float in validation_types("OPENVAS")["cvss"]
    assert list not in validation_types("OPENVAS")["cvss"]
