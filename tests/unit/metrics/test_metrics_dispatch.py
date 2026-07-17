import os

from mulitaminer.pipeline.metrics_dispatch import (
    ALL_METHODS_ORDER,
    METRIC_SCRIPTS,
    expand_evaluation_methods,
)


def test_all_expands_to_every_method_in_order():
    assert expand_evaluation_methods(["all"]) == ALL_METHODS_ORDER


def test_coverage_auto_adds_producer_bert():
    out = expand_evaluation_methods(["coverage"])
    assert "coverage" in out
    assert "bert" in out  # consumer needs a producer


def test_unknown_method_dropped():
    assert expand_evaluation_methods(["does_not_exist"]) == []


def test_output_is_canonically_ordered_regardless_of_input_order():
    out = expand_evaluation_methods(["coverage", "schema", "bert"])
    assert out == [m for m in ALL_METHODS_ORDER if m in out]


def test_every_method_has_a_script():
    for method in ALL_METHODS_ORDER:
        assert method in METRIC_SCRIPTS


def test_metric_script_paths_are_absolute_and_exist():
    # CWD-independence fix: scripts are resolved from the package location, not
    # a relative path that only works when run from the repo root.
    for method, entry in METRIC_SCRIPTS.items():
        script_path = entry[0]
        assert os.path.isabs(script_path), f"{method}: {script_path} is not absolute"
        assert os.path.isfile(script_path), f"{method}: {script_path} does not exist"
