import os

from mulitaminer.cli_args import _nest_under_outputs


def test_relative_is_nested_under_outputs():
    assert _nest_under_outputs("cloud_smoke") == os.path.join("outputs", "cloud_smoke")


def test_dot_relative_is_normalized_and_nested():
    assert _nest_under_outputs("./smoke") == os.path.join("outputs", "smoke")


def test_already_under_outputs_unchanged():
    p = os.path.join("outputs", "runs")
    assert _nest_under_outputs(p) == p


def test_outputs_root_itself_unchanged():
    assert _nest_under_outputs("outputs") == "outputs"


def test_absolute_path_unchanged():
    ap = os.path.abspath(os.sep + "some_abs_dir")
    assert _nest_under_outputs(ap) == ap
