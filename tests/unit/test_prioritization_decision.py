"""The SSVC decision tree (Fase 2): exhaustive over all 18 input combinations."""
import itertools

import pytest

from mulitaminer.prioritization.decision import (
    ACT,
    ATTEND,
    CATEGORY_ORDER,
    TRACK,
    TRACK_STAR,
    decide,
)

# The agreed table, transcribed independently of the module's own dict so the
# test actually checks the values rather than echoing them.
EXPECTED = {
    ("active", "exposed", "high"): ACT,
    ("active", "exposed", "medium"): ACT,
    ("active", "exposed", "low"): ATTEND,
    ("active", "internal", "high"): ACT,
    ("active", "internal", "medium"): ATTEND,
    ("active", "internal", "low"): TRACK_STAR,
    ("likely", "exposed", "high"): ACT,
    ("likely", "exposed", "medium"): ATTEND,
    ("likely", "exposed", "low"): TRACK_STAR,
    ("likely", "internal", "high"): ATTEND,
    ("likely", "internal", "medium"): TRACK_STAR,
    ("likely", "internal", "low"): TRACK,
    ("none", "exposed", "high"): ATTEND,
    ("none", "exposed", "medium"): TRACK_STAR,
    ("none", "exposed", "low"): TRACK,
    ("none", "internal", "high"): TRACK_STAR,
    ("none", "internal", "medium"): TRACK,
    ("none", "internal", "low"): TRACK,
    ("unknown", "exposed", "high"): ACT,
    ("unknown", "exposed", "medium"): ATTEND,
    ("unknown", "exposed", "low"): TRACK_STAR,
    ("unknown", "internal", "high"): ATTEND,
    ("unknown", "internal", "medium"): TRACK_STAR,
    ("unknown", "internal", "low"): TRACK,
}


@pytest.mark.parametrize("combo, expected", list(EXPECTED.items()))
def test_decide_matches_agreed_table(combo, expected):
    assert decide(*combo) == expected


def test_tree_covers_every_combination():
    combos = itertools.product(
        ("active", "likely", "none", "unknown"),
        ("exposed", "internal"),
        ("high", "medium", "low"),
    )
    for combo in combos:
        assert decide(*combo) in CATEGORY_ORDER  # no missing / unknown cell


def test_unknown_input_raises():
    with pytest.raises(KeyError):
        decide("bogus", "exposed", "high")
