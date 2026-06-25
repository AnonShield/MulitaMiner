"""The canonical SSVC Deployer reference + mapping used to validate our tree."""
from mulitaminer.prioritization.decision import ACT, TRACK, TRACK_STAR
from mulitaminer.prioritization.ssvc_reference import (
    DEPLOYER_TREE,
    canonical_category,
    map_exploitation,
)


def test_deployer_tree_is_complete():
    # 3 exploitation x 2 automatable x 3 exposure x 4 human impact = 72 rows.
    assert len(DEPLOYER_TREE) == 72


def test_known_canonical_rows():
    # Spot-check anchors from the published tree.
    assert DEPLOYER_TREE[("active", "yes", "open", "high")] == "immediate"
    assert DEPLOYER_TREE[("none", "no", "controlled", "low")] == "defer"
    assert DEPLOYER_TREE[("active", "no", "open", "very high")] == "immediate"


def test_canonical_category_projection():
    # active + exposed + high, automatable=yes -> immediate -> Act
    assert canonical_category("active", "exposed", "high", "yes") == ACT
    # none + internal + low, automatable=no -> defer -> Track
    assert canonical_category("none", "internal", "low", "no") == TRACK
    # likely maps to "public poc"; exposed+high, automatable=no -> scheduled -> Track*
    assert canonical_category("likely", "exposed", "high", "no") == TRACK_STAR


def test_unknown_maps_to_none_in_ssvc_terms():
    assert map_exploitation("unknown") == "none"
    assert map_exploitation("likely") == "public poc"
