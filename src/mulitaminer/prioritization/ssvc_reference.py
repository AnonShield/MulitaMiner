"""Canonical CISA/CERT SSVC *Deployer* decision tree, for validating our tree.

Source: https://certcc.github.io/SSVC/howto/deployer_tree/ (the 72-row deployer
tree: Exploitation x Automatable x System Exposure x Human Impact -> outcome).
CISA relabels the outcomes, which is the mapping to our four categories:
Defer=Track, Scheduled=Track*, Out-of-cycle=Attend, Immediate=Act.

Our tree is a deliberate simplification — it has no ``Automatable`` axis and uses
the CVSS band as a proxy for Human Impact. ``canonical_category`` therefore takes
``automatable`` explicitly and the comparison (tools/ssvc_check.py) reports where
our simplification diverges and in which direction. Documented assumptions live in
the ``map_*`` functions below.
"""
from __future__ import annotations

from .decision import ACT, ATTEND, TRACK, TRACK_STAR

_OUTCOME_TO_CATEGORY = {
    "defer": TRACK,
    "scheduled": TRACK_STAR,
    "out-of-cycle": ATTEND,
    "immediate": ACT,
}

# The full 72-row deployer tree, verbatim. Columns:
# exploitation | automatable | system_exposure | human_impact | outcome
_DEPLOYER_TREE_RAW = """
none,no,small,low,defer
none,no,small,medium,defer
none,no,small,high,scheduled
none,no,small,very high,scheduled
none,yes,small,low,defer
none,yes,small,medium,scheduled
none,yes,small,high,scheduled
none,yes,small,very high,scheduled
none,no,controlled,low,defer
none,no,controlled,medium,scheduled
none,no,controlled,high,scheduled
none,no,controlled,very high,scheduled
none,yes,controlled,low,scheduled
none,yes,controlled,medium,scheduled
none,yes,controlled,high,scheduled
none,yes,controlled,very high,scheduled
none,no,open,low,defer
none,no,open,medium,scheduled
none,no,open,high,scheduled
none,no,open,very high,scheduled
none,yes,open,low,scheduled
none,yes,open,medium,scheduled
none,yes,open,high,scheduled
none,yes,open,very high,out-of-cycle
public poc,no,small,low,defer
public poc,no,small,medium,scheduled
public poc,no,small,high,scheduled
public poc,no,small,very high,scheduled
public poc,yes,small,low,scheduled
public poc,yes,small,medium,scheduled
public poc,yes,small,high,scheduled
public poc,yes,small,very high,scheduled
public poc,no,controlled,low,defer
public poc,no,controlled,medium,scheduled
public poc,no,controlled,high,scheduled
public poc,no,controlled,very high,scheduled
public poc,yes,controlled,low,scheduled
public poc,yes,controlled,medium,scheduled
public poc,yes,controlled,high,scheduled
public poc,yes,controlled,very high,out-of-cycle
public poc,no,open,low,scheduled
public poc,no,open,medium,scheduled
public poc,no,open,high,scheduled
public poc,no,open,very high,out-of-cycle
public poc,yes,open,low,scheduled
public poc,yes,open,medium,scheduled
public poc,yes,open,high,out-of-cycle
public poc,yes,open,very high,out-of-cycle
active,no,small,low,scheduled
active,no,small,medium,scheduled
active,no,small,high,out-of-cycle
active,no,small,very high,out-of-cycle
active,yes,small,low,scheduled
active,yes,small,medium,out-of-cycle
active,yes,small,high,out-of-cycle
active,yes,small,very high,out-of-cycle
active,no,controlled,low,scheduled
active,no,controlled,medium,scheduled
active,no,controlled,high,out-of-cycle
active,no,controlled,very high,out-of-cycle
active,yes,controlled,low,out-of-cycle
active,yes,controlled,medium,out-of-cycle
active,yes,controlled,high,out-of-cycle
active,yes,controlled,very high,out-of-cycle
active,no,open,low,scheduled
active,no,open,medium,out-of-cycle
active,no,open,high,out-of-cycle
active,no,open,very high,immediate
active,yes,open,low,out-of-cycle
active,yes,open,medium,out-of-cycle
active,yes,open,high,immediate
active,yes,open,very high,immediate
"""

DEPLOYER_TREE: dict[tuple[str, str, str, str], str] = {}
for _line in _DEPLOYER_TREE_RAW.strip().splitlines():
    _expl, _auto, _expo, _hi, _out = _line.split(",")
    DEPLOYER_TREE[(_expl, _auto, _expo, _hi)] = _out


# --- mapping from our signals onto SSVC vocabulary (documented assumptions) --- #
def map_exploitation(value: str) -> str:
    # EPSS-"likely" is treated as SSVC "public poc" (some exploitation signal, not
    # confirmed active); no-CVE "unknown" has no SSVC equivalent -> "none".
    return {"active": "active", "likely": "public poc", "none": "none", "unknown": "none"}[value]


def map_exposure(value: str) -> str:
    return {"exposed": "open", "internal": "controlled"}[value]


def map_human_impact(severity: str) -> str:
    # CVSS band as a proxy for Human Impact; our tree never produces "very high".
    return {"high": "high", "medium": "medium", "low": "low"}[severity]


def canonical_category(exploitation: str, exposure: str, severity: str, automatable: str) -> str:
    """Our (exploitation, exposure, severity) projected onto the canonical tree."""
    key = (
        map_exploitation(exploitation),
        automatable,
        map_exposure(exposure),
        map_human_impact(severity),
    )
    return _OUTCOME_TO_CATEGORY[DEPLOYER_TREE[key]]
