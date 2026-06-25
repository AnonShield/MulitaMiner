"""Validate our simplified tree against the canonical CISA SSVC Deployer tree.

Our tree drops the SSVC ``Automatable`` axis and uses the CVSS band as a Human
Impact proxy, so each of our cells is compared to the canonical outcome for BOTH
``automatable=no`` and ``automatable=yes``. A cell that matches at least one is
"consistent" with some valid SSVC configuration; otherwise the divergence and its
direction (more/less urgent than canonical) are reported.

Usage:  python tools/ssvc_check.py
"""
from __future__ import annotations

import itertools

from mulitaminer.prioritization.decision import CATEGORY_ORDER, decide
from mulitaminer.prioritization.ssvc_reference import canonical_category

EXPLOITATIONS = ("active", "likely", "none", "unknown")
EXPOSURES = ("exposed", "internal")
SEVERITIES = ("high", "medium", "low")


def _direction(ours: str, ref: str) -> str:
    d = CATEGORY_ORDER[ours] - CATEGORY_ORDER[ref]
    if d == 0:
        return "same"
    return "more urgent" if d < 0 else "less urgent"


def main() -> None:
    rows = []
    consistent = 0
    for expl, expo, sev in itertools.product(EXPLOITATIONS, EXPOSURES, SEVERITIES):
        ours = decide(expl, expo, sev)
        ref_no = canonical_category(expl, expo, sev, "no")
        ref_yes = canonical_category(expl, expo, sev, "yes")
        ok = ours in (ref_no, ref_yes)
        consistent += ok
        rows.append((expl, expo, sev, ours, ref_no, ref_yes, ok))

    total = len(rows)
    print(f"Our tree vs canonical CISA SSVC Deployer tree — {total} cells")
    print("(canonical shown for automatable = no / yes; our tree has no such axis)\n")
    print(f"{'exploit':<9}{'exposure':<9}{'sev':<7}{'ours':<8}{'ssvc:no':<9}{'ssvc:yes':<9}flag")
    for expl, expo, sev, ours, rn, ry, ok in rows:
        flag = "" if ok else f"DIVERGES ({_direction(ours, rn)} vs no)"
        print(f"{expl:<9}{expo:<9}{sev:<7}{ours:<8}{rn:<9}{ry:<9}{flag}")

    print(f"\nConsistent with some SSVC automatable config: {consistent}/{total}")
    print("Exact agreement when automatable=no :",
          sum(1 for r in rows if r[3] == r[4]), f"/{total}")
    print("Exact agreement when automatable=yes:",
          sum(1 for r in rows if r[3] == r[5]), f"/{total}")
    divs = [r for r in rows if not r[6]]
    if divs:
        print(f"\n{len(divs)} cell(s) diverge from BOTH automatable settings:")
        for expl, expo, sev, ours, rn, ry, _ in divs:
            print(f"  {expl}/{expo}/{sev}: ours={ours} vs ssvc(no={rn}, yes={ry}) "
                  f"-> {_direction(ours, ry)}")


if __name__ == "__main__":
    main()
