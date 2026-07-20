"""Vulnerability-level alignment between baseline and extraction.

Extracts the composite-key + fuzzy fallback logic that today lives
duplicated inside ``compare_extractions_bert.py`` and
``compare_extractions_rouge.py`` (~200 lines each). This module owns the
single source of truth for *how* we decide that extraction record A
corresponds to baseline record B.

Design:
    - Pure: takes two DataFrames, returns an :class:`AlignmentResult`.
    - Greedy with priority: composite key > exact name > fuzzy name.
    - Duplicate-aware: each baseline row id is used at most once.
    - Hungarian-ready: the matching is a separate phase from scoring, so
      callers can swap to ``scipy.optimize.linear_sum_assignment`` (Fase 3
      do plano) by replacing :func:`_resolve_matches`.

The legacy bert/rouge pipelines keep their scoring-aware tiebreaker for
duplicate names — they can use this module's helpers piecemeal until full
migration.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Set, Tuple

import numpy as np
import pandas as pd
from rapidfuzz import fuzz
from scipy.optimize import linear_sum_assignment

from metrics.common.config import FUZZY_THRESHOLD
from metrics.common.matching import best_fuzzy_match
from metrics.common.normalization import normalize_name


# ---------------------------------------------------------------------------
# Scanner detection + composite key construction
# ---------------------------------------------------------------------------

def _scalar_notnull(v) -> bool:
    """Scalar version of ``pd.notnull`` — handles ndarrays and lists safely.

    ``pd.notnull(np_array)`` returns an *array* of bools, which crashes any
    direct truthiness check (``if pd.notnull(x): ...``) with a
    ``ValueError: truth value of an array is ambiguous``. We treat any
    non-empty array-like as "present" and delegate to ``pd.notnull`` only
    for scalars.
    """
    if isinstance(v, np.ndarray):
        return v.size > 0
    if isinstance(v, (list, tuple, set, dict)):
        return len(v) > 0
    return bool(pd.notnull(v))


def detect_scanner_type(df: pd.DataFrame) -> str:
    """Detect scanner type from the ``source`` column or column shape."""
    if "source" in df.columns:
        sources = df["source"].dropna().str.upper().unique()
        if "OPENVAS" in sources:
            return "openvas"
        if "TENABLE" in sources or "NESSUS" in sources:
            return "tenable"
    if "plugin" in df.columns:
        return "tenable"
    if "protocol" in df.columns and df["protocol"].notna().any():
        return "openvas"
    return "generic"


def normalize_port(port_value) -> str:
    """Strip thousands separators; return ``'*'`` for non-numeric values
    (except the literal string ``'general'`` which OpenVAS emits).

    Float guard: pandas coerces an int column to float64 the moment a
    single ``None`` shows up in the JSON (NaN is float-only). After that,
    ``8019`` arrives here as ``8019.0`` — naïvely stripping the decimal
    point would produce ``"80190"``, silently breaking every composite
    key. Cast back to int first when the float is an integer value.
    Caught when V1 extractions (which DO emit ``null`` ports for "general"
    services) showed 100% MATCHED_NAME_ONLY fallback while V2/V3 (no nulls,
    column stayed dtype=object) matched via composite cleanly.
    """
    if isinstance(port_value, float):
        if pd.isna(port_value):
            return "*"
        if port_value.is_integer():
            port_value = int(port_value)
    s = str(port_value).strip().replace(",", "").replace(".", "")
    if not s or (not s.isdigit() and s.lower() != "general"):
        return "*"
    return s


def build_composite_key(row: pd.Series, scanner_type: str) -> str:
    """Build the composite identifier for a single record.

    Layout per scanner:
        openvas → ``<name>|<port>|<protocol>``
        tenable → ``<name>|<severity>|<plugin>``
        generic → ``<name>``

    Special case: the sentinel name ``"services"`` appears many times in
    OpenVAS with different details. We hash the full row to keep instances
    distinguishable instead of collapsing them on name alone.
    """
    name = normalize_name(str(row.get("Name", "")))

    if scanner_type == "openvas":
        if name == "services":
            # ``pd.notnull`` returns an array (not a bool) when ``v`` is a list
            # or ndarray — guard with the scalar helper so the dict comprehension
            # never tries to bool-cast an array.
            row_dict = {k: v for k, v in row.items() if _scalar_notnull(v)}
            return f"services_exact|{hash(json.dumps(row_dict, sort_keys=True, default=str))}"
        port = normalize_port(row.get("port", ""))
        protocol = str(row.get("protocol", "")).strip().lower() or "*"
        return f"{name}|{port}|{protocol}"

    if scanner_type == "tenable":
        severity = str(row.get("severity", "")).strip().lower() or "*"
        plugin = str(row.get("plugin", "")).strip() or "*"
        return f"{name}|{severity}|{plugin}"

    return name


def keys_match(key1: str, key2: str) -> bool:
    """Two composite keys are compatible if every position matches or is ``'*'``."""
    parts1, parts2 = key1.split("|"), key2.split("|")
    if len(parts1) != len(parts2):
        return False
    return all(a == "*" or b == "*" or a == b for a, b in zip(parts1, parts2))


def key_match_score(key1: str, key2: str) -> float:
    """Score in [0, 1]: concrete equal parts contribute 1.0, wildcards 0.3."""
    parts1, parts2 = key1.split("|"), key2.split("|")
    if len(parts1) != len(parts2):
        return 0.0
    score = 0.0
    for a, b in zip(parts1, parts2):
        if a == "*" or b == "*":
            score += 0.3
        elif a == b:
            score += 1.0
    return score / len(parts1) if parts1 else 0.0


# ---------------------------------------------------------------------------
# Alignment
# ---------------------------------------------------------------------------

@dataclass
class AlignmentResult:
    """Output of :func:`align`.

    Attributes:
        pairs: list of ``(extraction_row_idx, baseline_row_idx)`` matched pairs.
        unmatched_extraction: extraction row indices with no baseline match.
        unmatched_baseline: baseline row indices not consumed by any pair.
        debug_rows: dicts ready to populate the ``Mapping_Debug`` sheet
            consumed by field_f1/severity/paper pipelines.
        scanner_type: detected scanner kind (``openvas``/``tenable``/``generic``).
    """
    pairs: List[Tuple[int, int]] = field(default_factory=list)
    unmatched_extraction: List[int] = field(default_factory=list)
    unmatched_baseline: List[int] = field(default_factory=list)
    debug_rows: List[Dict] = field(default_factory=list)
    scanner_type: str = "generic"


def align(
    baseline_df: pd.DataFrame,
    extraction_df: pd.DataFrame,
    *,
    method: Literal["greedy", "hungarian"] = "greedy",
    allow_duplicates: bool = False,
    fuzzy_threshold: float = FUZZY_THRESHOLD,
) -> AlignmentResult:
    """Align extraction records to baseline records.

    Args:
        baseline_df: human-annotated reference, with a ``Name`` column.
        extraction_df: LLM output to align.
        method: ``"greedy"`` (default, legacy behavior — composite > exact >
            fuzzy with first-fit) or ``"hungarian"`` (optimal global
            assignment via ``scipy.optimize.linear_sum_assignment``).
        allow_duplicates: when False (default), the baseline is deduplicated
            by normalized Name before matching — matches the legacy mode used
            by bert/rouge for general comparisons. When True, every baseline
            instance is kept (legitimate-duplicates mode).
        fuzzy_threshold: minimum similarity to accept a match. Greedy uses
            this only on rapidfuzz fallback; Hungarian uses it as a global
            cutoff on the optimal assignment.
    """
    scanner_type = detect_scanner_type(baseline_df)
    base, ext = _prepare(baseline_df, extraction_df, scanner_type, allow_duplicates)

    if method == "hungarian":
        return _resolve_hungarian(base, ext, scanner_type, fuzzy_threshold)

    composite_map = _composite_phase(base, ext)
    exact_map = _exact_phase(base, ext)
    fuzzy_map = _fuzzy_phase(base, ext, exact_map, fuzzy_threshold)
    return _resolve_matches(base, ext, composite_map, exact_map, fuzzy_map, scanner_type)


# ---------------------------------------------------------------------------
# Internals — small, composable phases.
# ---------------------------------------------------------------------------

def _normalize_name_column(df: pd.DataFrame) -> pd.DataFrame:
    """Tolerate case variants of the ``Name`` column ("name", "NAME", etc.).

    Some malformed extractions store the column as lower-case. The aligner
    expects the canonical capitalised form; this rename keeps downstream
    code unchanged when the casing slipped.
    """
    if "Name" in df.columns:
        return df
    for variant in ("name", "NAME", "Name "):
        if variant in df.columns:
            return df.rename(columns={variant: "Name"})
    return df


def _prepare(
    baseline_df: pd.DataFrame,
    extraction_df: pd.DataFrame,
    scanner_type: str,
    allow_duplicates: bool,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Annotate both DataFrames with normalized name + composite key.

    The baseline carries ``_baseline_row_id`` = its original positional index
    so downstream consumers can recover the exact row even after dedup.

    If the extraction is malformed (no ``Name`` column at all — typically a
    truncated/empty LLM output saved as a degenerate sheet), return an
    empty extraction frame instead of raising. Callers downstream emit
    zero-pair summaries and the run is reported as "no matches" rather
    than crashing the whole pipeline.
    """
    base = _normalize_name_column(baseline_df).copy()
    ext = _normalize_name_column(extraction_df).copy()

    if "Name" not in ext.columns:
        # Malformed extraction — synthesize an empty frame matching the
        # columns _resolve_matches expects to find.
        ext = pd.DataFrame(columns=list(extraction_df.columns) + ["Name"])
        ext["_Name_norm"] = []
        ext["_composite_key"] = []
    else:
        ext["_Name_norm"] = ext["Name"].map(normalize_name)
        ext["_composite_key"] = ext.apply(lambda r: build_composite_key(r, scanner_type), axis=1)

    base["_Name_norm"] = base["Name"].map(normalize_name)
    base["_composite_key"] = base.apply(lambda r: build_composite_key(r, scanner_type), axis=1)

    if not allow_duplicates:
        deduped = base.drop_duplicates(subset=["_Name_norm"], keep="first")
        deduped["_baseline_row_id"] = deduped.index
        base = deduped
    else:
        base["_baseline_row_id"] = base.index
    return base, ext


def _composite_phase(base: pd.DataFrame, ext: pd.DataFrame) -> Dict[str, str]:
    """For each extraction key, find the best compatible baseline key."""
    base_keys = base["_composite_key"].tolist()
    out: Dict[str, str] = {}
    for ext_key in ext["_composite_key"]:
        candidates = [(bk, key_match_score(ext_key, bk))
                      for bk in base_keys if keys_match(ext_key, bk)]
        if candidates:
            out[ext_key] = max(candidates, key=lambda x: x[1])[0]
    return out


def _exact_phase(base: pd.DataFrame, ext: pd.DataFrame) -> Dict[str, str]:
    """Exact normalized-name matches for extraction names that are 1:1."""
    base_set = set(base["_Name_norm"].tolist())
    return {n: n for n in ext["_Name_norm"] if n in base_set}


def _fuzzy_phase(
    base: pd.DataFrame,
    ext: pd.DataFrame,
    exact_map: Dict[str, str],
    fuzzy_threshold: float,
) -> Dict[str, str]:
    """Fuzzy fallback for extraction names that miss exact match."""
    base_norms = base["_Name_norm"].tolist()
    out: Dict[str, str] = {}
    for n in ext["_Name_norm"]:
        if n in exact_map or not n:
            continue
        match, score = best_fuzzy_match(n, base_norms)
        if match and score >= fuzzy_threshold:
            out[n] = match
    return out


def _resolve_matches(
    base: pd.DataFrame,
    ext: pd.DataFrame,
    composite_map: Dict[str, str],
    exact_map: Dict[str, str],
    fuzzy_map: Dict[str, str],
    scanner_type: str,
) -> AlignmentResult:
    """Walk extraction rows, picking the first matching baseline row per priority.

    Priority is enforced by sorting: rows with a composite match are processed
    first so they cannot be starved by name-only matches.
    """
    # ``drop=False`` keeps the index columns also accessible by name on each
    # row — needed when we read ``chosen["_Name_norm"]`` after a composite
    # lookup or vice-versa.
    base_by_composite = base.set_index("_composite_key", drop=False)
    base_by_name = base.set_index("_Name_norm", drop=False)

    used_rowids: Set[int] = set()
    pairs: List[Tuple[int, int]] = []
    unmatched_ext: List[int] = []
    debug_rows: List[Dict] = []

    rows = sorted(
        ext.iterrows(),
        key=lambda kv: (0 if composite_map.get(kv[1]["_composite_key"]) else 1),
    )

    for ext_idx, row in rows:
        comp_key = row["_composite_key"]
        name_norm = row["_Name_norm"]

        target = composite_map.get(comp_key)
        match_via = "COMPOSITE"
        candidates = base_by_composite.loc[[target]] if target in base_by_composite.index else None

        if candidates is None:
            target_name = exact_map.get(name_norm) or fuzzy_map.get(name_norm)
            if target_name is None:
                unmatched_ext.append(ext_idx)
                debug_rows.append(_debug(ext_idx, row, comp_key, None, 0.0, "UNMATCHED"))
                continue
            candidates = base_by_name.loc[[target_name]] if target_name in base_by_name.index else None
            match_via = "NAME_ONLY"

        if candidates is None or len(candidates) == 0:
            unmatched_ext.append(ext_idx)
            debug_rows.append(_debug(ext_idx, row, comp_key, None, 0.0, "UNMATCHED"))
            continue

        # First unused candidate (greedy). Hungarian would replace this loop.
        chosen: Optional[pd.Series] = None
        for _, cand in candidates.iterrows():
            rid = int(cand["_baseline_row_id"])
            if rid not in used_rowids:
                chosen = cand
                used_rowids.add(rid)
                pairs.append((ext_idx, rid))
                break

        if chosen is None:
            unmatched_ext.append(ext_idx)
            debug_rows.append(_debug(ext_idx, row, comp_key, None, 0.0, "UNMATCHED_EXCESS"))
            continue

        score = fuzz.ratio(name_norm, chosen["_Name_norm"]) / 100.0
        debug_rows.append(_debug(
            ext_idx, row, comp_key, chosen["Name"], score,
            f"MATCHED_{match_via}", baseline_row_id=int(chosen["_baseline_row_id"]),
        ))

    unmatched_baseline = [int(rid) for rid in base["_baseline_row_id"]
                          if int(rid) not in used_rowids]

    return AlignmentResult(
        pairs=pairs,
        unmatched_extraction=unmatched_ext,
        unmatched_baseline=unmatched_baseline,
        debug_rows=debug_rows,
        scanner_type=scanner_type,
    )


def _similarity_matrix(ext: pd.DataFrame, base: pd.DataFrame) -> np.ndarray:
    """Build an N_ext × N_base similarity matrix in [0, 1].

    Score per cell = max(composite-key score, fuzzy name score). The matrix
    is the input to Hungarian — it minimizes ``1 - similarity``.
    """
    ext_keys = ext["_composite_key"].tolist()
    ext_names = ext["_Name_norm"].tolist()
    base_keys = base["_composite_key"].tolist()
    base_names = base["_Name_norm"].tolist()

    sim = np.zeros((len(ext), len(base)))
    for i, (ek, en) in enumerate(zip(ext_keys, ext_names)):
        for j, (bk, bn) in enumerate(zip(base_keys, base_names)):
            comp = key_match_score(ek, bk) if keys_match(ek, bk) else 0.0
            name = (fuzz.ratio(en, bn) / 100.0) if en and bn else 0.0
            sim[i, j] = max(comp, name)
    return sim


def _resolve_hungarian(
    base: pd.DataFrame,
    ext: pd.DataFrame,
    scanner_type: str,
    threshold: float,
) -> AlignmentResult:
    """Optimal global assignment via the Hungarian algorithm.

    Builds a similarity matrix, minimizes ``1 - similarity`` with
    ``linear_sum_assignment``, and accepts only assignments above
    ``threshold``. Unlike greedy, this guarantees the *globally* maximal
    sum of similarities — important when duplicate names create local
    ambiguity that greedy resolves by row order.
    """
    if ext.empty or base.empty:
        return AlignmentResult(
            unmatched_extraction=list(ext.index),
            unmatched_baseline=[int(rid) for rid in base["_baseline_row_id"]],
            scanner_type=scanner_type,
        )

    sim = _similarity_matrix(ext, base)
    cost = 1.0 - sim
    row_ind, col_ind = linear_sum_assignment(cost)

    base_rows = base.reset_index(drop=True)
    pairs: List[Tuple[int, int]] = []
    used_rowids: Set[int] = set()
    matched_ext_idx: Set[int] = set()
    debug_rows: List[Dict] = []

    ext_index = list(ext.index)
    for i, j in zip(row_ind, col_ind):
        ext_idx = ext_index[i]
        ext_row = ext.iloc[i]
        score = float(sim[i, j])
        if score < threshold:
            debug_rows.append(_debug(ext_idx, ext_row, ext_row["_composite_key"],
                                     None, score, "UNMATCHED"))
            continue
        base_row = base_rows.iloc[j]
        rid = int(base_row["_baseline_row_id"])
        pairs.append((ext_idx, rid))
        used_rowids.add(rid)
        matched_ext_idx.add(ext_idx)
        debug_rows.append(_debug(
            ext_idx, ext_row, ext_row["_composite_key"], base_row["Name"],
            score, "MATCHED_HUNGARIAN", baseline_row_id=rid,
        ))

    # Extraction rows not in the Hungarian assignment (when N_ext > N_base).
    for ext_idx, ext_row in ext.iterrows():
        if ext_idx in matched_ext_idx:
            continue
        if any(d["extraction_row_id"] == ext_idx for d in debug_rows):
            continue  # already logged as below-threshold
        debug_rows.append(_debug(ext_idx, ext_row, ext_row["_composite_key"],
                                 None, 0.0, "UNMATCHED"))

    unmatched_ext = [i for i in ext.index if i not in matched_ext_idx]
    unmatched_baseline = [int(rid) for rid in base["_baseline_row_id"]
                          if int(rid) not in used_rowids]

    return AlignmentResult(
        pairs=pairs,
        unmatched_extraction=unmatched_ext,
        unmatched_baseline=unmatched_baseline,
        debug_rows=debug_rows,
        scanner_type=scanner_type,
    )


def _debug(
    ext_idx: int,
    row: pd.Series,
    comp_key: str,
    matched_name: Optional[str],
    score: float,
    status: str,
    baseline_row_id: Optional[int] = None,
) -> Dict:
    return {
        "extraction_row_id": ext_idx,
        "baseline_row_id": baseline_row_id,
        "Extraction_Name": row.get("Name"),
        "Extraction_Name_norm": row.get("_Name_norm"),
        "Composite_Key": comp_key,
        "Baseline_Name_matched": matched_name,
        "match_score": score,
        "Status": status,
    }
