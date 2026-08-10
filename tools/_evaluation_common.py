"""Shared helpers for converter validation and LLM evaluation.

Single source of truth for ligature fixes, text normalization, list/ref
parsing, fuzzy name matching, and metric helpers.
"""
import ast
import re

import pandas as pd
from rapidfuzz import fuzz, process


LIGATURE_PATTERNS = [
    (re.compile(r"\bBuer\b"), "Buffer"),
    (re.compile(r"\bOverow\b"), "Overflow"),
    (re.compile(r"\baws\b"), "flaws"),
    (re.compile(r"\bUnxed\b"), "Unfixed"),
    (re.compile(r"\bxed\b"), "fixed"),
    (re.compile(r"\bsuf"), "suff"),
    (re.compile(r"\bdi(?=erent)"), "diff"),
    (re.compile(r"\baected\b"), "affected"),
    (re.compile(r"\bAected\b"), "Affected"),
    (re.compile(r"\bspecied\b"), "specified"),
    (re.compile(r"\bnoty\b"), "notify"),
    (re.compile(r"\bcerticate\b"), "certificate"),
    (re.compile(r"\bClassication\b"), "Classification"),
    (re.compile(r"\bsignicant\b"), "significant"),
    (re.compile(r"\bcong"), "config"),
    (re.compile(r"\bdened\b"), "defined"),
    (re.compile(r"\bVerication\b"), "Verification"),
]

NAME_MATCH_THRESHOLD = 85


def fix_ligatures(text: str) -> str:
    for pat, rep in LIGATURE_PATTERNS:
        text = pat.sub(rep, text)
    return text


def _isna_safe(v) -> bool:
    if isinstance(v, (list, dict, set, tuple)):
        return False
    try:
        return bool(pd.isna(v))
    except (TypeError, ValueError):
        return False


def norm_text(val) -> str:
    if val is None or _isna_safe(val):
        return ""
    if isinstance(val, list):
        val = " ".join(str(v) for v in val)
    s = fix_ligatures(str(val))
    return re.sub(r"\s+", " ", s).strip().lower()


def parse_list(val):
    """Coerce a value into a list of strings.

    Accepts: native list, Python list literal in a string ("['a', 'b']"),
    or newline-separated string ("a\\nb"). NaN/None -> [].
    """
    if val is None or _isna_safe(val):
        return []
    if isinstance(val, list):
        return [str(x) for x in val]
    s = str(val).strip()
    if s.startswith("[") and s.endswith("]"):
        try:
            parsed = ast.literal_eval(s)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except (ValueError, SyntaxError):
            pass
    return [ln.strip() for ln in s.split("\n") if ln.strip()]


def norm_ref(s: str) -> str:
    s = re.sub(
        r"^(cve:|bid:|url:|cert-bund:|dfn-cert:|wid-sec:)\s*",
        "", str(s).strip(), flags=re.IGNORECASE,
    )
    return s.strip().lower()


def to_num(v):
    if isinstance(v, list):
        v = v[0] if v else None
    if v is None or _isna_safe(v):
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def num_eq(a, b, tol: float = 0.0) -> bool:
    na, nb = to_num(a), to_num(b)
    if na is None and nb is None:
        return True
    if na is None or nb is None:
        return False
    return abs(na - nb) <= tol


def set_f1(gold: list, pred: list):
    g = {norm_ref(x) for x in gold if x}
    p = {norm_ref(x) for x in pred if x}
    if not g and not p:
        return 1.0, 1.0, 1.0
    inter = len(g & p)
    prec = inter / len(p) if p else 0.0
    rec = inter / len(g) if g else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def rouge_l(gold: str, pred: str, scorer) -> float:
    if not gold and not pred:
        return 1.0
    if not gold or not pred:
        return 0.0
    return scorer.score(gold, pred)["rougeL"].fmeasure


def match_pairs(json_items, xlsx_df, threshold: int = NAME_MATCH_THRESHOLD):
    """Greedy fuzzy match of JSON items to XLSX rows by Name.

    Returns (pairs, unmatched_json_idx, unmatched_xlsx_idx) where
    pairs is a list of (j_idx, x_idx, score).
    """
    j_norms = [norm_text(v.get("Name")) for v in json_items]
    x_norms = xlsx_df["Name"].fillna("").astype(str).map(norm_text).tolist()

    pairs = []
    used = set()
    for j_idx, j_name in enumerate(j_norms):
        if not j_name:
            continue
        candidates = [(i, n) for i, n in enumerate(x_norms) if i not in used and n]
        if not candidates:
            break
        names_only = [n for _, n in candidates]
        best = process.extractOne(j_name, names_only, scorer=fuzz.ratio)
        if best and best[1] >= threshold:
            x_idx = candidates[best[2]][0]
            used.add(x_idx)
            pairs.append((j_idx, x_idx, best[1]))
    matched_j = {p[0] for p in pairs}
    matched_x = {p[1] for p in pairs}
    unmatched_j = [i for i in range(len(json_items)) if i not in matched_j]
    unmatched_x = [i for i in range(len(xlsx_df)) if i not in matched_x]
    return pairs, unmatched_j, unmatched_x
