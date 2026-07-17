from __future__ import annotations

NAME = "rouge_l"

# Porter stemming folds morphological variants (injections↔injection); this is
# the common convention in ROUGE reporting. Documented as a deliberate choice.
_USE_STEMMER = True

try:
    from rouge_score import rouge_scorer  # type: ignore
    _AVAILABLE = True
except Exception:  # pragma: no cover — environment-dependent
    rouge_scorer = None  # type: ignore
    _AVAILABLE = False

# Process-wide cache — the RougeScorer builds a tokenizer/stemmer on init.
_scorer_cache = None


def _get_scorer():
    """Return a cached ``RougeScorer`` for rougeL, building it on first call."""
    global _scorer_cache
    if _scorer_cache is not None:
        return _scorer_cache
    if not _AVAILABLE:
        return None
    _scorer_cache = rouge_scorer.RougeScorer(["rougeL"], use_stemmer=_USE_STEMMER)
    return _scorer_cache


def rouge_l_score(pred, ref) -> float:
    """ROUGE-L F1 between ``pred`` (extraction) and ``ref`` (baseline).

    Empty inputs, or an unavailable ``rouge-score`` package, return 0.0.
    """
    if not _AVAILABLE:
        return 0.0
    if pred is None or ref is None:
        return 0.0
    p = str(pred).strip()
    r = str(ref).strip()
    if not p or not r:
        return 0.0

    scorer = _get_scorer()
    if scorer is None:
        return 0.0

    try:
        # Library signature is score(target, prediction) — reference first.
        result = scorer.score(r, p)
        return float(result["rougeL"].fmeasure)
    except Exception as exc:  # pragma: no cover
        print(f"Error in ROUGE-L calculation: {exc}")
        return 0.0


# Public registry-friendly entry point.
def score(pred, ref) -> float:
    return rouge_l_score(pred, ref)
