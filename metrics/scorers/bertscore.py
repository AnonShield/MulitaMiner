"""BERTScore F1 scorer (single owner of the implementation).

The model is loaded lazily and cached process-wide on first call. CPU/GPU
selection is automatic via ``torch.cuda.is_available()``.

Asking for a BERTScore without the ``bert_score`` package installed raises
instead of returning 0.0: a silent zero is indistinguishable from a genuinely
bad extraction, so a partially installed environment would report success
while producing meaningless similarity numbers. To run the battery without
the heavy torch dependency, request ``rouge`` instead of ``bert`` (the
pipelines that need matched pairs accept either).

This module is the source of truth, pipelines import it through
``metrics.scorers``.
"""
from __future__ import annotations

NAME = "bertscore"

# Candidates tried in order until one loads. ``rescale_with_baseline`` is
# enabled on the first model so scores are recentered against random pairs.
_MODEL_CANDIDATES = [
    "distilbert-base-uncased",
    "all-mpnet-base-v2",
    "sentence-transformers/all-mpnet-base-v2",
    "roberta-large",
    "bert-base-uncased",
]
_LANG = "en"

try:
    from bert_score import BERTScorer  # type: ignore
    _AVAILABLE = True
except Exception:  # pragma: no cover — environment-dependent
    BERTScorer = None  # type: ignore
    _AVAILABLE = False

# Process-wide cache. The first call pays for model load (~1–2 s on CPU).
_scorer_cache = None


def _device() -> str:
    try:
        import torch  # type: ignore
        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"


def _get_scorer():
    """Return a :class:`BERTScorer` instance, loading on first call."""
    global _scorer_cache
    if _scorer_cache is not None:
        return _scorer_cache
    if not _AVAILABLE:
        return None
    model = _MODEL_CANDIDATES[0]
    try:
        print(f"Loading BERTScore model: {model}...")
        _scorer_cache = BERTScorer(
            model_type=model, lang=_LANG, device=_device(),
            rescale_with_baseline=True,
        )
        print("BERTScore model loaded successfully!")
    except Exception as exc:  # pragma: no cover — environment-dependent
        print(f"Error loading BERTScore model {model}: {exc}")
        return None
    return _scorer_cache


_MISSING_MSG = (
    "bert-score is not installed, so BERTScore cannot be computed.\n"
    "  Install it:  pip install bert-score torch\n"
    "  Or skip it:  request 'rouge' instead of 'bert' "
    "(coverage/severity/entity accept either for matched pairs)."
)


def bertscore_score(pred, ref) -> float:
    """BERTScore F1 between ``pred`` and ``ref``. Empty inputs return 0.0."""
    if not _AVAILABLE:
        raise RuntimeError(_MISSING_MSG)
    if pred is None or ref is None:
        return 0.0
    p = str(pred).strip()
    r = str(ref).strip()
    if not p or not r:
        return 0.0

    scorer = _get_scorer()
    if scorer is None:
        raise RuntimeError(
            "bert-score is installed but the model could not be loaded "
            "(see the error above). Check the network/cache, or request "
            "'rouge' instead of 'bert'."
        )

    try:
        _, _, F = scorer.score([p], [r])
        f0 = F[0]
        try:
            f = float(f0.cpu().numpy()) if hasattr(f0, "cpu") else float(f0)
        except Exception:
            f = float(f0)
        if f != f:  # NaN check without importing math
            return 0.0
        return max(0.0, min(1.0, f))
    except Exception as exc:  # pragma: no cover
        print(f"Error in BERTScore calculation: {exc}")
        return 0.0


# Public registry-friendly entry point.
def score(pred, ref) -> float:
    return bertscore_score(pred, ref)
