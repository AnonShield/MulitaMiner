"""Pure scoring functions used across metric pipelines.

Each scorer module exposes:

    NAME: str                       — identifier used in CLI / config
    score(pred, ref) -> float       — value in [0, 1]; higher is better

Scorers are stateless (with the exception of cached embedding models inside
BERTScore) and side-effect-free. Orchestrators in ``metrics/pipelines/``
handle I/O, alignment and aggregation.

Why this layout (metrics.md §"Organização Proposta"):
    Decouples *how* a metric is computed from *what data* it runs on.
    Adding a metric = create a module here and register it. No pipeline
    changes required.
"""
from __future__ import annotations

from typing import Callable

from . import bertscore, exact_match, presence, rouge_l, set_f1, token_f1

# Single source of truth — pipelines and CLIs resolve scorers through this map.
SCORERS: dict[str, Callable] = {
    bertscore.NAME: bertscore.score,
    rouge_l.NAME: rouge_l.score,
    token_f1.NAME: token_f1.score,
    presence.NAME: presence.score,
    exact_match.NAME: exact_match.score,
    set_f1.NAME: set_f1.score,
}


def get_scorer(name: str) -> Callable:
    """Return a scorer callable by name. Raises ``KeyError`` if unknown."""
    return SCORERS[name]


def list_scorers() -> list[str]:
    """List registered scorer names, sorted."""
    return sorted(SCORERS)
