"""SQuAD-style token-level F1 over whitespace+punctuation tokenized strings.

Robust to word reordering and partial overlap; standard in extractive QA.
Complements ROUGE-L (longest common subsequence) and BERTScore (semantic).
See metrics.md §3.4.
"""
from __future__ import annotations

import re
import string
from collections import Counter

NAME = "token_f1"

_SPLIT = re.compile(rf"[\s{re.escape(string.punctuation)}]+")


def _tokens(text) -> list[str]:
    """Lowercase, split on whitespace + punctuation, drop empty tokens.

    Lists are joined with spaces so list-typed fields (description, solution…)
    can be compared without callers having to flatten them.
    """
    if text is None:
        return []
    if isinstance(text, list):
        text = " ".join(str(x) for x in text)
    return [t for t in _SPLIT.split(str(text).lower().strip()) if t]


def score(pred, ref) -> float:
    p = _tokens(pred)
    r = _tokens(ref)
    if not p and not r:
        # Both empty: vacuous match. Aggregator can override via presence().
        return 1.0
    if not p or not r:
        return 0.0
    common = sum((Counter(p) & Counter(r)).values())
    if common == 0:
        return 0.0
    prec = common / len(p)
    rec = common / len(r)
    return 2 * prec * rec / (prec + rec)
