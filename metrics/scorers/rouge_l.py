"""ROUGE-L F1 scorer (single owner of the implementation).

Computes the longest-common-subsequence F1 over whitespace-tokenized
text. ROUGE-L is a recall-flavored complement to BERTScore — sensitive
to surface form, lenient on word order. See metrics.md §3.4.
"""
from __future__ import annotations

NAME = "rouge_l"


def _lcs_length(x: list[str], y: list[str]) -> int:
    """Length of the longest common subsequence (classic DP)."""
    m, n = len(x), len(y)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m):
        for j in range(n):
            if x[i] == y[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i][j + 1], dp[i + 1][j])
    return dp[m][n]


def rouge_l_score(pred, ref) -> float:
    """ROUGE-L F1 between ``pred`` and ``ref``."""
    pt = str(pred).split()
    rt = str(ref).split()
    if not pt or not rt:
        return 0.0
    lcs = _lcs_length(pt, rt)
    if lcs == 0:
        return 0.0
    prec = lcs / len(pt)
    rec = lcs / len(rt)
    return (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0


# Public registry-friendly entry point.
def score(pred, ref) -> float:
    return rouge_l_score(pred, ref)
