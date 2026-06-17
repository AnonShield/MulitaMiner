"""Fatal-API-error detection.

The chunk-level try/except swallows everything by design (parse failures,
validation failures, transient JSON garbage) and returns []. That semantic is
fine for code bugs, but DISASTROUS for billing/auth/quota errors: the run
finishes with 0 vulnerabilities and exit code 0, which run_experiments then
marks as "ok". ``_is_fatal_api_error`` lets callers re-raise those so the
process exits != 0 and the orchestrator records the run as failed.
"""

# Substrings (case-insensitive) that mark an exception as a fatal API condition.
_FATAL_API_ERROR_HINTS = (
    "quota",
    "insufficient_quota",
    "rate limit",
    "ratelimit",
    "429",
    "401",
    "403",
    "authentication",
    "invalid_api_key",
    "incorrect api key",
    "permission denied",
    "you exceeded your current quota",
)


def _is_fatal_api_error(exc: BaseException) -> bool:
    """True if ``exc`` looks like a billing / auth / quota error from any
    LLM provider. Pattern-matches the exception type name and message —
    works across openai, anthropic, langchain wrappers, etc., without
    importing each SDK.
    """
    type_name = type(exc).__name__.lower()
    if any(tag in type_name for tag in ("ratelimit", "quota", "authentication", "permission")):
        return True
    msg = str(exc).lower()
    return any(hint in msg for hint in _FATAL_API_ERROR_HINTS)
