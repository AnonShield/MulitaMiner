"""Single source of truth for output locations and tunable constants.

All run artifacts live under one gitignored ``outputs/`` tree, resolved
relative to the current working directory (the project root, by convention —
same as the legacy ``results_runs/``/``results_tokens/`` defaults this replaces).

Layout::

    outputs/
    ├── runs/             # experiment results (run_experiments --output-dir)
    ├── tokens/           # per-run token/cost JSONs
    ├── visual_layouts/   # PDF visual-layout dumps
    ├── debug/            # raw LLM response debug logs
    ├── plots/            # generated charts / HTML reports
    ├── checkpoints/      # run_experiments resume checkpoints
    └── tmp/              # transient scratch (e.g. per-block temp files)

Runs worth keeping (e.g. a paper dataset) graduate out of ``outputs/`` into a
named, tracked directory of their own.
"""
from pathlib import Path

OUTPUTS_DIR = Path("outputs")

RUNS_DIR = OUTPUTS_DIR / "runs"
TOKENS_DIR = OUTPUTS_DIR / "tokens"
VISUAL_LAYOUTS_DIR = OUTPUTS_DIR / "visual_layouts"
DEBUG_DIR = OUTPUTS_DIR / "debug"
PLOTS_DIR = OUTPUTS_DIR / "plots"
CHECKPOINTS_DIR = OUTPUTS_DIR / "checkpoints"
TMP_DIR = OUTPUTS_DIR / "tmp"


# ---------------------------------------------------------------------------
# Chunking — char-budget tuning for splitting a block into LLM-sized chunks.
# ---------------------------------------------------------------------------
# Fraction of the theoretical char budget actually used, leaving headroom for
# the prompt template + tokenizer estimation error. A per-LLM override can be
# read from the LLM JSON (``chunk_chars_safety_margin``) defaulting to this.
CHUNK_SAFETY_MARGIN_DEFAULT = 0.85
# Absolute floor for the char ceiling, and the token multiplier above it:
# ceiling = max(CHUNK_CHAR_CEILING_MIN, chunk_size_tokens * CHUNK_CHAR_CEILING_TOKEN_MULT)
CHUNK_CHAR_CEILING_MIN = 30_000
CHUNK_CHAR_CEILING_TOKEN_MULT = 2
