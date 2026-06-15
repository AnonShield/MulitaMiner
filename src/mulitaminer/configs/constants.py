"""Single source of truth for output locations.

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
