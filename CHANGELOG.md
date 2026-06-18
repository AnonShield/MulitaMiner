# Changelog

All notable changes to MulitaMiner are documented here.

## [Unreleased] — Structural refactor

A large refactor turned the codebase into an installable package with a clean,
intent-revealing layout. **These are breaking changes** for anyone importing the
internals or scripting against the old paths — see the migration notes below.

### Breaking changes

- **Installable package.** Code moved from `src/` (with `sys.path` hacks) to the
  importable package `src/mulitaminer/`. Install with `pip install -e .`.
  Imports change `from src.X …` → `from mulitaminer.X …`.
- **Subpackages renamed** (clearer names):
  `model_management/` → `llm/`, `scanner_strategies/` → `scanners/`,
  `converters/` → `writers/`, `configs/templates/` → `configs/prompts/`.
  The old `utils/` catch-all was dissolved into `chunking/`, `validators/`,
  `reporting/`, `readers/`, and `pipeline/`.
- **`main.py` is now a 12-line wrapper** around `mulitaminer.cli:main`; the
  orchestration / persistence / metrics-dispatch logic lives in
  `mulitaminer/pipeline/`.
- **Inputs.** Baselines moved to `resources/baselines/<scanner>/`. Input is read
  through `mulitaminer/readers/` (`get_reader()` dispatches by file extension —
  PDF today, other formats are additive via `@register`).
- **Outputs.** Every run artifact now lives under one gitignored `outputs/` tree
  (`runs/`, `tokens/`, `visual_layouts/`, `debug/`, `plots/`, `checkpoints/`,
  `tmp/`), replacing `results_runs/`, `results_tokens/`, `plot_runs/`, root-level
  `temp_blocks_*`, and `src/visual_layouts/`. A relative `--output-dir` is nested
  under `outputs/` automatically.
- **Dependencies.** `requirements.txt` was removed — `pyproject.toml` is the
  single source (install via `pip install -e .`; `uv.lock` is the deterministic
  lock). Added `pydantic` and declared `scipy`.
- **Metrics CLI.** The standalone `metrics/bert/…` and `metrics/rouge/…` scripts
  were removed in favor of the unified `metrics/pipelines/compare_extractions.py`
  (selected via `--scorer`). Run metrics inline (`main.py --metrics …`), over a
  results tree (`tools/run_metrics.py --root … --methods …`), or build charts with
  `python -m metrics.plot.metrics --root …`.
- **Metric renamed `entity` → `field_f1`** (it computes per-field F1, not NER
  entities). Use `--metrics field_f1`; outputs are `field_f1_metrics_*.xlsx` with
  aggregation source `field_f1`; the script moved to `metrics/field_f1/field_f1.py`.

### Added

- **pytest test suite** (`tests/`) with a `MockLLM` fixture; `dev` extra
  (`pip install -e ".[dev]"`) brings pytest/ruff/mypy, configured in `pyproject.toml`.
- **Config validation** — `load_llm` / `load_profile` validate against pydantic
  schemas (`configs/schemas.py`) and fail fast with a clear message on malformed
  JSON (they still return plain dicts).
- **`.env.example`** template for the API-key environment variables.
- **`configs/constants.py`** — single source of truth for output locations and
  chunking tunables.

### Changed

- Retired the V1/V2 schema scaffolding — the schema path is now V3-only.
- `run_experiments` per-run subprocess runs with `PYTHONUNBUFFERED=1`; the `debug`
  flag is preserved across `--checkpoint-file` resumes; checkpoints write atomically.
- `LLM_PRICES` entries carry `_last_updated` + `_source` for auditability.

### Fixed

- Versioning chart's Schema KPI and the per-field-failure card (were reading
  keys/blocks no longer emitted).
