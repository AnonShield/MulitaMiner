"""Discover run artifacts on disk.

Walks a result root (e.g. ``results_runs/`` or ``results_runs_V2/``) and
returns one :class:`RunArtifacts` per run directory. Knows nothing about
metrics — its only job is layout traversal.

Expected layout::

    <root>/<target>/<model>/<runN>/
        <target>_<model>_<runN>.json                (raw LLM output)
        <target>_<model>_<runN>.xlsx                (converted)
        bert_comparison_*.xlsx                      (after running bert)
        rouge_comparison_*.xlsx                     (after running rouge)
        entity_metrics_*.xlsx                       (after running entity)
        schema_report_*.json                        (after running schema)
        severity_confusion_*.xlsx                   (after running severity)
        coverage_*.xlsx                             (after running coverage)

Version is inferred from the root path: a path containing ``_V2`` segment
maps to ``"v2"``; everything else is ``"v3"``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Per-run filename patterns. Glob, not regex, for clarity.
_ARTIFACT_GLOBS: dict[str, str] = {
    "raw_json": "*_run*.json",
    "extraction_xlsx": "*_run*.xlsx",
    "bert": "bert_comparison_*.xlsx",
    "rouge": "rouge_comparison_*.xlsx",
    "token_f1": "token_f1_comparison_*.xlsx",
    "entity": "entity_metrics_*.xlsx",
    "schema": "schema_report_*.json",
    "severity": "severity_confusion_*.xlsx",
    "coverage": "coverage_*.xlsx",
}

_RUN_DIR_RE = re.compile(r"^run\d+$", re.IGNORECASE)


@dataclass
class RunArtifacts:
    """All artifacts located inside a single ``runN/`` directory."""
    version: str          # root folder basename (e.g. "results_runs", "results_runs_v2")
    target: str           # e.g. "OpenVAS_JuiceShop"
    model: str            # e.g. "llama4"
    run: str              # e.g. "run1"
    run_dir: Path
    files: dict[str, list[Path]] = field(default_factory=dict)

    def first(self, kind: str) -> Path | None:
        """Return the first artifact of ``kind`` (alphabetically), or None."""
        items = self.files.get(kind, [])
        return items[0] if items else None

    def has(self, kind: str) -> bool:
        return bool(self.files.get(kind))


def _infer_version(root: Path) -> str:
    """Use the root directory's basename as the version label.

    Lets multi-root sweeps (cross-version paper experiments) and single-root
    runs share the same column without hardcoded special cases — the user
    sees the actual folder name, e.g. ``results_runs`` or ``results_runs_v2``.
    """
    return root.name or str(root)


def _collect_files(run_dir: Path) -> dict[str, list[Path]]:
    """Apply the artifact globs to one run directory.

    The ``raw_json`` and ``extraction_xlsx`` patterns can collide with
    metric outputs (which also live in the same dir), so we exclude any
    file that matches a more-specific pattern.
    """
    found: dict[str, list[Path]] = {kind: [] for kind in _ARTIFACT_GLOBS}
    for kind, pattern in _ARTIFACT_GLOBS.items():
        found[kind] = sorted(run_dir.glob(pattern))

    metric_files = (
        set(found["bert"]) | set(found["rouge"]) | set(found["entity"])
        | set(found["schema"]) | set(found["severity"]) | set(found["coverage"])
    )
    found["raw_json"] = [p for p in found["raw_json"] if p not in metric_files]
    found["extraction_xlsx"] = [p for p in found["extraction_xlsx"] if p not in metric_files]
    return found


def discover_runs(root: Path) -> list[RunArtifacts]:
    """Walk ``root`` and return one :class:`RunArtifacts` per run directory.

    Silently skips directories that do not match the expected layout. The
    caller decides how to handle missing artifacts (e.g. a run that has
    bert but no rouge yet).
    """
    if not root.exists():
        return []

    version = _infer_version(root)
    runs: list[RunArtifacts] = []

    for target_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for model_dir in sorted(p for p in target_dir.iterdir() if p.is_dir()):
            for run_dir in sorted(p for p in model_dir.iterdir() if p.is_dir()):
                if not _RUN_DIR_RE.match(run_dir.name):
                    continue
                runs.append(RunArtifacts(
                    version=version,
                    target=target_dir.name,
                    model=model_dir.name,
                    run=run_dir.name,
                    run_dir=run_dir,
                    files=_collect_files(run_dir),
                ))
    return runs
