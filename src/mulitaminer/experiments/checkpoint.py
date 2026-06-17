"""Checkpoint IO for run_experiments resume support."""
import json
import os

from mulitaminer.configs.constants import CHECKPOINTS_DIR


def make_checkpoint_path(ts: str) -> str:
    """Path for a fresh checkpoint under outputs/checkpoints/."""
    os.makedirs(CHECKPOINTS_DIR, exist_ok=True)
    return str(CHECKPOINTS_DIR / f"run_checkpoints_{ts}.json")


def save_checkpoint(path: str, data: dict) -> None:
    """Write the checkpoint atomically (temp file + os.replace) so a crash
    mid-write can't corrupt the resume file."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
