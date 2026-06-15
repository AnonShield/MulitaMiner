"""
Prompt loading utility.

Handles loading prompt templates from files or returning them as strings.
"""

import os
from pathlib import Path

# Templates ship inside the package (src/mulitaminer/configs/templates/), so
# resolve stored template paths relative to the package root, never the CWD.
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent  # src/mulitaminer/


def load_prompt(prompt):
    """
    Load a prompt template from a file or return as string.

    Tries multiple path resolution strategies:
    1. Direct file path
    2. Relative to the package root (e.g. "configs/templates/openvas_prompt.txt")
    3. Return as string if not a file

    Args:
        prompt: File path or prompt string

    Returns:
        str: Prompt content or original string
    """
    if os.path.isfile(prompt):
        with open(prompt, "r", encoding="utf-8") as f:
            return f.read()

    # Stored template paths are package-relative. Tolerate the legacy "src/"
    # prefix that predates the move into src/mulitaminer/.
    rel = prompt[4:] if prompt.startswith("src/") else prompt
    candidate = _PACKAGE_ROOT / rel
    if candidate.is_file():
        with open(candidate, "r", encoding="utf-8") as f:
            return f.read()

    return prompt
