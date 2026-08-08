"""Prompt loading utility."""

import os


def load_prompt(prompt):
    """Read prompt from a path (direct or project-relative); else return as-is."""
    if os.path.isfile(prompt):
        with open(prompt, "r", encoding="utf-8") as f:
            return f.read()
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    rel_path = os.path.join(project_root, prompt)
    
    if os.path.isfile(rel_path):
        with open(rel_path, "r", encoding="utf-8") as f:
            return f.read()
    
    return prompt
