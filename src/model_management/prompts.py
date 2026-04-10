"""
Prompt loading utility.

Handles loading prompt templates from files or returning them as strings.
"""

import os


def load_prompt(prompt):
    """
    Load a prompt template from a file or return as string.
    
    Tries multiple path resolution strategies:
    1. Direct file path
    2. Relative to project root
    3. Return as string if not a file
    
    Args:
        prompt: File path or prompt string
    
    Returns:
        str: Prompt content or original string
    """
    if os.path.isfile(prompt):
        with open(prompt, "r", encoding="utf-8") as f:
            return f.read()
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    rel_path = os.path.join(project_root, prompt)
    
    if os.path.isfile(rel_path):
        with open(rel_path, "r", encoding="utf-8") as f:
            return f.read()
    
    return prompt
