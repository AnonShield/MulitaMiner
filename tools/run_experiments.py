"""Batch experiment runner.

Thin wrapper — the implementation lives in :mod:`mulitaminer.experiments.cli`
(also exposed as the ``mulita-experiments`` entry point). See that module's
docstring for usage.
"""
from mulitaminer.experiments.cli import main

if __name__ == "__main__":
    main()
