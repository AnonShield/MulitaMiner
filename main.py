"""PDF Vulnerability Extractor — entry point.

Thin wrapper around :mod:`mulitaminer.cli`. All logic lives in the installed
package (``src/mulitaminer/``); this file just lets you run ``python main.py``.

Usage:
    python main.py --input <pdf_path> [--llm <model>] [--convert <format>] [--scanner <name>]
"""
from mulitaminer.cli import main

if __name__ == "__main__":
    main()
