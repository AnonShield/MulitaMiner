"""Entrypoint do pacote `plot`.

Suporta execução via `python -m plot` (recomendado) e também execução direta
do arquivo `plot/__main__.py` (por compatibilidade). Quando executado
diretamente, ajusta temporariamente `sys.path` para garantir que o pacote
`plot` seja importável.
"""
import sys
from pathlib import Path

def _import_and_run():
    try:
        # Import normally (when package is executed with -m)
        from plot.cli import cli_entry
    except Exception:
        # If it fails (direct file execution), add repo root to sys.path
        repo_root = Path(__file__).parents[1]
        if str(repo_root) not in sys.path:
            sys.path.insert(0, str(repo_root))
        from plot.cli import cli_entry
    cli_entry()


if __name__ == '__main__':
    _import_and_run()
