#!/usr/bin/env python3
"""Contagem reproduzível das linhas de código do TMM.

Critério (o mesmo citado no artigo): uma linha conta como código se contém
ao menos um token real de Python. Ficam de fora linhas em branco,
comentários e docstrings (module-, class- e function-level, além de
strings soltas em nível de expressão). Implementado apenas com a stdlib
(tokenize + ast), sem dependências externas.

Uso:
    python3 tools/count_loc.py [raiz-do-repo]

Sem argumento, usa o diretório pai de tools/.
"""
import ast
import io
import sys
import tokenize
from pathlib import Path

_SKIP_TOKENS = frozenset({
    tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
    tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER,
})


def loc_of(path: Path) -> int:
    src = path.read_text(encoding='utf-8', errors='replace')

    try:
        tree = ast.parse(src)
    except SyntaxError:
        # Arquivo que não parseia: cai para não-vazias e não-comentário.
        return sum(1 for line in src.splitlines()
                   if line.strip() and not line.strip().startswith('#'))

    # Linhas ocupadas por docstrings/strings soltas (statements que são
    # apenas uma constante string).
    doc_lines: set[int] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            doc_lines.update(range(node.lineno, node.end_lineno + 1))

    code_lines: set[int] = set()
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in _SKIP_TOKENS:
            continue
        code_lines.update(range(tok.start[0], tok.end[0] + 1))

    return len(code_lines - doc_lines)


def count(paths) -> int:
    return sum(loc_of(p) for p in paths)


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    core = [root / 'main.py'] + sorted((root / 'src').rglob('*.py'))
    metrics = sorted((root / 'metrics').rglob('*.py'))
    tools = sorted((root / 'tools').rglob('*.py'))

    c, m, t = count(core), count(metrics), count(tools)
    print(f'nucleo (main.py + src/): {c}')
    print(f'metrics/:                {m}')
    print(f'tools/:                  {t}')
    print(f'total:                   {c + m + t}')


if __name__ == '__main__':
    main()
