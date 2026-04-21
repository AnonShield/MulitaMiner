"""One-shot: normalize `references` column in OpenVAS baseline xlsx files.

Target format: Python list repr of strings (e.g. "['URL:foo', 'CVE-123']").
Same as bBWA already uses and what pandas produces from LLM list output.

Writes .bak alongside each file before overwriting.
"""
import ast
import re
import shutil
import sys
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[1] / 'baselines' / 'openvas'
FILES = [
    BASE / 'OpenVAS_JuiceShop.xlsx',
    BASE / 'OpenVAS_bBWA.xlsx',
    BASE / 'openvas_artifactory-oss_5.11.0.xlsx',
]

LABEL_RE = re.compile(
    r'(?<=\S)\s+(?=(?:cve|url|cert-bund|dfn-cert|cisa|scconfig|scid|score|vuldb|bid|owasp|cwe|other):)',
    re.IGNORECASE,
)
BARE_LABEL_RE = re.compile(r'[A-Za-z][\w-]*:\s*')


def _clean(s: str) -> str:
    # Strip wrapping quotes/brackets/trailing commas that survive failed parses
    s = s.strip()
    for _ in range(3):
        before = s
        s = s.strip().strip("'").strip('"').lstrip('[').rstrip(']').rstrip(',').strip()
        if s == before:
            break
    return s


def split_item(s: str) -> list[str]:
    out = []
    for chunk in s.split('\n'):
        chunk = _clean(chunk)
        if not chunk:
            continue
        for sub in LABEL_RE.split(chunk):
            sub = _clean(sub)
            if sub and not BARE_LABEL_RE.fullmatch(sub):
                out.append(sub)
    return out


def parse_juiceshop(v) -> list[str]:
    if pd.isna(v) or not str(v).strip():
        return []
    s = str(v).strip()
    parts = []
    for p in s.split(','):
        parts.extend(split_item(p))
    return parts


def parse_bbwa(v) -> list[str]:
    if pd.isna(v) or not str(v).strip():
        return []
    s = str(v).strip()
    # Pre-escape real newlines so ast.literal_eval can parse list literals
    # that contain raw \n characters inside their string items.
    escaped = s.replace('\n', '\\n').replace('\r', '\\r')
    items: list[str] = []
    try:
        parsed = ast.literal_eval(escaped)
        if isinstance(parsed, list):
            for x in parsed:
                items.extend(split_item(str(x)))
            return items
    except (ValueError, SyntaxError):
        pass
    return split_item(s)


def parse_artifactory(v) -> list[str]:
    if pd.isna(v) or not str(v).strip():
        return []
    return split_item(str(v))


PARSERS = {
    'OpenVAS_JuiceShop.xlsx': parse_juiceshop,
    'OpenVAS_bBWA.xlsx': parse_bbwa,
    'openvas_artifactory-oss_5.11.0.xlsx': parse_artifactory,
}


def main(dry_run: bool = False) -> None:
    for path in FILES:
        name = path.name
        parser = PARSERS[name]
        df = pd.read_excel(path)
        col = next((c for c in df.columns if c.lower() == 'references'), None)
        if col is None:
            print(f'[SKIP] {name}: no references column')
            continue
        new_values = [str(parser(v)) for v in df[col]]
        n_changed = sum(1 for old, new in zip(df[col], new_values) if str(old) != new)
        print(f'[{name}] {n_changed}/{len(df)} rows changed')
        for i, (old, new) in enumerate(zip(df[col], new_values)):
            if str(old) != new and i < 3:
                print(f'  row {i}:')
                print(f'    OLD: {str(old)[:160]!r}')
                print(f'    NEW: {new[:160]!r}')
        if not dry_run:
            bak = path.with_suffix(path.suffix + '.bak')
            if not bak.exists():
                shutil.copy(path, bak)
                print(f'  backup: {bak.name}')
            df[col] = new_values
            df.to_excel(path, index=False)
            print(f'  wrote: {path.name}')


if __name__ == '__main__':
    main(dry_run='--dry' in sys.argv)
