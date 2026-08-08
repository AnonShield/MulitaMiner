"""Check that .env exists and carries a real DeepSeek key, not the template value.

Usage: python claims/check_env.py
Exits 0 when the key looks usable, 1 otherwise.
"""
import pathlib
import re
import sys

PLACEHOLDER = "your-deepseek-api-key"


def main() -> int:
    env = pathlib.Path(".env")
    if not env.is_file():
        print("[CHECK] FAILED: no .env file in the repository root.")
        print("  Copy .env.example to .env and fill in API_KEY_DEEPSEEK.")
        return 1

    text = env.read_text(encoding="utf-8", errors="ignore")
    m = re.search(r"^\s*API_KEY_DEEPSEEK\s*=\s*(.+?)\s*$", text, re.MULTILINE)
    if m is None:
        print("[CHECK] FAILED: .env does not define API_KEY_DEEPSEEK.")
        print('  Add a line like: API_KEY_DEEPSEEK = "sk-..."')
        return 1

    value = m.group(1).strip().strip('"').strip("'")
    if not value or value == PLACEHOLDER:
        print("[CHECK] FAILED: API_KEY_DEEPSEEK still holds the template value.")
        print("  Replace it in .env with the key provided for the evaluation.")
        return 1

    print("[CHECK] .env defines API_KEY_DEEPSEEK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
