#!/usr/bin/env bash
# Claim 2: pipeline versioning drives extraction quality (V1 -> V2 -> V3).
# Extracts the same report with V1 and V2 (shipped as zips in versions/),
# then evaluates all three versions with the V3 metric battery.
# If the V3 run from Claim 1 is missing, Claim 1 is executed first.
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="$(command -v python3 || command -v python)"

if [ ! -f .env ] || ! grep -q "API_KEY_DEEPSEEK" .env; then
    echo "ERROR: copy .env.example to .env and fill in API_KEY_DEEPSEEK." >&2
    exit 1
fi

if ! ls claims/out/results_runs_v3/OpenVAS_JuiceShop/deepseek/run1/OpenVAS_JuiceShop_deepseek_run1*.json >/dev/null 2>&1; then
    echo "[0/5] V3 extraction not found, running Claim 1 first ..."
    bash claims/claim1_extraction_metrics.sh
fi

PDF="$ROOT/baselines/openvas/OpenVAS_JuiceShop.pdf"
V1_DIR="$ROOT/claims/out/versions/mulitaminer-v1"
V2_DIR="$ROOT/claims/out/versions/mulitaminer-v2"
VENV="$ROOT/claims/out/versions/venv-legacy"
V1_RUN="$ROOT/claims/out/results_runs_v1/OpenVAS_JuiceShop/deepseek/run1"
V2_RUN="$ROOT/claims/out/results_runs_v2/OpenVAS_JuiceShop/deepseek/run1"

echo "[1/5] Unpacking V1 and V2 from versions/ ..."
mkdir -p claims/out/versions
[ -d "$V1_DIR" ] || "$PY" -m zipfile -e versions/mulitaminer-v1.zip claims/out/versions/
[ -d "$V2_DIR" ] || "$PY" -m zipfile -e versions/mulitaminer-v2.zip claims/out/versions/

echo "[2/5] Preparing legacy virtualenv (V1/V2 extraction dependencies) ..."
if [ ! -f "$VENV/bin/python" ] && [ ! -f "$VENV/Scripts/python.exe" ]; then
    "$PY" -m venv "$VENV"
fi
PY_LEGACY="$VENV/bin/python"
[ -f "$PY_LEGACY" ] || PY_LEGACY="$VENV/Scripts/python.exe"
"$PY_LEGACY" -m pip install --quiet "langchain>=0.1.0,<0.3.0" "langchain-openai>=0.1.0,<0.2.0" \
    "langchain-core>=0.1.0,<0.2.0" "pdfplumber>=0.10.0,<0.12.0" "tqdm>=4.0.0,<5.0.0" \
    "tiktoken>=0.7.0" "python-dotenv>=0.21.0" "deepmerge>=1.1.0,<2.0.0" \
    "pandas>=1.3.0,<3.0.0" "openpyxl>=3.0.0,<4.0.0"

echo "[3/5] Extracting with V1 (DeepSeek) ..."
mkdir -p "$V1_RUN"
(cd "$V1_DIR" && "$PY_LEGACY" main.py "$PDF" --scanner openvas --LLM deepseek \
    --allow-duplicates --output "$V1_RUN/OpenVAS_JuiceShop_deepseek_run1.json")

echo "[4/5] Extracting with V2 (DeepSeek) ..."
mkdir -p "$V2_RUN"
(cd "$V2_DIR" && "$PY_LEGACY" main.py --input "$PDF" --llm deepseek --scanner openvas \
    --allow-duplicates --output-file OpenVAS_JuiceShop_deepseek_run1 --output-dir "$V2_RUN")

echo "[5/5] Evaluating V1, V2 and V3 outputs with the V3 metric battery ..."
"$PY" tools/run_metrics.py \
    --root claims/out/results_runs_v1 claims/out/results_runs_v2 claims/out/results_runs_v3 \
    --methods coverage severity --no-aggregate

echo
echo "=== Cross-version summary (DeepSeek, JuiceShop) ==="
"$PY" claims/summarize_versions.py \
    claims/out/results_runs_v1 claims/out/results_runs_v2 claims/out/results_runs_v3