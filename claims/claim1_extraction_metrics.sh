#!/usr/bin/env bash
# Claim 1: structured extraction with the V3 pipeline (DeepSeek, JuiceShop report)
# followed by the full quantitative metric battery against the curated baseline.
set -e
cd "$(dirname "$0")/.."
PY="$(command -v python3 || command -v python)"

if [ ! -f .env ] || ! grep -q "API_KEY_DEEPSEEK" .env; then
    echo "ERROR: copy .env.example to .env and fill in API_KEY_DEEPSEEK." >&2
    exit 1
fi

OUT=claims/out/results_runs_v3/OpenVAS_JuiceShop/deepseek/run1
mkdir -p "$OUT"

echo "[1/3] Extracting with the V3 pipeline (DeepSeek) ..."
"$PY" main.py --input baselines/openvas/OpenVAS_JuiceShop.pdf \
    --llm deepseek --scanner openvas --allow-duplicates \
    --output-file OpenVAS_JuiceShop_deepseek_run1 --output-dir "$OUT"

echo
echo "[2/3] Extraction summary ..."
"$PY" tools/summarize_vulnerabilities.py --input "$OUT/OpenVAS_JuiceShop_deepseek_run1.json"

echo
echo "[3/3] Running the metric battery against the curated baseline ..."
"$PY" tools/run_metrics.py --root claims/out/results_runs_v3 --methods all --no-aggregate --force

echo
echo "=== Metric summary (V3, DeepSeek, JuiceShop) ==="
"$PY" claims/summarize_versions.py claims/out/results_runs_v3
