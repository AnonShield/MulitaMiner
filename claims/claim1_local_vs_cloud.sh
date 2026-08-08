#!/usr/bin/env bash
# Claim 1: a local SLM matches the cloud reference on structured extraction.
# Runs the same pipeline, same prompts and same baseline with both models,
# then scores them with the identical metric battery.
set -e
cd "$(dirname "$0")/.."
PY="$(command -v python3 || command -v python)"

# Models compared, in table order.
CLOUD_MODEL=deepseek
LOCAL_MODELS="llama31_local"

BASELINE=OpenVAS_JuiceShop
PDF="baselines/openvas/${BASELINE}.pdf"
ROOT=claims/out/results_runs

if [ ! -f .env ] || ! grep -q "API_KEY_DEEPSEEK" .env; then
    echo "ERROR: copy .env.example to .env and fill in API_KEY_DEEPSEEK." >&2
    exit 1
fi

echo "[1/4] Checking the local model backend ..."
"$PY" claims/check_ollama.py $LOCAL_MODELS

echo
echo "[2/4] Extracting with the cloud reference ($CLOUD_MODEL) ..."
OUT="$ROOT/$BASELINE/$CLOUD_MODEL/run1"
mkdir -p "$OUT"
"$PY" main.py --input "$PDF" --llm "$CLOUD_MODEL" --scanner openvas \
    --allow-duplicates --output-file "${BASELINE}_${CLOUD_MODEL}_run1" --output-dir "$OUT"

step=3
for m in $LOCAL_MODELS; do
    echo
    echo "[$step/4] Extracting with the local model ($m) ..."
    echo "         This is the slow part: minutes on a GPU, longer on CPU."
    OUT="$ROOT/$BASELINE/$m/run1"
    mkdir -p "$OUT"
    "$PY" main.py --input "$PDF" --llm "$m" --scanner openvas \
        --allow-duplicates --output-file "${BASELINE}_${m}_run1" --output-dir "$OUT"
done

echo
echo "[4/4] Scoring every extraction with the same metric battery ..."
"$PY" tools/run_metrics.py --root "$ROOT" --methods all --no-aggregate --force

echo
echo "=== Per-model extraction quality ==="
"$PY" claims/summarize_models.py "$ROOT"
