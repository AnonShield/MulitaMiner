#!/usr/bin/env bash
# Claim 1: a local SLM matches the cloud reference on structured extraction.
# Runs the same pipeline, same prompts and same baseline with both models,
# then scores them with the identical metric battery.
set -e
cd "$(dirname "$0")/.."
PY="$(command -v python3 || command -v python || true)"

if [ -z "$PY" ]; then
    echo "ERROR: no python3 or python on PATH. Activate the virtual environment first." >&2
    exit 1
fi

# Models compared, in table order.
CLOUD_MODEL=deepseek
LOCAL_MODELS="llama31_local"

BASELINE=OpenVAS_JuiceShop
PDF="baselines/openvas/${BASELINE}.pdf"
ROOT=claims/out/results_runs

# An extraction that yields no vulnerability means the provider never answered;
# main.py still exits 0 in that case, so check the output explicitly.
check_output() {
    if ! "$PY" -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1],encoding='utf-8')) else 1)" "$1" 2>/dev/null; then
        echo >&2
        echo "ERROR: $2 extracted no vulnerabilities." >&2
        echo "  The model never answered. Common causes: Ollama stopped mid-run," >&2
        echo "  or the DeepSeek key is invalid or out of credit." >&2
        exit 1
    fi
}

"$PY" claims/check_env.py

echo "[1/4] Checking the local model backend ..."
"$PY" claims/check_ollama.py $LOCAL_MODELS

echo
echo "[2/4] Extracting with the cloud reference ($CLOUD_MODEL) ..."
OUT="$ROOT/$BASELINE/$CLOUD_MODEL/run1"
mkdir -p "$OUT"
"$PY" main.py --input "$PDF" --llm "$CLOUD_MODEL" --scanner openvas \
    --allow-duplicates --output-file "${BASELINE}_${CLOUD_MODEL}_run1" --output-dir "$OUT"
check_output "$OUT/${BASELINE}_${CLOUD_MODEL}_run1.json" "the cloud reference ($CLOUD_MODEL)"

step=3
for m in $LOCAL_MODELS; do
    echo
    echo "[$step/4] Extracting with the local model ($m) ..."
    echo "         This is the slow part: minutes on a GPU, longer on CPU."
    OUT="$ROOT/$BASELINE/$m/run1"
    mkdir -p "$OUT"
    "$PY" main.py --input "$PDF" --llm "$m" --scanner openvas \
        --allow-duplicates --output-file "${BASELINE}_${m}_run1" --output-dir "$OUT"
    check_output "$OUT/${BASELINE}_${m}_run1.json" "the local model ($m)"
done

echo
echo "[4/4] Scoring every extraction with the same metric battery ..."
"$PY" tools/run_metrics.py --root "$ROOT" --methods all --no-aggregate --force

echo
echo "=== Per-model extraction quality ==="
"$PY" claims/summarize_models.py "$ROOT"
