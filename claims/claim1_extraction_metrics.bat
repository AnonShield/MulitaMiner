@echo off
REM Claim 1: structured extraction with the V3 pipeline (DeepSeek, JuiceShop report)
REM followed by the full quantitative metric battery against the curated baseline.
cd /d "%~dp0.."

if not exist .env (
    echo ERROR: copy .env.example to .env and fill in API_KEY_DEEPSEEK.
    exit /b 1
)
python -c "import pathlib,sys; sys.exit(0 if 'API_KEY_DEEPSEEK' in pathlib.Path('.env').read_text(encoding='utf-8',errors='ignore') else 1)"
if errorlevel 1 (
    echo ERROR: .env must define API_KEY_DEEPSEEK="..."
    exit /b 1
)

set OUT=claims\out\results_runs_v3\OpenVAS_JuiceShop\deepseek\run1
if not exist "%OUT%" mkdir "%OUT%"

echo [1/3] Extracting with the V3 pipeline (DeepSeek) ...
python main.py --input baselines\openvas\OpenVAS_JuiceShop.pdf ^
    --llm deepseek --scanner openvas --allow-duplicates ^
    --output-file OpenVAS_JuiceShop_deepseek_run1 --output-dir "%OUT%"
if errorlevel 1 exit /b 1

echo.
echo [2/3] Extraction summary ...
python tools\summarize_vulnerabilities.py --input "%OUT%\OpenVAS_JuiceShop_deepseek_run1.json"

echo.
echo [3/3] Running the metric battery against the curated baseline ...
python tools\run_metrics.py --root claims\out\results_runs_v3 --methods all --no-aggregate --force
if errorlevel 1 exit /b 1

echo.
echo === Metric summary (V3, DeepSeek, JuiceShop) ===
python claims\summarize_versions.py claims\out\results_runs_v3
