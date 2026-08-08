@echo off
REM Claim 1: a local SLM matches the cloud reference on structured extraction.
REM Runs the same pipeline, same prompts and same baseline with both models,
REM then scores them with the identical metric battery.
setlocal
cd /d "%~dp0.."

REM Models compared, in table order.
set CLOUD_MODEL=deepseek
set LOCAL_MODELS=llama31_local

set BASELINE=OpenVAS_JuiceShop
set PDF=baselines\openvas\%BASELINE%.pdf
set ROOT=claims\out\results_runs

if not exist .env (
    echo ERROR: copy .env.example to .env and fill in API_KEY_DEEPSEEK.
    exit /b 1
)
python -c "import pathlib,sys; sys.exit(0 if 'API_KEY_DEEPSEEK' in pathlib.Path('.env').read_text(encoding='utf-8',errors='ignore') else 1)"
if errorlevel 1 (
    echo ERROR: .env must define API_KEY_DEEPSEEK="..."
    exit /b 1
)

echo [1/4] Checking the local model backend ...
python claims\check_ollama.py %LOCAL_MODELS%
if errorlevel 1 exit /b 1

echo.
echo [2/4] Extracting with the cloud reference (%CLOUD_MODEL%) ...
set OUT=%ROOT%\%BASELINE%\%CLOUD_MODEL%\run1
if not exist "%OUT%" mkdir "%OUT%"
python main.py --input "%PDF%" --llm %CLOUD_MODEL% --scanner openvas ^
    --allow-duplicates --output-file "%BASELINE%_%CLOUD_MODEL%_run1" --output-dir "%OUT%"
if errorlevel 1 exit /b 1

for %%m in (%LOCAL_MODELS%) do (
    echo.
    echo [3/4] Extracting with the local model ^(%%m^) ...
    echo          This is the slow part: minutes on a GPU, longer on CPU.
    set OUT=%ROOT%\%BASELINE%\%%m\run1
    if not exist "%ROOT%\%BASELINE%\%%m\run1" mkdir "%ROOT%\%BASELINE%\%%m\run1"
    python main.py --input "%PDF%" --llm %%m --scanner openvas ^
        --allow-duplicates --output-file "%BASELINE%_%%m_run1" --output-dir "%ROOT%\%BASELINE%\%%m\run1"
    if errorlevel 1 exit /b 1
)

echo.
echo [4/4] Scoring every extraction with the same metric battery ...
python tools\run_metrics.py --root "%ROOT%" --methods all --no-aggregate --force
if errorlevel 1 exit /b 1

echo.
echo === Per-model extraction quality ===
python claims\summarize_models.py "%ROOT%"
