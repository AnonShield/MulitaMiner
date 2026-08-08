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

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: no python on PATH. Activate the virtual environment first.
    exit /b 1
)

python claims\check_env.py
if errorlevel 1 exit /b 1

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
call :check_output "%OUT%\%BASELINE%_%CLOUD_MODEL%_run1.json" "the cloud reference %CLOUD_MODEL%"
if errorlevel 1 exit /b 1

for %%m in (%LOCAL_MODELS%) do (
    echo.
    echo [3/4] Extracting with the local model ^(%%m^) ...
    echo          This is the slow part: minutes on a GPU, longer on CPU.
    if not exist "%ROOT%\%BASELINE%\%%m\run1" mkdir "%ROOT%\%BASELINE%\%%m\run1"
    python main.py --input "%PDF%" --llm %%m --scanner openvas ^
        --allow-duplicates --output-file "%BASELINE%_%%m_run1" --output-dir "%ROOT%\%BASELINE%\%%m\run1"
    if errorlevel 1 exit /b 1
    call :check_output "%ROOT%\%BASELINE%\%%m\run1\%BASELINE%_%%m_run1.json" "the local model %%m"
    if errorlevel 1 exit /b 1
)

echo.
echo [4/4] Scoring every extraction with the same metric battery ...
python tools\run_metrics.py --root "%ROOT%" --methods all --no-aggregate --force
if errorlevel 1 exit /b 1

echo.
echo === Per-model extraction quality ===
python claims\summarize_models.py "%ROOT%"
exit /b 0

REM An extraction that yields no vulnerability means the provider never answered;
REM main.py still exits 0 in that case, so check the output explicitly.
REM No parenthesised block here: %~2 is echoed raw, and a ")" inside it would
REM close the block while cmd parses it, breaking the script even on success.
:check_output
python -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1],encoding='utf-8')) else 1)" %1 2>nul
if not errorlevel 1 exit /b 0
echo.
echo ERROR: %~2 extracted no vulnerabilities.
echo   The model never answered. Common causes: Ollama stopped mid-run,
echo   or the DeepSeek key is invalid or out of credit.
exit /b 1
