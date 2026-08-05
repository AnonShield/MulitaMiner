@echo off
REM Claim 2: pipeline versioning drives extraction quality (V1 -> V2 -> V3).
REM Extracts the same report with V1 and V2 (shipped as zips in versions/),
REM then evaluates all three versions with the V3 metric battery.
REM If the V3 run from Claim 1 is missing, Claim 1 is executed first.
setlocal
cd /d "%~dp0.."
set ROOT=%CD%

if not exist .env (
    echo ERROR: copy .env.example to .env and fill in API_KEY_DEEPSEEK.
    exit /b 1
)
findstr /C:"API_KEY_DEEPSEEK" .env >nul || (
    echo ERROR: .env must define API_KEY_DEEPSEEK="..."
    exit /b 1
)

if not exist "claims\out\results_runs_v3\OpenVAS_JuiceShop\deepseek\run1\OpenVAS_JuiceShop_deepseek_run1*.json" (
    echo [0/5] V3 extraction not found, running Claim 1 first ...
    call claims\claim1_extraction_metrics.bat
    if errorlevel 1 exit /b 1
)

set PDF=%ROOT%\baselines\openvas\OpenVAS_JuiceShop.pdf
set V1_DIR=%ROOT%\claims\out\versions\mulitaminer-v1
set V2_DIR=%ROOT%\claims\out\versions\mulitaminer-v2
set VENV=%ROOT%\claims\out\versions\venv-legacy
set V1_RUN=%ROOT%\claims\out\results_runs_v1\OpenVAS_JuiceShop\deepseek\run1
set V2_RUN=%ROOT%\claims\out\results_runs_v2\OpenVAS_JuiceShop\deepseek\run1

echo [1/5] Unpacking V1 and V2 from versions\ ...
if not exist claims\out\versions mkdir claims\out\versions
if not exist "%V1_DIR%" python -m zipfile -e versions\mulitaminer-v1.zip claims\out\versions\
if not exist "%V2_DIR%" python -m zipfile -e versions\mulitaminer-v2.zip claims\out\versions\

echo [2/5] Preparing legacy virtualenv (V1/V2 extraction dependencies) ...
if not exist "%VENV%\Scripts\python.exe" python -m venv "%VENV%"
set PY_LEGACY=%VENV%\Scripts\python.exe
"%PY_LEGACY%" -m pip install --quiet "langchain>=0.1.0,<0.3.0" "langchain-openai>=0.1.0,<0.2.0" ^
    "langchain-core>=0.1.0,<0.2.0" "pdfplumber>=0.10.0,<0.12.0" "tqdm>=4.0.0,<5.0.0" ^
    "tiktoken>=0.5.1,<0.7.0" "python-dotenv>=0.21.0" "deepmerge>=1.1.0,<2.0.0" ^
    "pandas>=1.3.0,<3.0.0" "openpyxl>=3.0.0,<4.0.0"
if errorlevel 1 exit /b 1

echo [3/5] Extracting with V1 (DeepSeek) ...
if not exist "%V1_RUN%" mkdir "%V1_RUN%"
pushd "%V1_DIR%"
"%PY_LEGACY%" main.py "%PDF%" --scanner openvas --LLM deepseek ^
    --allow-duplicates --output "%V1_RUN%\OpenVAS_JuiceShop_deepseek_run1.json"
if errorlevel 1 (popd & exit /b 1)
popd

echo [4/5] Extracting with V2 (DeepSeek) ...
if not exist "%V2_RUN%" mkdir "%V2_RUN%"
pushd "%V2_DIR%"
"%PY_LEGACY%" main.py --input "%PDF%" --llm deepseek --scanner openvas ^
    --allow-duplicates --output-file OpenVAS_JuiceShop_deepseek_run1 --output-dir "%V2_RUN%"
if errorlevel 1 (popd & exit /b 1)
popd

echo [5/5] Evaluating V1, V2 and V3 outputs with the V3 metric battery ...
python tools\run_metrics.py ^
    --root claims\out\results_runs_v1 claims\out\results_runs_v2 claims\out\results_runs_v3 ^
    --methods coverage severity --no-aggregate
if errorlevel 1 exit /b 1

echo.
echo === Cross-version summary (DeepSeek, JuiceShop) ===
python claims\summarize_versions.py ^
    claims\out\results_runs_v1 claims\out\results_runs_v2 claims\out\results_runs_v3
