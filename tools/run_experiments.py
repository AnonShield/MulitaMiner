import subprocess
import os
import time
import json
import sys
from datetime import datetime, timedelta

# Configurações das runs
baselines = [
    "metrics/baselines/openvas/OpenVAS_JuiceShop.xlsx"
]
extractors = [
    "metrics/baselines/openvas/OpenVAS_JuiceShop.pdf"
]
llms = ["llama3"] # config llm
scanners = ["openvas"] # config scanners
evaluation_methods = ["bert"] # config metricas
runs_per_model = 10 # numero de runs
allow_duplicates_map = {"openvas": True, "tenable": False} # config do cli allow-duplicates por scanner

os.makedirs("results_runs", exist_ok=True)

# Estatísticas de execução
def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

run_stats = {
    'start_time': time.time(),
    'baseline_counts': {},
    'total_runs': 0
}

# === SISTEMA DE CHECKPOINT ===
from pathlib import Path
def make_checkpoint_path(ts):
    return f"run_checkpoints_{ts}.json"

checkpoint_id = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
checkpoint_path = make_checkpoint_path(checkpoint_id)

all_run_ids = []
for baseline_path, extractor_path in zip(baselines, extractors):
    for scanner in scanners:
        for llm in llms:
            for run_num in range(1, runs_per_model + 1):
                baseline_folder = os.path.splitext(os.path.basename(baseline_path))[0]
                run_id = f"{baseline_folder}_{llm}_run{run_num}"
                all_run_ids.append((run_id, baseline_path, extractor_path, scanner, llm, run_num))


import uuid
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--checkpoint-file', type=str, default=None, help='Arquivo de checkpoint a ser usado')
args, unknown = parser.parse_known_args()

# Verifica argumentos desconhecidos
if unknown:
    print(f"\nErro: Argumentos não reconhecidos: {unknown}")
    print("Verifique se há erros de digitação nos argumentos.")
    sys.exit(1)

if args.checkpoint_file:
    checkpoint_path = args.checkpoint_file
    with open(checkpoint_path, "r", encoding="utf-8") as f:
        checkpoint_data = json.load(f)
    checkpoints = checkpoint_data["runs"]
    checkpoint_id = checkpoint_data.get("checkpoint_id", datetime.now().strftime("%Y-%m-%dT%H-%M-%S"))
else:
    checkpoint_id = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    checkpoint_path = f"run_checkpoints_{checkpoint_id}.json"
    checkpoints = {}
    for run_id, baseline_path, extractor_path, scanner, llm, run_num in all_run_ids:
        checkpoints[run_id] = {
            "status": "pending",
            "erro": None,
            "baseline": baseline_path,
            "extractor": extractor_path,
            "scanner": scanner,
            "llm": llm,
            "run_num": run_num,
            "cmd": None,
            "rouge_cmd": None,
            "output_file": None,
            "timestamp": None
        }
    checkpoint_data = {"checkpoint_id": checkpoint_id, "runs": checkpoints}
    with open(checkpoint_path, "w", encoding="utf-8") as f:
        json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)


for run_id, baseline_path, extractor_path, scanner, llm, run_num in all_run_ids:
    entry = checkpoints[run_id]
    if args.checkpoint_file:
        if entry["status"] == "ok":
            print(f"[CHECKPOINT] Pulando {run_id} (status ok)")
            continue
    allow_duplicates = allow_duplicates_map.get(scanner, False)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    baseline_folder = os.path.splitext(os.path.basename(baseline_path))[0]
    subdir = os.path.join("results_runs", baseline_folder, llm, f"run{run_num}")
    os.makedirs(subdir, exist_ok=True)
    base_id = f"{baseline_folder}_{llm}_run{run_num}_{timestamp}"
    output_file = os.path.join(subdir, f"{base_id}.txt")
    os.environ["RUN_PREFIX"] = base_id
    cmd = [
        sys.executable, "main.py",
        extractor_path,
        "--scanner", scanner,
        "--llm", llm,
        "--convert", "xlsx",
        "--evaluate",
        "--baseline", baseline_path,
        "--output-dir", subdir
    ]
    if allow_duplicates:
        cmd.append("--allow-duplicates")
    try:
        print(f"Rodando extração: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.stdout and result.stdout.strip():
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
        if result.stderr and result.stderr.strip():
            print(f"[STDERR] {result.stderr}")
        pdf_base = os.path.splitext(os.path.basename(extractor_path))[0]
        llm_name = llm.replace('/', '_').replace(':', '_')
        import shutil, glob
        run_prefix = f"{baseline_folder}_{llm}_run{run_num}_"
        patterns = [
            f"{pdf_base}_{llm_name}*.json",
            f"{pdf_base}_{llm_name}*.xlsx",
            f"{pdf_base}_{llm_name}*removed_log*",
            f"{pdf_base}_{llm_name}*merge_log*",
            f"{run_prefix}*.json",
            f"{run_prefix}*.xlsx",
            f"{run_prefix}*removed_log*",
            f"{run_prefix}*merge_log*"
        ]
        for pattern in patterns:
            for file in glob.glob(os.path.join("results_runs", pattern)):
                fname = os.path.basename(file)
                if not fname.startswith(run_prefix):
                    new_fname = f"{run_prefix}{fname}"
                else:
                    new_fname = fname
                dst = os.path.join(subdir, new_fname)
                if os.path.abspath(file) != os.path.abspath(dst):
                    shutil.move(file, dst)

        # Check if JSON output is empty
        json_candidates = [f for f in os.listdir(subdir) if f.startswith(f"{run_prefix}") and f.endswith(".json")]
        if json_candidates:
            json_file = os.path.join(subdir, json_candidates[0])
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list) and not data:  # Check if it's an empty list
                    raise ValueError("JSON output is an empty list")
            except Exception as e:
                print(f"[CHECKPOINT] Erro na run {run_id}: {e}")
                checkpoints[run_id] = {
                    "status": "erro",
                    "erro": str(e),
                    "baseline": baseline_path,
                    "extractor": extractor_path,
                    "scanner": scanner,
                    "llm": llm,
                    "run_num": run_num,
                    "cmd": cmd,
                    "rouge_cmd": None,
                    "output_file": output_file,
                    "timestamp": timestamp
                }
                checkpoint_data["runs"] = checkpoints
                with open(checkpoint_path, "w", encoding="utf-8") as f:
                    json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
                continue
        print(f"[DEBUG] Procurando arquivos .xlsx no subdir: {subdir}")
        print(f"[DEBUG] Padrão de busca: prefixo='{run_prefix}', sufixo='.xlsx'")
        print(f"[DEBUG] Arquivos no subdir após main.py: {os.listdir(subdir)}")
        xlsx_candidates = [f for f in os.listdir(subdir) if f.startswith(f"{run_prefix}") and f.endswith(".xlsx")]
        print(f"[DEBUG] Arquivos .xlsx candidatos encontrados: {xlsx_candidates}")
        if not xlsx_candidates:
            print(f"[ERRO DEBUG] Nenhum arquivo .xlsx encontrado com prefixo '{run_prefix}' e sufixo '.xlsx' em {subdir}")
            raise Exception(f"[ERRO] Arquivo .xlsx de extração não encontrado para {pdf_base} {llm_name}")
        extraction_xlsx = os.path.join(subdir, xlsx_candidates[0])
        for method in evaluation_methods:
            if method == "bert":
                bert_output_dir = os.path.join("metrics", "bert", "results")
                os.makedirs(bert_output_dir, exist_ok=True)
                bert_cmd = [
                    sys.executable, "metrics/bert/compare_extractions_bert.py",
                    "--baseline-file", baseline_path,
                    "--extraction-file", extraction_xlsx,
                    "--model", llm,
                    "--output-dir", bert_output_dir
                ]
                if allow_duplicates:
                    bert_cmd.append("--allow-duplicates")
                print(f"Rodando análise BERT: {' '.join(bert_cmd)}")
                result_bert = subprocess.run(bert_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
                bert_log = output_file.replace('.txt', '_bert.txt')
                if result_bert.stdout and result_bert.stdout.strip():
                    with open(bert_log, "w", encoding="utf-8") as f:
                        f.write(result_bert.stdout)
                if result_bert.stderr and result_bert.stderr.strip():
                    print(f"[STDERR-BERT] {result_bert.stderr}")
            elif method == "rouge":
                rouge_output_dir = os.path.join("metrics", "rouge", "results")
                os.makedirs(rouge_output_dir, exist_ok=True)
                rouge_cmd = [
                    sys.executable, "metrics/rouge/compare_extractions_rouge.py",
                    "--baseline-file", baseline_path,
                    "--extraction-file", extraction_xlsx,
                    "--model", llm,
                    "--output-dir", rouge_output_dir
                ]
                if allow_duplicates:
                    rouge_cmd.append("--allow-duplicates")
                print(f"Rodando análise ROUGE: {' '.join(rouge_cmd)}")
                result_rouge = subprocess.run(rouge_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
                rouge_log = output_file.replace('.txt', '_rouge.txt')
                if result_rouge.stdout and result_rouge.stdout.strip():
                    with open(rouge_log, "w", encoding="utf-8") as f:
                        f.write(result_rouge.stdout)
                if result_rouge.stderr and result_rouge.stderr.strip():
                    print(f"[STDERR-ROUGE] {result_rouge.stderr}")
        xlsx_subdir = os.path.join("results_runs_xlsx", baseline_folder, llm, f"run{run_num}")
        os.makedirs(xlsx_subdir, exist_ok=True)
        bert_dir = os.path.join("metrics", "bert", "results", baseline_folder)
        bert_file = os.path.join(bert_dir, f"bert_comparison_vulnerabilities_{llm}.xlsx")
        if os.path.exists(bert_file):
            shutil.copy(bert_file, os.path.join(xlsx_subdir, os.path.basename(bert_file)))
        bert_summary_file = os.path.join("metrics", "bert", "results", f"summary_all_extractions_bert_{baseline_folder}_{llm}.xlsx")
        if os.path.exists(bert_summary_file):
            shutil.copy(bert_summary_file, os.path.join(xlsx_subdir, os.path.basename(bert_summary_file)))

        # 
        rouge_metrics_dir = os.path.join("metrics", "rouge", "results", baseline_folder)
        rouge_file = os.path.join(rouge_metrics_dir, f"rouge_comparison_vulnerabilities_{llm}.xlsx")
        if os.path.exists(rouge_file):
            shutil.copy(rouge_file, os.path.join(xlsx_subdir, os.path.basename(rouge_file)))
       
        rouge_summary_file = os.path.join(rouge_metrics_dir, f"summary_all_extractions_rouge_{baseline_folder}_{llm}.xlsx")
        if not os.path.exists(rouge_summary_file):
            
            rouge_summary_file = os.path.join("metrics", "rouge", "results", f"summary_all_extractions_rouge_{baseline_folder}_{llm}.xlsx")
        if os.path.exists(rouge_summary_file):
            shutil.copy(rouge_summary_file, os.path.join(xlsx_subdir, os.path.basename(rouge_summary_file)))
            os.remove(rouge_summary_file)
        checkpoints[run_id] = {
            "status": "ok",
            "erro": None,
            "baseline": baseline_path,
            "extractor": extractor_path,
            "scanner": scanner,
            "llm": llm,
            "run_num": run_num,
            "cmd": cmd,
            "output_file": output_file,
            "timestamp": timestamp
        }
    except Exception as e:
        print(f"[CHECKPOINT] Erro na run {run_id}: {e}")
        import traceback
        traceback.print_exc()
        checkpoints[run_id] = {
            "status": "erro",
            "erro": str(e),
            "baseline": baseline_path,
            "extractor": extractor_path,
            "scanner": scanner,
            "llm": llm,
            "run_num": run_num,
            "cmd": cmd,
            "rouge_cmd": None,
            "output_file": output_file,
            "timestamp": timestamp
        }
    checkpoint_data["runs"] = checkpoints
    with open(checkpoint_path, "w", encoding="utf-8") as f:
        json.dump(checkpoint_data, f, indent=2, ensure_ascii=False)
    baseline_key = os.path.basename(baseline_path)
    run_stats['baseline_counts'][baseline_key] = run_stats['baseline_counts'].get(baseline_key, 0) + 1
    run_stats['total_runs'] += 1

# Ao final, salva estatísticas de execução
run_stats['end_time'] = time.time()
run_stats['duration'] = run_stats['end_time'] - run_stats['start_time']
start_dt = datetime.fromtimestamp(run_stats['start_time'])
end_dt = datetime.fromtimestamp(run_stats['end_time'])
duration_td = timedelta(seconds=int(run_stats['duration']))
with open("results_runs/experiments_summary.txt", "w", encoding="utf-8") as f:
    f.write(f"Resumo das execuções\n")
    f.write(f"Início: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Término: {end_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"Tempo total: {duration_td}\n")
    f.write(f"\nTotal de runs por baseline:\n")
    for base, count in run_stats['baseline_counts'].items():
        f.write(f"  {base}: {count}\n")
    f.write(f"\nTotal de runs: {run_stats['total_runs']}\n")
