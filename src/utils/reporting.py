import os
import json
import uuid
from datetime import datetime, timedelta
from glob import glob

def generate_final_report(
    start_time,
    end_time,
    run_stats,
    tokens_dir="results_tokens",
    report_dir="results_runs",
    include_metrics_time=True,
    timing_report=None
):
    """
    Gera relatório final de execução, incluindo tempo, tokens e custo.
    - start_time: timestamp inicial
    - end_time: timestamp final
    - run_stats: dict com estatísticas de execução
    - tokens_dir: diretório dos arquivos de tokens
    - report_dir: diretório para salvar o relatório
    - include_metrics_time: se True, soma tempo das métricas
    - timing_report: lista de dicts com tempo de cada run (opcional)
    """
    start_dt = datetime.fromtimestamp(start_time)
    end_dt = datetime.fromtimestamp(end_time)
    # Corrige tempo total: soma dos tempos das runs
    if timing_report:
        total_exec_time = sum([r['total_time'] for r in timing_report])
        duration_td = timedelta(seconds=total_exec_time)
    else:
        total_exec_time = end_time - start_time
        duration_td = timedelta(seconds=total_exec_time)

    report_uuid = str(uuid.uuid4())
    report_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    final_report_name = f"final_report_{report_ts}_{report_uuid}.txt"
    final_report_path = os.path.join(report_dir, final_report_name)

    from src.utils.tokens_cost import calc_tokens_and_cost
    llm_totals, llm_costs, total_all_tokens, total_cost = calc_tokens_and_cost(tokens_dir)

    with open(final_report_path, "w", encoding="utf-8") as f:
        f.write(f"==== Experiments Final Report ====" + "\n")
        f.write(f"Report UUID: {report_uuid}\n")
        f.write(f"Report Timestamp: {report_ts}\n")
        f.write(f"Start: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"End: {end_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
        # Formata hh:mm:ss.sss
        total_seconds = total_exec_time
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = total_seconds % 60
        f.write(f"Total time: {hours:02d}:{minutes:02d}:{seconds:06.3f}\n")
        if 'baseline_counts' in run_stats:
            f.write(f"\nTotal runs per baseline:\n")
            for base, count in run_stats['baseline_counts'].items():
                f.write(f"  {base}: {count}\n")
        if 'total_runs' in run_stats:
            f.write(f"\nTotal runs: {run_stats['total_runs']}\n")
        f.write(f"\n==== Token Usage and Cost ====" + "\n")
        f.write(f"TOTAL TOKENS: {total_all_tokens}\n")
        f.write(f"TOTAL ESTIMATED COST (US$): {total_cost:.2f}\n")
        for llm, stats in llm_totals.items():
            f.write(f"\nLLM: {llm}\n")
            f.write(f"  Files: {stats['files']}\n")
            f.write(f"  Tokens input: {stats['input']}\n")
            f.write(f"  Tokens output: {stats['output']}\n")
            f.write(f"  Estimated Cost (USD): {llm_costs.get(llm, 0):.2f}\n")
        f.write(f"\n==== Execution Timing Details ====" + "\n")
        if timing_report:
            total_exec_time = sum([r['total_time'] for r in timing_report])
            f.write(f"Total execution time (all runs): {total_exec_time:.2f} seconds\n\n")
            f.write(f"Run details:\n")
            for r in timing_report:
                f.write(f"  {r}\n")
        else:
            f.write(f"(No timing details provided)\n")
    print(f"Final report saved to: {final_report_path}")
    return final_report_path
