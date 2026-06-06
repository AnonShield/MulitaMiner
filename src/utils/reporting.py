"""Final-report generator (Markdown).

Produces a single ``final_report_<ts>_<uuid>.md`` per call, structured for
both human reading and downstream parsing. The legacy plain-text layout was
flattened and noisy; this version uses headers + tables.

Per-run reports are deliberately NOT generated here — orchestrators
(``run_experiments.py`` / ``batch_pdf_extractor.py``) call this once at the
end. ``main.py`` only writes a report when invoked standalone.
"""
import os
import uuid
from datetime import datetime, timedelta


def _fmt_duration(seconds: float) -> str:
    td = timedelta(seconds=seconds)
    h = int(td.total_seconds() // 3600)
    m = int((td.total_seconds() % 3600) // 60)
    s = td.total_seconds() % 60
    return f"{h:02d}:{m:02d}:{s:06.3f}"


def _section(title: str, level: int = 2) -> str:
    return f"\n{'#' * level} {title}\n\n"


def generate_final_report(
    start_time,
    end_time,
    run_stats,
    tokens_dir="results_tokens",
    report_dir="results_runs",
    include_metrics_time=True,
    timing_report=None,
    failures=None,
):
    """Write a Markdown final report and return its path.

    Args:
        start_time / end_time: Unix timestamps.
        run_stats: dict with optional keys ``baseline_counts``, ``total_runs``.
        tokens_dir: directory with ``*_tokens.json`` files.
        report_dir: where the .md is written.
        include_metrics_time: kept for API compat (currently unused; metrics
            time is part of the per-run timing).
        timing_report: list of per-run dicts (must contain ``total_time``,
            optionally ``run_id``, ``llm``, ``baseline``).
        failures: list of dicts with ``run_id`` + ``error`` for the
            "Failures" section.
    """
    start_dt = datetime.fromtimestamp(start_time)
    end_dt = datetime.fromtimestamp(end_time)

    if timing_report:
        total_exec_time = sum(r.get('total_time', 0) for r in timing_report)
    else:
        total_exec_time = end_time - start_time

    report_uuid = str(uuid.uuid4())
    report_ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    final_report_name = f"final_report_{report_ts}_{report_uuid}.md"
    final_report_path = os.path.join(report_dir, final_report_name)

    from src.utils.tokens_cost import calc_tokens_and_cost
    llm_totals, llm_costs, total_all_tokens, total_cost = calc_tokens_and_cost(tokens_dir)

    lines: list[str] = []
    lines.append("# Experiment Report\n")
    lines.append(f"- **Report ID:** `{report_uuid}`")
    lines.append(f"- **Generated:** {report_ts}")
    lines.append(f"- **Started:**   {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- **Ended:**     {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- **Duration:**  {_fmt_duration(total_exec_time)}")
    if 'total_runs' in run_stats:
        lines.append(f"- **Total runs:** {run_stats['total_runs']}")

    if run_stats.get('baseline_counts'):
        lines.append(_section("Runs per baseline"))
        lines.append("| Baseline | Runs |")
        lines.append("|---|---:|")
        for base, count in run_stats['baseline_counts'].items():
            lines.append(f"| {base} | {count} |")

    lines.append(_section("Token usage & cost (estimativa — tiktoken)"))
    if llm_totals:
        lines.append("| LLM | Files | Input tokens | Output tokens | Cost (USD) |")
        lines.append("|---|---:|---:|---:|---:|")
        for llm, stats in llm_totals.items():
            lines.append(
                f"| {llm} | {stats['files']} | {stats['input']:,} | "
                f"{stats['output']:,} | {llm_costs.get(llm, 0):.2f} |"
            )
        lines.append(
            f"| **TOTAL** | | | **{total_all_tokens:,}** | **{total_cost:.2f}** |"
        )
    else:
        lines.append("_No token data found._")

    # Usage REAL da API (usage_real_*.jsonl): contagem exata + custo com cache do DeepSeek.
    from src.utils.tokens_cost import calc_real_usage
    real = calc_real_usage(tokens_dir)
    real = {k: v for k, v in real.items() if (v.get("input") or v.get("output"))}
    if real:
        lines.append(_section("Real API usage & cost"))
        lines.append("| LLM | Input (real) | cache hit | cache miss | Output | Cost real (USD) |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        tot_real_cost = 0.0
        for llm, a in real.items():
            c = a.get("cost")
            tot_real_cost += c or 0
            cost_s = f"{c:.4f}" if c is not None else "—"
            lines.append(
                f"| {llm} | {a['input']:,} | {a['cache_hit']:,} | {a['cache_miss']:,} | "
                f"{a['output']:,} | {cost_s} |"
            )
        lines.append(f"| **TOTAL** | | | | | **{tot_real_cost:.4f}** |")
        lines.append("\n_Contagem real retornada pela API (modelos locais não retornam usage → não aparecem). "
                     "Confirme o valor oficial no dashboard do provedor._")

    lines.append(_section("Timing"))
    if timing_report:
        n = len(timing_report)
        times = [r.get('total_time', 0) for r in timing_report]
        mean = sum(times) / n if n else 0
        slowest_idx = times.index(max(times)) if times else 0
        slowest = timing_report[slowest_idx] if timing_report else {}
        slowest_label = slowest.get('run_id') or slowest.get('llm') or 'n/a'
        lines.append(f"- Runs reported: **{n}**")
        lines.append(f"- Mean per run: **{mean:.2f}s**")
        lines.append(f"- Slowest: **{max(times):.2f}s** ({slowest_label})")
        lines.append(f"- Total (sum of runs): **{_fmt_duration(sum(times))}**")
    else:
        lines.append("_No timing data._")

    if failures:
        lines.append(_section("Failures"))
        lines.append(f"**{len(failures)} run(s) failed:**\n")
        for f in failures:
            run_id = f.get('run_id', '?')
            err = f.get('error', '').replace('\n', ' ').strip()
            lines.append(f"- `{run_id}` — {err}")

    os.makedirs(report_dir, exist_ok=True)
    with open(final_report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Final report saved to: {final_report_path}")
    return final_report_path
