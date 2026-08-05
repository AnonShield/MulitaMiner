"""Markdown final-report generator.

Writes one final_report_<ts>_<uuid>.md per call. Orchestrators call it once at
the end of a batch, so per-run reports are deliberately not generated here.
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
    """Write the Markdown final report and return its path.

    timing_report holds per-run dicts with total_time (plus optional run_id,
    llm, baseline); failures holds run_id + error entries. include_metrics_time
    is unused, kept for API compatibility.
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

    lines.append(_section("Token usage & cost"))
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
            lines.append(f"- `{run_id}`: {err}")

    os.makedirs(report_dir, exist_ok=True)
    with open(final_report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Final report saved to: {final_report_path}")
    return final_report_path
