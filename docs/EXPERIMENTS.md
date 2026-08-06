# Experiments

Experimental protocol of the paper *MulitaMiner: A Multi-Version Evaluation of
LLM-Based Vulnerability Report Extraction* (SBSeg 2026, main track).

The reviewer-facing, runnable version of these experiments is in the
[README](../README.md#experiments): two claims, each with a ready script. This
document describes the full protocol behind the numbers reported in the paper.

## Design

Three pipeline versions were evaluated under identical conditions:

| Version | Chunking | Tokenizer | Retry | Metrics |
| ------- | -------- | --------- | ----- | ------- |
| **V1** | Single pass, fixed budget read from JSON (~2600 tokens), scanner marker as a soft hint | `cl100k_base` for every LLM | Up to 3 attempts, chunk split at the nearest line break | None |
| **V2** | Two steps: marker-aware character split (8000), then token slice (~3000) | `cl100k_base` for every LLM | Up to 3 attempts, redivision respects scanner markers | BERTScore, ROUGE-L |
| **V3** | Marker-aware split with a dual cap: tokens from JSON and characters derived from the text's own token density | Per-LLM, configurable | Library-based JSON repair first, then up to 3 error-aware redivisions; fatal API errors abort the run | Full battery (see below) |

The grid is **3 versions × 5 LLMs × 3 baselines × 10 runs = 450 independent runs**.
Ten runs per cell capture the run-to-run variance of stochastic LLM decoding.

### Models

`deepseek-coder`, `gpt-4o-mini-2024-07-18`, `gpt-5-mini-2025-08-07`,
`llama-3.3-70b-versatile` and `meta-llama/llama-4-scout-17b-16e-instruct`, all
through their official cloud APIs (OpenAI for the GPT family, DeepSeek's native
API, Groq for the LLaMA models) so that observed differences reflect model
behaviour rather than deployment artifacts. To respect per-endpoint rate limits,
models were grouped by provider and the groups executed sequentially.

### Ground-truth baselines

Three OpenVAS reports from Docker containers with known vulnerability profiles,
chosen to span distinct application categories and three points of vulnerability
density:

| Baseline | Application type | Vulnerabilities |
| -------- | ---------------- | --------------- |
| OWASP Juice Shop | Deliberately vulnerable e-commerce | 34 |
| bBWA | Intentionally insecure banking web app | 58 |
| Artifactory OSS 5.11.0 | Artifact repository | 116 |
| **Total** | | **217** |

Each baseline was built in two stages: a primary annotator extracted the
vulnerabilities from the source PDF, then a second specialist independently
reviewed the result against the original PDF, adding missed entries and fixing
field values. This extract-then-review protocol converges on a single baseline
by design, so inter-annotator agreement statistics (Cohen's κ, raw agreement)
do not apply.

The PDFs and their XLSX annotations are in [baselines/openvas/](../baselines/openvas/).

## Metric battery

All metrics follow the same two-stage aggregation: computed independently per
run of each (model, baseline) pair, then aggregated. Scalar metrics are averaged
across runs and baselines; categorical metrics aggregate per-run category counts
and report their mean share. This preserves the run-to-run variability that
pooling raw scores would mask.

**Vulnerability-level alignment.** Extracted records are aligned with baseline
records through a three-stage hierarchy: composite-key match on a scanner-aware
tuple (`name|port|protocol` for OpenVAS, with absent positions treated as
wildcards that contribute less to the match score); exact normalized-name match
for records whose composite key fails; and fuzzy name match (rapidfuzz ratio
>= 0.85) as the final fallback. Each baseline record is consumed at most once.
From this alignment come the *hallucination rate* (extracted records with no
baseline match), the *omission rate* (baseline records with no extraction) and
the mean number of *matched pairs* per run.

**Field-level quality**, within matched pairs. *Exact Record Match* is the
fraction of matched pairs where all deterministic fields (`cvss`, `port`,
`protocol`, `severity`, `source`) agree exactly with the baseline. Field-level
hallucination counts fields filled in the extraction where the baseline is
empty; field-level omission counts the inverse. Precision, recall and F1 are
also reported per field.

**Textual similarity**, for free-text fields (`description`, `impact`,
`detection_method`, `references`): BERTScore F1 (semantic), ROUGE-L (lexical)
and Token-F1 (token overlap). Each per-field score is also bucketed as Highly
Similar (>= 0.7), Moderately Similar (0.6-0.7), Slightly Similar (0.4-0.6),
Divergent (< 0.4) or Absent (extraction empty when the baseline is not).

**Severity classification.** Macro F1 averages per-class F1 across the five
severity levels (LOG / LOW / MEDIUM / HIGH / CRITICAL). Coverage-aware Macro F1
weights each per-class F1 by the fraction of baseline records of that class
actually recovered, penalizing pipelines that classify well only what they
happen to extract.

**Confidence intervals.** Each headline metric carries a 95% bootstrap
confidence interval (10,000 resamples, percentile method) over the N=150
observations per version. Non-overlapping intervals between two versions are
treated as evidence that the difference exceeds run-level noise.

## Running the experiments

The two reviewer claims are documented in the
[README](../README.md#experiments). To run the full grid instead of a single
configuration:

```bash
# Windows
python tools/run_experiments.py --input-dir baselines\openvas --llm deepseek gpt4 llama3 --scanner openvas --metrics all --runs-per-model 10 --allow-duplicates

# Linux/macOS
python3 tools/run_experiments.py --input-dir baselines/openvas --llm deepseek gpt4 llama3 --scanner openvas --metrics all --runs-per-model 10 --allow-duplicates
```

Key parameters:

- `--input-dir`: directory with paired `.pdf` (report) and `.xlsx` (baseline) files
- `--llm`: space-separated LLM configuration names from `src/configs/llms/`
- `--scanner`: one scanner per invocation (`openvas` or `tenable`)
- `--metrics`: `bert`, `rouge`, `entity`, `schema`, `severity`, `coverage`, or `all`; producer/consumer dependencies are resolved automatically
- `--runs-per-model`: repetitions per (report, LLM) pair
- `--allow-duplicates`: recommended for OpenVAS, where the same vulnerability legitimately repeats on different ports; omit it for Tenable WAS
- `--checkpoint-file`: resume an interrupted execution

Extraction runs first for every (report, LLM, run) combination, then the metrics
run as a parallel post-pass so the BERTScore model loads once instead of once
per run.

### Output layout

```
<output-dir>/
├── <baseline>/<llm>/run<N>/
│   ├── <baseline>_<llm>_run<N>.json      # extraction (native output)
│   ├── bert_comparison_*.xlsx
│   ├── rouge_comparison_*.xlsx
│   ├── token_f1_comparison_*.xlsx
│   ├── entity_metrics_*.xlsx
│   ├── coverage_*.xlsx
│   ├── severity_confusion_*.xlsx
│   └── schema_report_*.json
├── aggregated_metrics.xlsx               # mean +- std across runs
└── final_report_*.md                     # single summary with timing and cost
```

Cross-version comparison and confidence intervals come from the aggregators:

```bash
python -m metrics.aggregators.multi_run --root results_runs_v3
python -m metrics.aggregators.bootstrap_ci --root results_runs_v1 results_runs_v2 results_runs_v3 --output bootstrap_ci.xlsx
python -m metrics.aggregators.version_compare --root results_runs_v1 results_runs_v2 results_runs_v3 --output comparison.xlsx
```

## Deduplication

Deduplication is scanner-specific, which is why the flag differs per scanner:

- **OpenVAS**, with `--allow-duplicates`: groups by `(Name, port, protocol)` and
  keeps the most complete record, then runs a fuzzy pass that merges small name
  variations while refusing to merge records whose CVE sets are disjoint.
- **Tenable WAS**, without `--allow-duplicates`: groups by `(Name, plugin)`,
  merging instances and consolidating array fields.

## Results of the previous version

Earlier versions of this tool were evaluated differently: a dataset of 6,700
vulnerabilities extracted from 129 OpenVAS reports, compared against an OpenVAS
CSV baseline through fuzzy matching. Those results (Recall 96.18%, Precision
91.06%, F1 0.9355) belong to that earlier work and are **not** the claims of the
current paper, which measures the V1 -> V2 -> V3 progression described above.
