# 📈 Report Metrics — Reference

Reference for every metric, table and chart that appears in the HTML reports
(`metrics_report_*.html`, `metrics_comparison_*.html`) and PNG paper figures
(`outputs/plots/*.png`). For the methodology behind each family of metrics, see
[metrics.md](../metrics.md). This file is the **what-do-I-see-on-screen**
companion to that one.

> **Audience:** anyone reading a generated report and wondering what a number
> means, what its denominator is, or whether it's the right metric for their
> question. Each entry follows the same template: **what · formula · how to
> read · gotchas**.

---

## 0. Quick reference

| Metric                                | Answers the question                                             | Where it shows up                |
| ------------------------------------- | ---------------------------------------------------------------- | -------------------------------- |
| **F1 (coverage-aware)** (recall × F1) | "How good is this pipeline overall, accounting for what it skips?" | KPI hero · leaderboard · scatter |
| F1 (per-match)                        | "Given a successful match, how good is the per-field score?"     | Quality bars · scatter Y-axis    |
| Recall × F1 scatter (with iso-Eff contours) | "Where does each model sit on the coverage-vs-quality Pareto?" | Quality (normal) · Headline (compare) |
| Precision / Recall                    | "What fraction of what I extract is right? What fraction of the truth do I find?" | Quality bars                     |
| Hallucination rate                    | "How often does the model invent vulnerabilities?"               | Quality scatter · coverage       |
| Omission rate                         | "How often does the model miss real vulnerabilities?"            | Quality scatter · coverage       |
| Per-field hallucination / omission    | "Which field does the model most invent / skip?"                 | Diagnostic heatmaps              |
| Exact Record Match (ERM)              | "Fraction of matched pairs where every deterministic field is exactly right" | KPI hero · leaderboard          |
| Schema (per-field LLM compliance)     | "What fraction of field × record checks pass against the version's own schema?" | KPI · Schema view (compare)      |
| Per-field schema failure breakdown    | "Which specific field is dragging schema compliance down?"       | Schema view table (compare)      |
| JSON validity rate                    | "Does the raw LLM output even parse?"                            | Diagnostic schema bars           |
| Type-coercion breakdown               | "How much downstream cleanup did the LLM force?"                 | Diagnostic stacked bars · §0 cross-version |
| Extra fields rate                     | "Did the LLM invent keys outside the V3 schema?"                 | Diagnostic                       |
| Missing fields top-N                  | "Which schema fields does the LLM most often forget?"            | Diagnostic table                 |
| Severity Macro-F1 (coverage-aware)    | "Does it classify severity correctly, counting omitted records as FN and hallucinations as FP?" | KPI · Diagnostic confusion      |
| BERTScore F1 / ROUGE-L / Token-F1     | "How similar is the extracted text to the baseline text?"        | Drilldown heatmaps               |
| Similarity distribution               | "How does each model's per-vulnerability score break down by bucket?" | Drilldown stacked bars         |
| CV (coefficient of variation)         | "How reproducible is the model across runs?"                     | Consistency table                |
| Δ CV (cross-version)                  | "Did the new pipeline make the LLM more reproducible?"           | Statistics (compare)             |
| Wilcoxon p-value                      | "Is the difference between two models / versions significant?"   | Robustness · Statistics         |
| Missed-vulnerabilities table          | "Which baseline vulns are systematically dropped?"               | Drilldown                        |

---

## 1. F1 (coverage-aware) — the headline

> Internally still called `effective_f1` in the data layer. The label in
> the report was renamed to **F1 (coverage-aware)** to sit next to
> **F1 (per-match)** without jargon — same number, clearer naming.

**What.** A coverage-aware quality score that combines two halves of the
extraction problem into one number.

**Formula.**

```
F1 (coverage-aware) = (1 − omission_rate) × per_match_F1
                    ↑                       ↑
                 recall                conditional F1
                (selection-aware)      ("F1 (per-match)")
```

**How to read.** A model with F1 (coverage-aware) = 0.80 either has very
high recall × moderate per-match quality, or moderate recall × very high
per-match quality. The per-match F1 alone hides the trade-off — a
pipeline that only matches the easy 50% of vulnerabilities will look
near-perfect on F1 (per-match) while leaving half the baseline on the
floor.

**Why it matters.** Per-match F1 is conditioned on a successful match. A
pipeline can game it by being conservative — refusing to align hard
vulnerabilities at all. F1 (coverage-aware) multiplies in the recall
side and prevents the cheating.

**Gotchas.**
- F1 (coverage-aware) is itself the product of two means; it is *not* the
  same as computing F1 over all baseline records (that would be a
  different number).
- A change of −0.01 in F1 (coverage-aware) with +0.10 in recall is a
  *win*: you traded a tiny per-match score drop for a lot more coverage.
- See the **Recall × F1 scatter** (Comparison report) to visualise this trade-off.

**Where it shows up.**
- Regular report: hero KPI card "Best Model — F1 (coverage-aware)", leaderboard column.
- Comparison report: hero KPI per version with Δ, leaderboard wide first column.

---

## 2. Regular report (`metrics_report_*.html`)

### 2.1 Summary view

#### KPI hero (4 cards above the fold)

| Card                          | Value                                    | Source                                    |
| ----------------------------- | ---------------------------------------- | ----------------------------------------- |
| **Best Model — F1 (coverage-aware)** | Highest F1 (coverage-aware) across models | `entity.F1_Score` × `(1 − coverage.omission_rate)` |
| **Schema validity**           | Mean of `schema.schema_conformance_rate` across models, in % | `schema_report_*.json`                     |
| **Severity Macro-F1**         | Mean of `severity.coverage_aware_macro_F1` across models | `severity_confusion_*.xlsx` (cov-aware variant) |
| **Best Exact Record Match**   | Highest `coverage.exact_record_match` across models, in % | `coverage_*.xlsx`                          |

Card colour reflects the qualitative band (excellent / good / fair / weak)
defined in [`themes.METRIC_THRESHOLDS`](../metrics/plot/themes.py).

#### Leaderboard table

One row per model, sorted by F1 (coverage-aware) desc:

| Column              | Definition                                             |
| ------------------- | ------------------------------------------------------ |
| **#**               | Rank by F1 (coverage-aware)                            |
| **Model**           | Model identifier                                       |
| **F1 (coverage-aware)** | Recall × per-match F1 (single number, the headline) |
| **F1 (per-match)**  | `entity.F1_Score` — selection-biased, kept for reference |
| **Schema validity** | `schema_conformance_rate × 100` (%)                    |
| **Severity Macro-F1** | `severity.coverage_aware_macro_F1` (omitted → FN, hallucinated → FP) |
| **Exact Record Match** | `coverage.exact_record_match × 100` (%)             |

A `—` means the metric is not available for that model (no run produced the
corresponding output file).

#### Run-to-run consistency

Per-model variability of `entity.F1_Score` across runs. Models sorted by CV ascending (most stable first):

| Column     | Definition                                              |
| ---------- | ------------------------------------------------------- |
| **Mean F1** | Average F1 across runs                                  |
| **σ**       | Standard deviation across runs                          |
| **CV**      | σ / Mean F1, expressed as %                             |
| **Runs**    | N runs the model has on disk                            |
| **Stability** | Qualitative band — see thresholds below              |

Bands (CV %): `very stable < 2%`, `stable < 5%`, `moderate < 10%`, `unstable ≥ 10%`.

#### Scope panel + How-to-read

Chips listing models / baselines / metric sources discovered, plus a
condensed legend for the other 4 views.

---

### 2.2 Quality view — "which model is best?"

#### Precision · Recall · F1 (grouped bars)

For each model, three bars: P / R / F1 (mean ± σ across runs). Models
sorted by F1 desc. Error bars = σ across runs.

- **P/R/F1** are the standard `entity_metrics_*.xlsx` Summary numbers,
  averaged across fields and targets.
- **σ** here is computed across runs of the same target — small N (≤10),
  treat as ballpark.

#### Hallucination × Omission scatter

x-axis = hallucination rate; y-axis = omission rate. Bottom-left is ideal.
Bubble size scales with N runs.

- **Hallucination rate** = `coverage.hallucination_rate` = fraction of
  cells the model filled where the baseline was empty (over total cells).
- **Omission rate** = `coverage.omission_rate` = fraction of cells the
  model left empty where the baseline had content.
- The diagonal helps spot Pareto-dominated models.

#### Recall × per-match F1 scatter

x-axis = recall (`1 − omission_rate`); y-axis = per-match F1 (`entity.F1_Score`).
**Top-right is ideal.** One labelled point per model.

Dashed grey curves are **iso-Effective-F1 contours** at `Eff = 0.5 / 0.7 / 0.85`
— every point on the same curve has the same Effective F1 (recall × F1).
Two models on the same contour are equally good despite different
recall/F1 trade-offs. Moving up-and-right between contours is real
improvement, not redistribution.

> **Why this matters**: per-match F1 alone is selection-biased — a
> conservative pipeline that skips hard vulns has high F1 by *choosing
> what to measure*. The scatter exposes the trade-off so you can see
> *why* Effective F1 ranks models the way it does. See [metrics.md §4.1](../metrics.md#41-effective-f1--por-que-essa-métrica-existe).

---

### 2.3 Robustness view — "can I trust the numbers?"

#### F1 distribution across runs (boxplot)

For each model, the boxplot of per-run mean F1. Overlaid jitter shows each
individual run. Models ordered by median F1 desc.

- Wider boxes = less reliable scores.
- Outliers worth investigating — usually a "bad run" that hit a corner case.

#### Pairwise Wilcoxon p-value heatmap

Cell `(i, j)` = Bonferroni-adjusted p-value for "model_i F1 differs from
model_j F1" (paired by run).

- **p < 0.05** (after Bonferroni) → significant difference. Coloured cells.
- Diagonal blanked.
- Symmetric matrix.

---

### 2.4 Diagnostic view — "where does it fail?"

The Diagnostic view is divided into 4 sub-sections, each answering a
different "where does the pipeline fail?" question:

#### 2.4.1 Schema fidelity — "is my output canonical?"

Three charts that together answer whether the LLM produces V3-canonical
JSON without downstream cleanup.

##### Schema validity per model (bars)

Bar chart of `schema_conformance_rate` per model, in %. Uses the
**native** check when available (LLM compliance with own version's prompt)
falling back to legacy auto-mode rate. Sorted descending.

> Reading: `100%` = every record passes structural validation;
> low values warrant inspection of `missing_field_counts` (below).

##### JSON validity rate per model (bars)

Bar chart of `json_valid` (0/1 → %), per model. Floor metric: `100%`
expected from any working pipeline. Anything below indicates the LLM
sometimes emits malformed JSON requiring repair downstream.

##### Type-coercion breakdown per model (stacked)

Stacked bar per model. Each segment is one coercion label
(`cvss:list→float`, `plugin_details:list→dict`, `severity:case`,
`port:str→int`) summed across runs.

> **Zero bars = perfectly canonical output** (the LLM honoured the V3
> schema directly). Any non-zero stack means downstream consumers had
> to apply the canonicalizer before consuming the output. See
> [metrics.md §0 + §1](../metrics.md).

#### 2.4.2 Severity confusion (small multiples)

One mini matrix per model. Rows = true class, cols = predicted. Diagonal =
correct classification. Cell value = mean count across runs.

- Reading: **off-diagonal in adjacent cells** (e.g. `MEDIUM ↔ HIGH`) is
  acceptable; **off-diagonal far from diagonal** (e.g. `LOG → CRITICAL`) is
  catastrophic.
- The chart uses small multiples (Tufte) so cross-model comparison is just
  eye saccades between panels.

#### 2.4.3 Schema conformance heatmap (legacy)

`model × field` heatmap of `schema_conformance_rate`. Today schema check
emits one `_overall` field per record, so the heatmap collapses to a 1-column
matrix; once per-field schema validation lands the chart picks it up
automatically. Kept alongside the per-model bars (2.4.1) because the
heatmap form is the natural place for per-field expansion.

#### 2.4.4 Per-field coverage failure surfaces

Three heatmaps, all `field × model`:

##### Per-field F1 heatmap

Heatmap of `entity.F1_Score`. Fields ordered by overall mean desc —
**easiest at top, hardest at bottom**. Helps spot which fields are the
bottleneck (typically `description`, `solution` — free text).

##### Per-field hallucination rate heatmap

Heatmap of `coverage.hallucination_rate` per (model, field). Fields
ordered worst-at-bottom (highest mean rate). Identifies *which* fields
the LLM most commonly invents content for.

##### Per-field omission rate heatmap

Symmetrical: `coverage.omission_rate` per (model, field). Fields the
LLM most commonly skips. Compare with the hallucination heatmap to
see if a model has a systemic bias toward "say something" or "say nothing".

#### 2.4.5 Schema-fidelity diagnostics (per-model breakdown)

Two cards complementing the schema bars (2.4.1):

##### Extra fields rate per model

Bar chart of `schema.extra_fields_rate × 100`. Measures records where
the LLM invented keys outside the V3 schema. **0% expected** from a
compliant pipeline; high values suggest prompt drift or the LLM
hallucinating additional metadata fields.

##### Top-N most-omitted fields (table)

Top 10 schema fields the LLM most frequently failed to emit, summed
across runs. Per row:

| Column | Meaning |
| --- | --- |
| **Field** | Schema field name |
| **Omitted** | Total omission count across all (model, run) pairs |
| **Models affected** | Distinct models that ever omitted this field; many = systemic prompt issue, few = model-specific gap |

---

### 2.5 Drill-down view

#### Text similarity by field — BERTScore · ROUGE-L · Token-F1

Three heatmaps stacked (one per scorer). Each cell = mean score across
runs for one (model, field). A `<select>` lets you switch between
**All baselines (mean)** and a specific baseline.

| Scorer       | What it captures                              | Strict on…    |
| ------------ | --------------------------------------------- | ------------- |
| **BERTScore** | Semantic overlap (lenient on phrasing)       | Meaning       |
| **ROUGE-L**   | Lexical longest common subsequence           | Surface form  |
| **Token-F1**  | SQuAD-style token overlap                    | Tokens, robust to reorder |

Reading three together is informative: if BERT high, ROUGE low → the model
paraphrases correctly; if all low → the content is wrong.

#### Similarity distribution per model

Stacked share of vulnerabilities per similarity bucket (Highly Similar,
Moderately, Slightly, Divergent, Absent). One stack per model, colour-coded
to brand similarity palette. **Non-existent** is excluded from the
denominator (LLM invention is a different failure mode, not a similarity
score). `<select>` switches baselines.

| Bucket             | Threshold (BERTScore F1) |
| ------------------ | ------------------------ |
| Highly Similar     | > 0.70                   |
| Moderately Similar | 0.60–0.70                |
| Slightly Similar   | 0.40–0.60                |
| Divergent          | ≤ 0.40                   |
| Absent             | (in baseline, not extracted) |

Thresholds in [`metrics/pipelines/compare_extractions.py`](../metrics/pipelines/compare_extractions.py) (`_CAT_HIGH/MOD/LOW`).

#### Most-missed vulnerabilities per baseline

Names tagged `Absent` most often. One row per name:

| Column          | Definition                                                  |
| --------------- | ----------------------------------------------------------- |
| **Misses**      | # of (run, model) attempts where this name was Absent       |
| **Miss rate**   | Misses ÷ total (run, model) observations of the baseline    |
| **Models**      | Distinct models that missed it (chips). High count = systemic gap; low count = model-specific |

> One observation per (run, model) — BERT and ROUGE share the same
> alignment so they always agree on what is `Absent`; counting both
> would double the denominator.

---

## 3. Comparison report (`metrics_comparison_*.html`)

Auto-generated when 2+ versions exist (`results_runs_v2/` + `results_runs_v3/`).
Replaces the regular report; same theme.

> **Version order = CLI order.** The order you pass `--root` to
> `metrics.plot.metrics` is preserved end-to-end (no alphabetical sort).
> Convention: **baseline first, canonical last** (e.g. `--root
> results_runs_v2 results_runs`), so Δ reads as `new − old`.

### 3.1 Summary view

#### KPI hero

4 cards, one per headline metric (**F1 (coverage-aware)** comes first,
then Severity Macro-F1 (coverage-aware), Exact Record Match, Schema
(per-field LLM compliance)). Each card shows:

- Mean across models, **per version** (one row per version, in CLI order).
- **Δ** = `last_version − first_version` (= canonical − baseline).
  Positive Δ in green = newer version improved; negative in red = regressed.
- Δ is in absolute units (F1: −0.04) or percentage points (ERM: −25.9pp).
- Hover over the card title for a **tooltip** explaining the metric,
  formula and known gotchas. Available on all 4 KPIs.

> **Dropped from the headline (intentional):**
> - **F1 (per-match)** — it's the Y axis of the Recall × F1 scatter (and
>   visible in the per-model leaderboard rows). Showing it as a KPI
>   created false alarms because its Δ is selection-biased.
> - **Schema (auto/legacy)** — sits near 100% on both versions because
>   the canonicaliser hides LLM bugs. Coercion cost still lives in the
>   **Type-coercion breakdown** chart (Schema view).

> **Critical reminder:** Δ on F1 (per-match) / ERM can be negative even
> when the pipeline genuinely improved, because adding harder matches to
> the pool drags the per-match average down (selection bias). Cross-check
> with Δ on **F1 (coverage-aware)** and **Severity Macro-F1 (coverage-aware)**
> — those are selection-aware (omitted records count as FN).

#### Per-model leaderboard (wide)

Rows = model, columns = (metric × version + Δ). Per metric: one cell per
version, then a Δ column highlighted green/red. Models sorted by
**F1 (coverage-aware) of the canonical (last) version**.

### 3.2 Headline view

#### Coverage trade-off — Recall × per-match F1 (scatter)

The single most important chart of the comparison report.

- One point per (model, version). Colour by model; shape per version
  (triangle = first, circle = last).
- **Arrows connect the same model across versions** (V2 → V3) — visualises
  the Pareto move.
- **Iso-Effective-F1 contours** (dashed lines at eff = 0.5 / 0.7 / 0.85):
  every point on a contour has the same Effective F1.
- **Ideal corner**: top-right (high recall + high per-match F1).

How to read:
- Arrow ↗ (right + up) — improvement on both axes.
- Arrow ↘ (right + down, crossing toward higher iso-contour) — typical
  V2 → V3 move when the new pipeline matches harder vulns. Net positive
  on Effective F1.
- Arrow ↖ (left + up) — regression, pipeline became more selective with
  no quality gain.

#### Headline grouped bars (4 panels)

For each headline metric, one bar per (model, version). Drill-down view
of where the version delta lives — uniform across models or concentrated
on a few.

### 3.3 Schema view

#### Type-coercion breakdown (stacked)

Per model, two adjacent stacked bars (one per version). Each stack
breaks down by coercion label:

- `cvss:list→float` — V2 stored cvss as `["10.0"]`, V3 stores `10.0`
- `plugin_details:list→dict` — V2 emitted wrong type
- `severity:case` — `"High"` → `"HIGH"` (LLM bug, not pipeline)
- `port:str→int` — `"443"` → `443`

Source: raw `schema_report_*.json` files (the agg sheet only carries
the aggregate `type_coercion_rate`).

#### JSON validity rate per model

Grouped bars: per model, one bar per version, value = % of runs that
produced parseable JSON.

#### Per-field failure rate — version-native schema (table)

Surfaces *which* field is dragging down the per-field LLM compliance KPI.
Rows = schema field; columns = `version · model`. Cell = fraction of
records where that field violated the version-native schema (missing OR
wrong type). Sourced from `field_failure_counts` in `schema_report*.json`
(native block). Field rows sorted with the worst offenders first.

Cell colours: red ≥ 50%, amber ≥ 5%, green > 0%, dot (·) = 0%.

> **Interpretation.** A field at 100% means the LLM emitted the wrong
> type for it on *every single record* — e.g. V2's `plugin_details` as
> list when the prompt asked for dict. This is the transparency layer
> behind the per-field KPI: a soft KPI of 94% looks fine in isolation,
> but the breakdown reveals "94% because 1 of 17 fields is fully broken".

### 3.4 Similarity view

Single canvas showing per-baseline similarity stacks, with:

- **Baseline `<select>`** — switches the baseline being shown.
- **BERT/ROUGE toggle** — segmented control (orange).
- **V2 / V3 grouped per model** — each model has 2 adjacent stacks (one
  per version) using the brand similarity palette.
- Tooltip shows `model · version → category: x%`.

Same exclusions as the regular report (`Non-existent` not counted).

### 3.5 Statistics view

Two tables: one for **per-model paired test of F1**, one for
**per-model reproducibility shift (Δ CV)**.

#### Paired Wilcoxon (F1)

V2 vs V3 per model, on F1_Score paired by `(target, run)`:

| Column            | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| **p (Bonferroni)** | Adjusted p-value across the model family                |
| **Significant?**  | `yes` if p < 0.05 after correction (highlighted green)  |
| **Δ direction**   | `mean(V3) − mean(V2)` — sign tells which is better      |

Read together: a model with significant p AND positive Δ went up reliably.
Significant p AND negative Δ went down reliably. Non-significant means
"can't tell from this many runs".

#### Δ CV per model — reproducibility shift

CV (= σ/μ on F1 across runs) compared between versions. Per row:

| Column           | Meaning                                                |
| ---------------- | ------------------------------------------------------ |
| **CV V2** / **CV V3** | Reproducibility per version, in % |
| **Δ CV**         | `CV(V3) − CV(V2)`. **Negative = improvement** (canonical version is more reproducible). Highlighted green when negative. |

Maps loosely to the qualitative bands in [metrics.md §5.1](../metrics.md#51-bandas-qualitativas-de-cv): a Δ < −2pp is meaningful tightening, > +2pp is loosening.

---

## 4. PNG outputs (`outputs/plots/*.png`)

PNGs are the paper-figure twins of HTML charts. Light background, Nord-aware
sequential ramp, tradicional similarity palette. One PNG per chart logical
unit. Generated by `metrics.plot.png` in the same `outputs/plots/` directory
as the HTML.

### Single-version (always exported)

| File                          | What                                                         |
| ----------------------------- | ------------------------------------------------------------ |
| `quality_prf.png`             | P/R/F1 grouped bars                                          |
| `quality_halluc.png`          | Hallucination × Omission scatter                             |
| `quality_recall_f1.png`       | Recall × per-match F1 scatter with iso-Effective-F1 contours |
| `robust_f1_box.png`           | F1 distribution boxplot across runs                          |
| `robust_wilcoxon.png`         | Pairwise model-vs-model Wilcoxon p-value heatmap             |
| `diag_schema.png`             | Schema conformance heatmap (legacy 1-column form)            |
| `diag_schema_validity.png`    | Schema validity per model (bar)                              |
| `diag_json_validity.png`      | JSON validity rate per model (bar)                           |
| `diag_type_coercion.png`      | Type-coercion breakdown per model (stacked)                  |
| `diag_severity.png`           | Severity confusion small multiples (one panel per model)     |
| `diag_field_coverage.png`     | Per-field F1 heatmap (field × model)                         |
| `diag_field_halluc.png`       | Per-field hallucination rate heatmap                         |
| `diag_field_omiss.png`        | Per-field omission rate heatmap                              |
| `drill_text_per_field.png`    | BERT / ROUGE / Token-F1 heatmaps side by side                |
| `stacked_similarity_bert.png` | Similarity distribution stacked, BERTScore (legacy palette + hatches per baseline) |
| `stacked_similarity_rouge.png`| Same, ROUGE-L                                                |

**Diagnostic-only (HTML, no PNG)** — pure tables/diagnostics that don't
make sense as static figures:

- Extra fields rate per model (HTML bar, no PNG twin)
- Top-N most-omitted fields (HTML table)
- Most-missed vulnerabilities per baseline (HTML table)
- Run-to-run consistency (CV) (HTML table)

### Versioning §0 (only when 2+ versions present)

| File                          | What                                                         |
| ----------------------------- | ------------------------------------------------------------ |
| `version_headline.png`        | 4 panels (F1, Severity Macro-F1, ERM, Schema validity), V2 vs V3 grouped per model |
| `version_type_coercion.png`   | Stacked coercion breakdown, V2 vs V3 adjacent per model      |
| `version_json_validity.png`   | JSON validity %, V2 vs V3 grouped per model                  |
| `version_similarity.png`      | Similarity distribution, BERT and ROUGE side by side, hatched per version |

### PNG vs HTML — intentional palette divergence

| Token                   | HTML (dark bg)        | PNG (white bg)        |
| ----------------------- | --------------------- | --------------------- |
| `MODEL_PALETTE`         | shared                | shared                |
| `STATUS`                | shared                | shared                |
| `SEQUENTIAL_STOPS`      | dark indigo→cyan ramp | (not used)            |
| `SEQUENTIAL_STOPS_LIGHT` | (not used)           | off-white→navy ramp   |
| `SIMILARITY_COLORS`     | neon brand-tone       | legacy paper palette  |

The PNG override of `SIMILARITY_COLORS` is documented inside
[`metrics/plot/png.py`](../metrics/plot/png.py) — kept distinct because
the HTML neon variant is too saturated for print.

---

## 5. Cross-references

- **Methodology rationale (why each metric exists)** —
  [metrics.md §1–§6](../metrics.md).
- **Effective F1 derivation + selection-bias caveat** —
  [metrics.md §4.1](../metrics.md#41-effective-f1--por-que-essa-métrica-existe).
- **CV bands for reproducibility** —
  [metrics.md §5.1](../metrics.md#51-bandas-qualitativas-de-cv).
- **Where each chart belongs (normal vs comparison)** —
  [metrics.md "Guia de visualização"](../metrics.md#-guia-de-visualização--qual-report-carrega-qual-métrica).
  This is the **single source of truth** for division of labour between
  the two reports — consult it before adding/moving any chart.
- **Pipeline that produces the per-run XLSX/JSON files the reports read** —
  [metrics/pipelines/](../metrics/pipelines/).
- **Aggregator that flattens runs into `aggregated_metrics.xlsx`** —
  [metrics/aggregators/multi_run.py](../metrics/aggregators/multi_run.py).
- **Where to change a chart's colours** —
  [metrics/plot/themes.py](../metrics/plot/themes.py).
- **Where to add a new chart**:
  1. Pure data extractor → new function in [metrics/plot/charts/](../metrics/plot/charts/) (`quality.py` for Quality view, `diagnostic.py` for Diagnostic, `comparison.py` for cross-version, etc.)
  2. Wire into [metrics/plot/report.py](../metrics/plot/report.py) (regular) or [metrics/plot/comparison_report.py](../metrics/plot/comparison_report.py) (compare) `chart_data` dict.
  3. Card + canvas in the corresponding `templates/*.jinja2` view.
  4. JS render block (Chart.js native or `renderHeatmap` for CSS-grid heatmaps).
  5. Optionally a matplotlib renderer in [metrics/plot/png.py](../metrics/plot/png.py) + entry in `export_all`'s plan list.
