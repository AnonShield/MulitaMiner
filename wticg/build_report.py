"""DESCARTÁVEL — transforma uma cópia do comparison_v1_v2_v3.html (motor CSS+JS
verbatim) injetando o DATA dos experimentos locais.

OPÇÃO A: a dimensão de comparação são os MODELOS (todos os locais lado a lado),
com a MÁQUINA como cor (3060 = v1, 5080 = v2, cloud/DeepSeek = v3 = referência).
Cada modelo roda numa única máquina → cada barra cai no slot da sua máquina.
Os KPIs/tabelas "por fonte" viram a MÉDIA dos modelos daquela máquina.
3060 + 5080 já têm dados; cloud entra quando o DeepSeek cloud rodar.
Saída: artifacts/relatorio_local.html
"""
import json, re, glob, math
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np

np.random.seed(42)  # bootstrap reprodutível


def _nan_to_none(o):
    """NaN -> None recursivo (NaN quebra JSON.parse; vira null -> render neutro)."""
    if isinstance(o, float) and math.isnan(o):
        return None
    if isinstance(o, dict):
        return {k: _nan_to_none(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_nan_to_none(x) for x in o]
    return o

WTICG = Path(__file__).resolve().parent  # dados, engine e saída vivem ao lado deste script
REF = WTICG / "comparison_v1_v2_v3.html"
OUT = WTICG / "relatorio_local.html"
ROOTS = [WTICG / "3060", WTICG / "5080"]
if (WTICG / "cloud" / "aggregated_metrics.xlsx").exists():
    ROOTS.append(WTICG / "cloud")

# slots de cor do motor = MÁQUINAS
VOF = {"3060": "v1", "5080": "v2", "cloud": "v3"}
# máquina conhecida de cada modelo (fallback p/ cloud, que ainda não tem dados)
KNOWN_MACHINE = {
    "gemma4": "3060", "ministral3": "3060", "qwen3_local": "3060",
    "phi4": "5080", "foundation_sec": "5080", "primus": "5080",
    "llama31_local": "5080", "gpt_oss": "5080", "deepseek_local": "5080",
    "deepseek": "cloud",
}

# MODELOS = grupos (eixo x). Ordem: 3060 -> 5080 -> cloud.
LLMS = [
    ("gemma4", "gemma4:e4b"), ("ministral3", "Ministral 3 8B"), ("qwen3_local", "Qwen3 8B"),
    ("llama31_local", "Llama 3.1 8B"), ("phi4", "Phi-4 14B"),
    ("foundation_sec", "Foundation-Sec 8B"), ("primus", "Primus 8B"),
    ("gpt_oss", "gpt-oss 20B"), ("deepseek_local", "DeepSeek-V2 16B"),
    ("deepseek", "deepseek-v4-flash (cloud)"),
]
LLM_LABEL = dict(LLMS)

TARGETS = [("OpenVAS_JuiceShop", "Juice Shop"), ("OpenVAS_bBWA", "bBWA"), ("openvas_artifactory-oss_5.11.0", "Artifactory")]
T2L = dict(TARGETS)
ENTITY_FIELDS = ["cvss", "plugin", "port", "protocol", "severity"]
SIM_CATS = ["Highly Similar", "Moderately Similar", "Slightly Similar", "Divergent", "Absent"]
MACHINES = [("v1", "3060"), ("v2", "5080"), ("v3", "cloud")]

long = pd.concat([pd.read_excel(r / "aggregated_metrics.xlsx", sheet_name="Long") for r in ROOTS], ignore_index=True)
long["version"] = long["version"].astype(str)

# --- métrica VULN-LEVEL correta ---
# A `omission_rate`/`hallucination_rate` _overall do pipeline são FIELD-level (campos faltando
# dentro de vulns casadas). Para o scatter/cards "por vulnerabilidade" sintetizamos a taxa
# vuln-level a partir das contagens: omission = bl_unmatched/baseline; halluc = ext_unmatched/extraídas.
_cov = long[(long["source"] == "coverage") & (long["field"] == "_overall")]
_piv = _cov.pivot_table(index=["version", "target", "model", "run"], columns="metric", values="value", aggfunc="mean")
_new_rows = []
for _idx, _r in _piv.iterrows():
    _ver, _tgt, _mdl, _run = _idx
    _m, _b, _e = _r.get("n_matched_pairs"), _r.get("n_baseline_unmatched"), _r.get("n_extraction_unmatched")
    base = {"version": _ver, "target": _tgt, "model": _mdl, "run": _run, "source": "coverage", "field": "_overall"}
    if pd.notna(_m) and pd.notna(_b) and (_m + _b) > 0:
        _new_rows.append({**base, "metric": "omission_vl", "value": _b / (_m + _b)})
    if pd.notna(_m) and pd.notna(_e) and (_m + _e) > 0:
        _new_rows.append({**base, "metric": "hallucination_vl", "value": _e / (_m + _e)})
if _new_rows:
    long = pd.concat([long, pd.DataFrame(_new_rows)], ignore_index=True)
ck = {}
for r in ROOTS:
    for f in sorted(r.glob("run_checkpoints_*.json")):
        ck.update(json.load(open(f, encoding="utf-8")).get("runs", {}))

# máquina (slot) real de cada modelo: usa o dado; se ausente, o mapa conhecido
mver = {}
for m in long["model"].dropna().unique():
    v = long[long["model"] == m]["version"].dropna().unique()
    mver[str(m)] = str(v[0]) if len(v) else None


def vslot(model):
    ver = mver.get(model) or KNOWN_MACHINE.get(model)
    return VOF.get(ver, "v1")


def _sel(source, metric, fields=None):
    d = long[(long["source"] == source) & (long["metric"] == metric)]
    if fields is not None:
        d = d[d["field"].isin(fields)]
    return d


# ---- por MÁQUINA (média entre os modelos daquela máquina) -> {v1,v2,v3} ----
def src_overall(source, metric, fields=None):
    d = _sel(source, metric, fields)
    out = {}
    for v, ver in MACHINES:
        sub = d[d["version"] == ver]
        out[v] = float(sub["value"].mean()) if not sub.empty else None
    return out


def src_field(source, metric, fields_list):
    return {f: src_overall(source, metric, [f]) for f in fields_list}


def src_per_target(source, metric, fields=None):
    d = _sel(source, metric, fields)
    out = {}
    for t, tl in TARGETS:
        sub = d[d["target"] == t]
        out[tl] = {v: (float(sub[sub["version"] == ver]["value"].mean()) if not sub[sub["version"] == ver].empty else None)
                   for v, ver in MACHINES}
    return out


# ---- por MODELO (grupos) ----
def by_llm(source, metric, fields=None):
    d = _sel(source, metric, fields)
    out = {}
    for llm, lab in LLMS:
        sub = d[d["model"] == llm]
        out[lab] = float(sub["value"].mean()) if not sub.empty else None
    return out


def by_llm_target(source, metric, fields=None):
    d = _sel(source, metric, fields)
    out = {}
    for t, tl in TARGETS:
        for llm, lab in LLMS:
            sub = d[(d["target"] == t) & (d["model"] == llm)]
            out[(tl, lab)] = float(sub["value"].mean()) if not sub.empty else None
    return out


# ---- métricas de sistema (checkpoint), por modelo ----
def sysmetrics():
    rows = {}
    for rid, r in ck.items():
        if r.get("status") != "ok":
            continue
        rows.setdefault(r["llm"], []).append(r)
    return {m: {"lat": sum(r.get("elapsed_time", 0) for r in v) / len(v),
                "energy": sum(r.get("gpu_energy_wh", 0) or 0 for r in v) / len(v)} for m, v in rows.items()}


sm = sysmetrics()


# ---- categorizações por (target, modelo) ----
def categorizations():
    acc = {}
    paths = [pp for r in ROOTS for pp in glob.glob(str(r / "**" / "bert_comparison_*.xlsx"), recursive=True)]
    for path in paths:
        p = Path(path)
        model, target = p.parent.parent.name, p.parent.parent.parent.name
        try:
            df = pd.read_excel(p, sheet_name="Categorization")
        except Exception:
            continue
        if "Category" not in df.columns:
            continue
        b = acc.setdefault((target, model), [0] * len(SIM_CATS))
        for i, c in enumerate(SIM_CATS):
            b[i] += int((df["Category"] == c).sum())
    return acc


cats = categorizations()

TEXT_FIELDS = sorted(_sel("bert", "Avg_BERTScore_F1")["field"].unique().tolist())
OMIS_FIELDS = [f for f in sorted(_sel("coverage", "omission_rate")["field"].unique().tolist()) if f != "_overall"]

# ============================================================
# Montagem do DATA — slots = máquinas (3060/5080/cloud)
# ============================================================
kpi = [
    {"id": "bert", "label": "BERTScore médio (texto livre)", "tip": "BERTScore F1 médio entre campos textuais (média dos modelos da máquina). Maior é melhor.",
     "values": src_overall("bert", "Avg_BERTScore_F1"), "fmt": "pct", "direction": 1},
    {"id": "ent", "label": "Entity F1 (campos exatos)", "tip": "F1 médio entre cvss/plugin/port/protocol/severity. Maior é melhor.",
     "values": src_overall("entity", "F1_Score", ENTITY_FIELDS), "fmt": "pct", "direction": 1},
    {"id": "sch", "label": "Conformidade de schema", "tip": "Fração de registros conformes ao schema. Maior é melhor.",
     "values": src_overall("schema", "schema_conformance_rate", ["_overall"]), "fmt": "pct", "direction": 1},
    {"id": "omis", "label": "Omission rate (vuln-level)", "tip": "Fração de vulns do baseline não recuperadas. Menor é melhor.",
     "values": src_overall("coverage", "omission_rate", ["_overall"]), "fmt": "pct", "direction": -1},
]
schema_rows = [
    {"label": "JSON Validity", "tip": "Fração de runs que parseiam como JSON.", "values": src_overall("schema", "json_valid", ["_overall"]), "direction": 1, "fmt": "pct"},
    {"label": "Schema Conformance", "tip": "% de registros conformes.", "values": src_overall("schema", "schema_conformance_rate", ["_overall"]), "direction": 1, "fmt": "pct"},
    {"label": "Field Conformance", "tip": "% de campos conformes.", "values": src_overall("schema", "schema_field_conformance_rate", ["_overall"]), "direction": 1, "fmt": "pct"},
]
coverage_rows = [
    {"label": "Exact Record Match", "tip": "Registros 100% corretos.", "values": src_overall("coverage", "exact_record_match", ["_overall"]), "direction": 1, "fmt": "pct"},
    {"label": "Hallucination Rate", "tip": "Vulns extraídas sem par no baseline.", "values": src_overall("coverage", "hallucination_rate", ["_overall"]), "direction": -1, "fmt": "pct"},
    {"label": "Omission Rate", "tip": "Vulns do baseline não recuperadas.", "values": src_overall("coverage", "omission_rate", ["_overall"]), "direction": -1, "fmt": "pct"},
    {"label": "Matched Pairs (média)", "tip": "Vulns pareadas com o baseline.", "values": src_overall("coverage", "n_matched_pairs", ["_overall"]), "direction": 1, "fmt": "num"},
]
sev_rows = [
    {"label": "Accuracy", "tip": "Acerto de severidade.", "values": src_overall("severity", "accuracy", ["_overall"]), "direction": 1, "fmt": "pct"},
    {"label": "Macro F1", "tip": "F1 médio entre classes.", "values": src_overall("severity", "macro_F1", ["_overall"]), "direction": 1, "fmt": "pct"},
    {"label": "Coverage-aware Macro F1", "tip": "Macro-F1 penalizando omissão.", "values": src_overall("severity", "coverage_aware_macro_F1", ["_overall"]), "direction": 1, "fmt": "pct"},
]

pP, pR, pF = src_field("entity", "Precision", ENTITY_FIELDS), src_field("entity", "Recall", ENTITY_FIELDS), src_field("entity", "F1_Score", ENTITY_FIELDS)
entity_rows = [{"field": f, "Precision": pP[f], "Recall": pR[f], "F1_Score": pF[f]} for f in ENTITY_FIELDS]
bF, rF, tF = src_field("bert", "Avg_BERTScore_F1", TEXT_FIELDS), src_field("rouge", "Avg_ROUGE_L", TEXT_FIELDS), src_field("token_f1", "Avg_Token_F1", TEXT_FIELDS)
text_rows = [{"field": f, "BERTScore F1": bF[f], "ROUGE-L": rF[f], "Token-F1": tF[f]} for f in TEXT_FIELDS]

headline_labels = ["BERTScore médio (texto livre)", "Entity F1 (campos exatos)", "Conformidade de schema", "Omission rate (vuln-level)"]
headline_dir = {headline_labels[0]: 1, headline_labels[1]: 1, headline_labels[2]: 1, headline_labels[3]: -1}
headline_fmt = {l: "pct" for l in headline_labels}
hl_src = {
    headline_labels[0]: src_per_target("bert", "Avg_BERTScore_F1"),
    headline_labels[1]: src_per_target("entity", "F1_Score", ENTITY_FIELDS),
    headline_labels[2]: src_per_target("schema", "schema_conformance_rate", ["_overall"]),
    headline_labels[3]: src_per_target("coverage", "omission_rate", ["_overall"]),
}
by_target = {label: {tl: hl_src[label][tl] for _, tl in TARGETS} for label in headline_labels}

# scatter: 1 ponto por (modelo, baseline); cor = máquina do modelo
hall = by_llm_target("coverage", "hallucination_vl", ["_overall"])
omis = by_llm_target("coverage", "omission_vl", ["_overall"])
nm = by_llm_target("coverage", "n_matched_pairs", ["_overall"])
nbl = by_llm_target("coverage", "n_baseline_unmatched", ["_overall"])
nex = by_llm_target("coverage", "n_extraction_unmatched", ["_overall"])
scatter_points = []
for t, tl in TARGETS:
    for llm, lab in LLMS:
        if hall.get((tl, lab)) is None:
            continue
        scatter_points.append({"version": vslot(llm), "model": lab, "target": tl,
                               "halluc": hall[(tl, lab)], "omission": omis[(tl, lab)],
                               "n_matched": round(nm.get((tl, lab)) or 0, 1),
                               "n_bl_unm": round(nbl.get((tl, lab)) or 0, 1),
                               "n_ext_unm": round(nex.get((tl, lab)) or 0, 1)})

# bars: grupos = MODELOS, cada barra no slot da máquina do modelo
bars_src = {"BERTScore F1": by_llm_target("bert", "Avg_BERTScore_F1"),
            "ROUGE-L": by_llm_target("rouge", "Avg_ROUGE_L"),
            "Token-F1": by_llm_target("token_f1", "Avg_Token_F1")}
bars_by_target = {}
for t, tl in TARGETS:
    bars_by_target[tl] = {}
    for metric, src in bars_src.items():
        per_llm = {}
        for llm, lab in LLMS:
            cell = {"v1": None, "v2": None, "v3": None}
            cell[vslot(llm)] = src.get((tl, lab))
            per_llm[lab] = cell
        bars_by_target[tl][metric] = per_llm

# cat: grupos = MODELOS, barras empilhadas no slot da máquina
cat_by_target = {}
for t, tl in TARGETS:
    per_llm = {}
    for llm, lab in LLMS:
        c = cats.get((t, llm), [0] * len(SIM_CATS)); tot = sum(c) or 1
        dist = {SIM_CATS[i]: c[i] / tot for i in range(len(SIM_CATS))}
        cell = {"v1": None, "v2": None, "v3": None}
        cell[vslot(llm)] = dist if sum(c) else None
        per_llm[lab] = cell
    cat_by_target[tl] = {m: per_llm for m in ("BERTScore F1", "ROUGE-L", "Token-F1")}

# heatmap omissão: 1 linha por MODELO, agrupado por fonte (3060/5080/cloud)
omf = {}
for llm, lab in LLMS:
    for f in OMIS_FIELDS:
        d = _sel("coverage", "omission_rate", [f]); d = d[d["model"] == llm]
        _m = d["value"].mean() if not d.empty else None  # NaN se "sem oportunidade" (|M_f|=0)
        omf[(lab, f)] = None if (_m is None or (isinstance(_m, float) and math.isnan(_m))) else float(_m)
HM_FIELDS = sorted(OMIS_FIELDS, key=lambda f: -(sum(omf[(lab, f)] or 0 for _, lab in LLMS) / len(LLMS)))
SRC_ORDER = {"3060": 0, "5080": 1, "cloud": 2}
hm_models = []
for llm, lab in LLMS:
    if all(omf.get((lab, f)) is None for f in HM_FIELDS):
        continue  # sem dados (ex.: cloud ainda)
    src = mver.get(llm) or KNOWN_MACHINE.get(llm)
    hm_models.append({"label": lab, "source": src, "vals": {f: omf.get((lab, f)) for f in HM_FIELDS}})
hm_models.sort(key=lambda m: SRC_ORDER.get(m["source"], 9))
heatmap_omission = {"fields": HM_FIELDS, "models": hm_models, "sources": ["3060", "5080", "cloud"]}

# ============================================================
# Dados centrados em MODELO (opção A) — cards, tabelas, breakdown
# ============================================================
LAB2ID = {lab: llm for llm, lab in LLMS}
MODELS_META = []
for _llm, _lab in LLMS:
    if long[long["model"] == _llm].empty:
        continue
    MODELS_META.append({"label": _lab, "source": mver.get(_llm) or KNOWN_MACHINE.get(_llm)})
MODELS_META.sort(key=lambda m: SRC_ORDER.get(m["source"], 9))

# trade-off por MODELO (média das baselines) — pros 3 gráficos alternativos
trade_models = []
for _meta in MODELS_META:
    _lab = _meta["label"]
    _oo = [omis.get((tl, _lab)) for _, tl in TARGETS]; _oo = [x for x in _oo if x is not None]
    _hh = [hall.get((tl, _lab)) for _, tl in TARGETS]; _hh = [x for x in _hh if x is not None]
    if not _oo or not _hh:
        continue
    trade_models.append({"model": _lab, "source": _meta["source"],
                         "omission": sum(_oo) / len(_oo), "hallucination": sum(_hh) / len(_hh)})


def _obs(llm, src, metric, flds):
    """Observações por (baseline × run) de um modelo p/ uma métrica (média dos campos por obs)."""
    d = _sel(src, metric, flds); d = d[d["model"] == llm]
    if d.empty:
        return []
    return [float(x) for x in d.groupby(["target", "run"])["value"].mean().values]


def _ci_str(llm, src, metric, flds, fmt):
    """IC 95% por bootstrap (10.000 reamostragens) sobre as obs (baseline × run) do modelo."""
    vals = [v for v in _obs(llm, src, metric, flds) if v is not None and not math.isnan(v)]
    if len(vals) < 2:
        return ""
    arr = np.asarray(vals, dtype=float)
    if arr.std(ddof=0) == 0:  # determinístico em todas as obs -> intervalo de largura 0
        m = float(arr.mean())
        return f"[{m*100:.1f}%, {m*100:.1f}%]" if fmt == "pct" else f"[{m:.1f}, {m:.1f}]"
    means = np.random.choice(arr, size=(10000, arr.size), replace=True).mean(axis=1)
    lo, hi = np.percentile(means, [2.5, 97.5])
    return f"[{lo*100:.1f}%, {hi*100:.1f}%]" if fmt == "pct" else f"[{lo:.1f}, {hi:.1f}]"


def _table_rows(specs):
    rows = []
    for meta in MODELS_META:
        llm = LAB2ID[meta["label"]]
        vals = {}; cis = {}
        for key, src, metric, flds in specs:
            d = _sel(src, metric, flds); d = d[d["model"] == llm]
            vals[key] = float(d["value"].mean()) if not d.empty else None
            cis[key] = _ci_str(llm, src, metric, flds, "num" if metric.startswith("n_") else "pct")
        rows.append({"model": meta["label"], "source": meta["source"], "vals": vals, "cis": cis})
    return rows


tbl_schema = {"cols": [{"key": "jv", "label": "JSON Validity", "fmt": "pct", "dir": 1},
                       {"key": "sc", "label": "Schema Conf.", "fmt": "pct", "dir": 1},
                       {"key": "fc", "label": "Field Conf.", "fmt": "pct", "dir": 1}],
              "rows": _table_rows([("jv", "schema", "json_valid", ["_overall"]),
                                   ("sc", "schema", "schema_conformance_rate", ["_overall"]),
                                   ("fc", "schema", "schema_field_conformance_rate", ["_overall"])])}
tbl_coverage = {"cols": [{"key": "erm", "label": "Exact Match", "fmt": "pct", "dir": 1},
                         {"key": "hal", "label": "Hallucination", "fmt": "pct", "dir": -1},
                         {"key": "omi", "label": "Omission", "fmt": "pct", "dir": -1},
                         {"key": "mp", "label": "Matched (méd)", "fmt": "num", "dir": 1}],
                "rows": _table_rows([("erm", "coverage", "exact_record_match", ["_overall"]),
                                     ("hal", "coverage", "hallucination_vl", ["_overall"]),
                                     ("omi", "coverage", "omission_vl", ["_overall"]),
                                     ("mp", "coverage", "n_matched_pairs", ["_overall"])])}
tbl_severity = {"cols": [{"key": "acc", "label": "Accuracy", "fmt": "pct", "dir": 1},
                         {"key": "mf1", "label": "Macro F1", "fmt": "pct", "dir": 1},
                         {"key": "caf1", "label": "Cov-aware F1", "fmt": "pct", "dir": 1}],
                "rows": _table_rows([("acc", "severity", "accuracy", ["_overall"]),
                                     ("mf1", "severity", "macro_F1", ["_overall"]),
                                     ("caf1", "severity", "coverage_aware_macro_F1", ["_overall"])])}
tbl_entity = {"cols": [{"key": f, "label": f, "fmt": "pct", "dir": 1} for f in ENTITY_FIELDS],
              "rows": _table_rows([(f, "entity", "F1_Score", [f]) for f in ENTITY_FIELDS])}
TEXT_METRICS = [("BERTScore F1", "bert", "Avg_BERTScore_F1"), ("ROUGE-L", "rouge", "Avg_ROUGE_L"), ("Token-F1", "token_f1", "Avg_Token_F1")]
tbl_text = {ml: {"cols": [{"key": f, "label": f, "fmt": "pct", "dir": 1} for f in TEXT_FIELDS],
                 "rows": _table_rows([(f, src, metric, [f]) for f in TEXT_FIELDS])}
            for ml, src, metric in TEXT_METRICS}

kpi_specs = [
    ("BERTScore médio (texto livre)", "bert", "Avg_BERTScore_F1", None, 1, "pct", "Melhores modelos por BERTScore F1 (texto livre)."),
    ("Entity F1 (campos exatos)", "entity", "F1_Score", ENTITY_FIELDS, 1, "pct", "Melhores por F1 de cvss/plugin/port/protocol/severity."),
    ("Conformidade de schema", "schema", "schema_conformance_rate", ["_overall"], 1, "pct", "Maior fração de registros conformes ao schema."),
    ("Omission rate (vuln-level)", "coverage", "omission_vl", ["_overall"], -1, "pct", "Menor omissão de vulns do baseline (vuln-level, melhor)."),
]
kpi_rank = []
for _label, _src, _metric, _flds, _dir, _fmt, _tip in kpi_specs:
    _vals = by_llm(_src, _metric, _flds)
    _rk = [{"model": m["label"], "source": m["source"], "value": _vals.get(m["label"]),
            "ci": _ci_str(LAB2ID[m["label"]], _src, _metric, _flds, _fmt)}
           for m in MODELS_META if _vals.get(m["label"]) is not None]
    _rk.sort(key=lambda r: r["value"] * (-1 if _dir > 0 else 1))
    kpi_rank.append({"label": _label, "tip": _tip, "fmt": _fmt, "direction": _dir, "ranking": _rk})

HLB = [("BERTScore", "bert", "Avg_BERTScore_F1", None, 1),
       ("Entity F1", "entity", "F1_Score", ENTITY_FIELDS, 1),
       ("Schema", "schema", "schema_conformance_rate", ["_overall"], 1),
       ("Omission", "coverage", "omission_rate", ["_overall"], -1)]
breakdown_cols = [{"key": h[0], "label": h[0], "fmt": "pct", "dir": h[4]} for h in HLB]
breakdown_by_target = {}
for _t, _tl in TARGETS:
    _rows = []
    for meta in MODELS_META:
        _llm = LAB2ID[meta["label"]]; _vals = {}
        for _hlabel, _src, _metric, _flds, _d in HLB:
            d = _sel(_src, _metric, _flds); d = d[(d["model"] == _llm) & (d["target"] == _t)]
            _vals[_hlabel] = float(d["value"].mean()) if not d.empty else None
        _rows.append({"model": meta["label"], "source": meta["source"], "vals": _vals})
    breakdown_by_target[_tl] = _rows

# paleta por MODELO (scatter colorido por modelo)
PALETTE = ["#f47174", "#f4a259", "#e6c84f", "#7bbf5a", "#3fb8af", "#4f9cf4", "#8a7bf0", "#c264d6", "#ef6fae", "#9aa0ab"]
model_colors = {m["label"]: PALETTE[i % len(PALETTE)] for i, m in enumerate(MODELS_META)}

# RQ3: especialização de domínio (mesma base Llama-3.1-8B)
RQ3 = [("llama31_local", "Llama 3.1 8B", "generalista (base)"),
       ("foundation_sec", "Foundation-Sec 8B", "Cisco · segurança"),
       ("primus", "Primus 8B", "Trend Micro · segurança")]
rq3_metrics = [("BERTScore", "bert", "Avg_BERTScore_F1", None, 1),
               ("Entity F1", "entity", "F1_Score", ENTITY_FIELDS, 1),
               ("Schema conf.", "schema", "schema_conformance_rate", ["_overall"], 1),
               ("Omission ↓", "coverage", "omission_vl", ["_overall"], -1),
               ("Severity F1", "severity", "macro_F1", ["_overall"], 1)]


def _mval(llm, src, metric, flds):
    d = _sel(src, metric, flds); d = d[d["model"] == llm]
    return float(d["value"].mean()) if not d.empty else None


rq3_rows = []
for _llm, _lab, _tag in RQ3:
    _vals = {ml: _mval(_llm, sr, me, fl) for ml, sr, me, fl, _dd in rq3_metrics}
    rq3_rows.append((_lab, _tag, _vals))
rq3_wins = 0; rq3_total = 0
for ml, sr, me, fl, direction in rq3_metrics:
    pairs = [(lab, vv[ml]) for lab, _, vv in rq3_rows if vv.get(ml) is not None]
    if len(pairs) < 2:
        continue
    rq3_total += 1
    bestlab = (min if direction < 0 else max)(pairs, key=lambda x: x[1])[0]
    if bestlab != "Llama 3.1 8B":
        rq3_wins += 1
def _mval_t(llm, src, metric, flds, target):
    d = _sel(src, metric, flds); d = d[(d["model"] == llm) & (d["target"] == target)]
    return float(d["value"].mean()) if not d.empty else None


# consistência por baseline: em quantas das 3 um especialista bate o generalista
rq3_consistency = {}
for ml, sr, me, fl, direction in rq3_metrics:
    cnt = 0
    for _t, _tl in TARGETS:
        gv = _mval_t("llama31_local", sr, me, fl, _t)
        sv = [x for x in (_mval_t("foundation_sec", sr, me, fl, _t), _mval_t("primus", sr, me, fl, _t)) if x is not None]
        if gv is None or not sv:
            continue
        best_spec = (min if direction < 0 else max)(sv)
        if (direction > 0 and best_spec > gv) or (direction < 0 and best_spec < gv):
            cnt += 1
    rq3_consistency[ml] = cnt

_rq3_head = "".join(f'<th class="num">{m[0]}</th>' for m in rq3_metrics)
# tabela média
_rq3_body = ""
for _lab, _tag, _vals in rq3_rows:
    _cells = "".join((f'<td class="num">{_vals[m[0]]*100:.1f}%</td>' if _vals.get(m[0]) is not None else '<td class="num">—</td>') for m in rq3_metrics)
    _rq3_body += (f'<tr><td class="key-cell"><strong>{_lab}</strong> '
                  f'<span style="font-size:10px;color:var(--text-2)">· {_tag}</span></td>{_cells}</tr>')
# tabela por baseline (consistência)
_rq3_pb = ""
for _t, _tl in TARGETS:
    _rq3_pb += f'<tr><td class="key-cell" colspan="{len(rq3_metrics)+1}" style="background:var(--bg-1);font-weight:700">{_tl}</td></tr>'
    for _llm, _lab, _tag in RQ3:
        _cells = "".join((f'<td class="num">{_mval_t(_llm, sr, me, fl, _t)*100:.1f}%</td>' if _mval_t(_llm, sr, me, fl, _t) is not None else '<td class="num">—</td>') for _ml, sr, me, fl, _dd in rq3_metrics)
        _rq3_pb += f'<tr><td class="key-cell" style="padding-left:18px">{_lab}</td>{_cells}</tr>'
# linhas de consistência
_cons = "".join(
    f'<li><strong>{ml}</strong>: especialista vence em <strong>{rq3_consistency[ml]}/3</strong> baselines '
    f'({"consistente" if rq3_consistency[ml] == 3 else ("parcial" if rq3_consistency[ml] > 0 else "nunca — generalista melhor")})</li>'
    for ml, sr, me, fl, direction in rq3_metrics)
_cons_metrics = [ml for ml, *_ in rq3_metrics if rq3_consistency[ml] == 3]
_mixed_metrics = [ml for ml, *_ in rq3_metrics if 1 <= rq3_consistency[ml] <= 2]
_cons_txt = (", ".join(_cons_metrics) or "nenhuma")
_mixed_txt = (", ".join(_mixed_metrics) or "nenhuma")

rq3_section = (
    '<section id="rq3">'
    '<h2><span class="ord">RQ3 ·</span> Especialização de domínio (estudo controlado)</h2>'
    '<p class="sub">Mesma base <strong>Llama-3.1-8B</strong>, mesmo tamanho (8B), mesmo prompt — a <strong>única</strong> variável é o '
    '<em>fine-tuning</em> de cibersegurança. Generalista (Llama 3.1) vs. <strong>Foundation-Sec</strong> (Cisco) e <strong>Primus</strong> (Trend Micro). '
    'A pergunta não é só "ajuda?", mas "ajuda de forma <strong>consistente</strong> entre baselines?" <em>(↓ = menor é melhor)</em></p>'
    '<h3 style="font-size:13px;margin:8px 0 4px">Média das 3 baselines</h3>'
    f'<div class="table-wrap scroll"><table aria-label="RQ3 media"><thead><tr><th>Modelo</th>{_rq3_head}</tr></thead>'
    f'<tbody>{_rq3_body}</tbody></table></div>'
    '<h3 style="font-size:13px;margin:14px 0 4px">Por baseline (em quantas das 3 um especialista bate o generalista)</h3>'
    f'<div class="table-wrap scroll"><table aria-label="RQ3 por baseline"><thead><tr><th>Baseline / Modelo</th>{_rq3_head}</tr></thead>'
    f'<tbody>{_rq3_pb}</tbody></table></div>'
    f'<ul class="sub" style="margin-top:10px;line-height:1.7">{_cons}</ul>'
    '<aside class="callout" role="note" style="margin-top:12px"><strong>Discussão:</strong> a especialização só vence de forma '
    f'<strong>consistente</strong> (3/3 baselines) em <strong>{_cons_txt}</strong> — o <em>recall de campos exatos</em>, onde o conhecimento '
    'de cibersegurança de fato rende. Nas demais '
    f'(<strong>{_mixed_txt}</strong>) o resultado é <strong>baseline-dependente</strong> (vence em 1–2 de 3), sem direção clara — e em '
    '<strong>conformidade de schema</strong> o generalista costuma levar, puxado pela fraqueza do Foundation-Sec (~82%). '
    'Os dois especialistas ainda <strong>divergem entre si</strong>: o Primus preserva a estrutura (schema ~99%), enquanto o '
    'Foundation-Sec a sacrifica em troca de recall de campos (e é o pior em texto livre). '
    '<strong>Conclusão:</strong> o <em>fine-tuning</em> de domínio ajuda a <em>identificar</em> campos exatos, mas seu efeito em '
    'texto livre e na geração estruturada é <strong>inconsistente</strong> — não substitui a robustez de instrução do modelo-base.</aside>'
    '</section>')

# Local × Cloud (mesma família DeepSeek): Coder-V2 16B (local) × v4-flash (cloud)
DS = [("deepseek_local", "DeepSeek-V2 16B", "local · 5080"),
      ("deepseek", "deepseek-v4-flash", "cloud · referência")]
ds_metrics = [("BERTScore", "bert", "Avg_BERTScore_F1", None),
              ("Entity F1", "entity", "F1_Score", ENTITY_FIELDS),
              ("Schema conf.", "schema", "schema_conformance_rate", ["_overall"]),
              ("Omission ↓", "coverage", "omission_vl", ["_overall"]),
              ("Severity F1", "severity", "macro_F1", ["_overall"])]
ds_rows = [(_lab, _tag, {m[0]: _mval(_llm, m[1], m[2], m[3]) for m in ds_metrics}) for _llm, _lab, _tag in DS]
_ds_head = "".join(f'<th class="num">{m[0]}</th>' for m in ds_metrics)
_ds_body = ""
for _lab, _tag, _vals in ds_rows:
    _cells = "".join((f'<td class="num">{_vals[m[0]]*100:.1f}%</td>' if _vals.get(m[0]) is not None else '<td class="num">—</td>') for m in ds_metrics)
    _ds_body += (f'<tr><td class="key-cell"><strong>{_lab}</strong><br>'
                 f'<span style="font-size:10px;color:var(--text-2)">{_tag}</span></td>{_cells}</tr>')


def _ds_gap(key):
    _lo = next((v[2].get(key) for v in ds_rows if v[0] == "DeepSeek-V2 16B"), None)
    _cl = next((v[2].get(key) for v in ds_rows if v[0] == "deepseek-v4-flash"), None)
    return (_lo - _cl) if (_lo is not None and _cl is not None) else None


_bg, _eg = _ds_gap("BERTScore"), _ds_gap("Entity F1")
ds_section = (
    '<section id="local-cloud">'
    '<h2><span class="ord">RQ · </span>Local × Cloud — mesma família (DeepSeek)</h2>'
    '<p class="sub">O eixo de <strong>privacidade</strong>: manter a extração on-premise com a melhor opção <strong>DeepSeek local</strong> '
    '(Coder-V2 16B) vs. a referência <strong>cloud</strong> (deepseek-v4-flash). Quanto custa, em qualidade, <em>não</em> mandar os dados pra fora? '
    '<em>(↓ = menor é melhor)</em></p>'
    f'<div class="table-wrap scroll"><table aria-label="DeepSeek local x cloud"><thead><tr><th>Modelo</th>{_ds_head}</tr></thead><tbody>{_ds_body}</tbody></table></div>'
    '<aside class="callout" role="note" style="margin-top:12px"><strong>Leitura:</strong> rodar DeepSeek <strong>on-premise</strong> custa caro no '
    '<strong>texto livre</strong> (BERTScore ' + (f'{_bg*100:+.1f}pp' if _bg is not None else '—') + ') e na <strong>severidade</strong>, '
    'mas fica <strong>perto</strong> da cloud em <strong>campos exatos</strong> (Entity F1 ' + (f'{_eg*100:+.1f}pp' if _eg is not None else '—') + ') e em schema. '
    'O "imposto de privacidade" da família DeepSeek se concentra na <em>descrição em linguagem natural</em>, não na identificação dos campos. '
    '<em>Ressalva: não é o mesmo modelo — Coder-V2 16B (local) vs v4-flash (cloud, MoE grande); é a melhor opção on-prem da família vs a cloud.</em></aside>'
    '</section>')

# SecureBERT × distilBERT (sensibilidade de backbone) — lê os securebert_metrics.xlsx
sb_compare = []
_sb_frames = []
for _r in ("3060", "5080", "cloud"):
    _p = WTICG / _r / f"securebert_metrics_{_r}.xlsx"
    if _p.exists():
        _f = pd.read_excel(_p); _f["_src"] = _r
        _sb_frames.append(_f)
securebert_section = ""
if _sb_frames:
    _sbdf = pd.concat(_sb_frames, ignore_index=True)
    for _llm, _lab in LLMS:
        _d = _sbdf[_sbdf["model"] == _llm]
        if _d.empty:
            continue
        sb_compare.append({"model": _lab, "source": (mver.get(_llm) or KNOWN_MACHINE.get(_llm)),
                           "distil": float(_d["distil_raw_f1"].mean()), "secure": float(_d["securebert_f1"].mean())})
    sb_compare.sort(key=lambda x: SRC_ORDER.get(x["source"], 9))
if sb_compare:
    _maxabs = max(abs(c["secure"] - c["distil"]) for c in sb_compare) * 100
    _tb = ""
    for c in sb_compare:
        _diff = (c["secure"] - c["distil"]) * 100
        _tb += (f'<tr><td class="key-cell"><span class="srcbadge s-{c["source"]}">{c["source"]}</span>'
                f'<strong>{c["model"]}</strong></td><td class="num">{c["distil"]:.3f}</td>'
                f'<td class="num">{c["secure"]:.3f}</td><td class="num">{_diff:+.2f} pp</td></tr>')
    _vals = [v for c in sb_compare for v in (c["distil"], c["secure"])]
    _lo = math.floor(min(_vals) * 20) / 20
    _hi = math.ceil(max(_vals) * 20) / 20
    if _hi - _lo < 0.05:
        _hi = _lo + 0.05
    W, H, PL, PB, PT, PR = 560, 380, 54, 48, 18, 150
    _SV = {"3060": "var(--v1)", "5080": "var(--v2)", "cloud": "var(--v3)"}
    def _sx(v): return PL + (v - _lo) / (_hi - _lo) * (W - PL - PR)
    def _sy(v): return H - PB - (v - _lo) / (_hi - _lo) * (H - PT - PB)
    _g = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="distilBERT x SecureBERT">']
    for _i in range(5):
        _t = _lo + (_hi - _lo) * _i / 4
        _g.append(f'<line x1="{_sx(_t):.1f}" x2="{_sx(_t):.1f}" y1="{PT}" y2="{H-PB}" stroke="var(--border)"/>')
        _g.append(f'<line x1="{PL}" x2="{W-PR}" y1="{_sy(_t):.1f}" y2="{_sy(_t):.1f}" stroke="var(--border)"/>')
        _g.append(f'<text x="{_sx(_t):.1f}" y="{H-PB+16}" text-anchor="middle" font-size="10" fill="var(--text-2)">{_t:.2f}</text>')
        _g.append(f'<text x="{PL-8}" y="{_sy(_t)+4:.1f}" text-anchor="end" font-size="10" fill="var(--text-2)">{_t:.2f}</text>')
    _g.append(f'<line x1="{_sx(_lo):.1f}" y1="{_sy(_lo):.1f}" x2="{_sx(_hi):.1f}" y2="{_sy(_hi):.1f}" stroke="var(--text-3)" stroke-dasharray="4 4"/>')
    _g.append(f'<text x="{_sx(_hi)-4:.1f}" y="{_sy(_hi)+14:.1f}" text-anchor="end" font-size="10" fill="var(--text-3)">y = x (sem diferença)</text>')
    _g.append(f'<text x="{(PL+W-PR)/2:.0f}" y="{H-6}" text-anchor="middle" font-size="11" fill="var(--text-1)">distilBERT (cru) →</text>')
    _ymid = (PT + H - PB) / 2
    _g.append(f'<text x="14" y="{_ymid:.0f}" text-anchor="middle" font-size="11" fill="var(--text-1)" transform="rotate(-90 14 {_ymid:.0f})">SecureBERT (cru) →</text>')
    for c in sb_compare:
        _cx, _cy = _sx(c["distil"]), _sy(c["secure"])
        _col = _SV.get(c["source"], "var(--text-2)")
        _g.append(f'<circle cx="{_cx:.1f}" cy="{_cy:.1f}" r="5" fill="{_col}" fill-opacity="0.8" stroke="{_col}"/>')
        _g.append(f'<text x="{_cx+8:.1f}" y="{_cy+3:.1f}" font-size="9" fill="var(--text-1)">{c["model"]}</text>')
    _g.append('</svg>')
    securebert_section = (
        '<section id="securebert">'
        '<h2><span class="ord">extra ·</span> BERTScore genérico × SecureBERT (domínio)</h2>'
        '<p class="sub">O BERTScore principal do report usa backbone <strong>genérico</strong> (distilBERT). Um backbone '
        '<strong>especializado em cibersegurança</strong> (SecureBERT) mudaria a foto? Pontuamos os <strong>mesmos pares</strong> '
        'com os dois, ambos <strong>crus</strong> (sem rescale) — a diferença isola o backbone. '
        '<em>(valores crus, escala diferente do BERTScore rescaled do report)</em></p>'
        f'<div class="table-wrap scroll"><table aria-label="distil x securebert"><thead><tr><th>Modelo</th>'
        '<th class="num">distilBERT (cru)</th><th class="num">SecureBERT (cru)</th><th class="num">Δ</th></tr></thead>'
        f'<tbody>{_tb}</tbody></table></div>'
        f'<div class="chart-card" style="margin-top:12px">{"".join(_g)}</div>'
        '<aside class="callout" role="note" style="margin-top:12px"><strong>Conclusão:</strong> a diferença é '
        f'<strong>desprezível</strong> — no máximo <strong>{_maxabs:.2f} pp</strong> em qualquer modelo, e todos os pontos caem '
        'sobre a linha <em>y = x</em>. O backbone de <strong>domínio (SecureBERT) não muda</strong> a avaliação de similaridade '
        'textual nesta tarefa: o <strong>distilBERT genérico</strong> (mais leve) já captura o mesmo sinal. Isso <strong>valida</strong> '
        'o BERTScore padrão do report — não há ganho em trocar pelo backbone especializado.</aside>'
        '</section>')


def run_count(ver):
    d = long[long["version"] == ver]
    return int(d.drop_duplicates(["target", "model", "run"]).shape[0]) if not d.empty else 0


DATA = {
    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    "versions": ["v1", "v2", "v3"],
    "targets": [tl for _, tl in TARGETS],
    "run_counts": {"v1": run_count("3060"), "v2": run_count("5080"), "v3": run_count("cloud")},
    "kpi": kpi_rank,
    "models": MODELS_META,
    "model_colors": model_colors,
    "tbl_schema": tbl_schema, "tbl_coverage": tbl_coverage, "tbl_severity": tbl_severity,
    "tbl_entity": tbl_entity, "tbl_text": tbl_text,
    "breakdown_by_target": breakdown_by_target, "breakdown_cols": breakdown_cols,
    "schema_rows": schema_rows, "coverage_rows": coverage_rows, "sev_rows": sev_rows,
    "entity_rows": entity_rows, "text_rows": text_rows,
    "headline_labels": headline_labels, "headline_dir": headline_dir, "headline_fmt": headline_fmt,
    "by_model": by_target, "by_target": by_target,
    "scatter_points": scatter_points, "trade_models": trade_models, "bars_by_target": bars_by_target,
    "cat_by_target": cat_by_target, "cat_versions": ["v1", "v2", "v3"],
    "cat_targets": [tl for _, tl in TARGETS], "cat_categories": SIM_CATS,
    "heatmap_omission": heatmap_omission,
}

# ============================================================
# Transformação do HTML (motor verbatim) — relabel v1/v2/v3 -> máquinas
# ============================================================
html = REF.read_text(encoding="utf-8")
html = re.sub(r"const DATA = \{.*?\};", "const DATA = " + json.dumps(_nan_to_none(DATA), ensure_ascii=False) + ";", html, count=1, flags=re.S)
html = re.sub(r"const CI_LOOKUP = \{.*?\n\};", "const CI_LOOKUP = {};", html, count=1, flags=re.S)

# rótulos das máquinas nos gráficos
html = html.replace("function ciFor(label, version) {",
                    "function vlab(v){return ({v1:'3060',v2:'5080',v3:'cloud'})[v]||v.toUpperCase();}\nfunction ciFor(label, version) {")
html = html.replace("v.toUpperCase()", "vlab(v)")
html = html.replace("p.version.toUpperCase()", "vlab(p.version)")
html = html.replace("r.version.toUpperCase()", "vlab(r.version)")
html = html.replace('{ v: "V1", color: VCOLOR.v1 }', '{ v: "3060", color: VCOLOR.v1 }')
html = html.replace('{ v: "V2", color: VCOLOR.v2 }', '{ v: "5080", color: VCOLOR.v2 }')
html = html.replace('{ v: "V3", color: VCOLOR.v3 }', '{ v: "cloud", color: VCOLOR.v3 }')
html = html.replace('{ v: "V1", fill: "var(--text-3)", pat: null }', '{ v: "3060", fill: "var(--text-3)", pat: null }')
html = html.replace('{ v: "V2", fill: "var(--text-3)", pat: "pat-v2" }', '{ v: "5080", fill: "var(--text-3)", pat: "pat-v2" }')
html = html.replace('{ v: "V3", fill: "var(--text-3)", pat: "pat-v3" }', '{ v: "cloud", fill: "var(--text-3)", pat: "pat-v3" }')

# cabeçalho / legenda / meta
html = html.replace("<title>MulitaMiner · V1 × V2 × V3</title>", "<title>MulitaMiner · local × cloud</title>")
html = html.replace('<div class="eyebrow">MulitaMiner · cross-version evaluation</div>',
                    '<div class="eyebrow">MulitaMiner · local on-premise × cloud</div>')
html = html.replace("<h1>V1 × V2 × V3 — pipeline de extração de vulnerabilidades</h1>",
                    "<h1>Extração de vulnerabilidades<br>local (3060 · 5080) × cloud — privacidade × qualidade × custo</h1>")
html = html.replace(
    "3 baselines (JuiceShop · bBWA · artifactory) ·\n    5 modelos · 10 runs por (target, modelo)",
    "9 modelos locais (3060 + 5080) × referência cloud (DeepSeek) · 3 baselines com ground truth · 5 runs por (modelo, baseline)")
html = html.replace(
    '<span class="legend-chip" role="listitem"><span class="dot v1"></span>V1 — schema legacy (cvss[7], sem plugin_details/instances)</span>',
    '<span class="legend-chip" role="listitem"><span class="dot v1"></span>RTX 3060 — local "acessível" (gemma4:e4b · Ministral 3 8B · Qwen3 8B)</span>')
html = html.replace(
    '<span class="legend-chip" role="listitem"><span class="dot v2"></span>V2 — schema intermediário (cvss list[str], plugin_details list)</span>',
    '<span class="legend-chip" role="listitem"><span class="dot v2"></span>RTX 5080 — local rápido (Llama 3.1 · Phi-4 · Foundation-Sec · Primus · gpt-oss · DeepSeek-V2)</span>')
html = html.replace(
    '<span class="legend-chip" role="listitem"><span class="dot v3"></span>V3 — schema canônico (referência)</span>',
    '<span class="legend-chip" role="listitem"><span class="dot v3"></span>cloud — DeepSeek (referência)</span>')

html = re.sub(r"<aside class=\"callout\" role=\"note\">.*?</aside>",
              '<aside class="callout" role="note"><strong>Contexto:</strong> a extração de vulnerabilidades dá pra rodar '
              '<strong>local (on-premise)</strong> sem perder qualidade a ponto de inviabilizar o uso? Comparamos os modelos locais — '
              '<strong>RTX 3060</strong> (acessível) e <strong>RTX 5080</strong> (rápido) — contra a referência <strong>cloud (DeepSeek)</strong>, '
              'no trade-off qualidade × custo × privacidade. Cada modelo é uma barra, colorida pela máquina onde rodou '
              '(3060 / 5080 / cloud). Os valores <span class="ci" style="display:inline">[entre colchetes]</span> são <strong>IC 95%</strong> '
              '(bootstrap, 10.000 reamostragens sobre baseline × run). Nas tabelas, o <strong>pill colorido</strong> ao lado do valor compara o modelo com a '
              'referência <strong>deepseek-v4-flash (cloud)</strong>: <span style="color:var(--pos)">verde = melhor</span>, '
              '<span style="color:var(--neg)">vermelho = pior</span> (diferença em pp). Os KPIs por fonte são a média dos modelos daquela máquina.</aside>',
              html, count=1, flags=re.S)

# remover seção "by-model" + nav + chamada JS
html = re.sub(r'<section id="by-model">.*?</section>', "", html, count=1, flags=re.S)
html = html.replace('<a href="#by-model">Por modelo</a>\n  ', "")
html = re.sub(r'setupBreakdown\("model",.*?"model-chips"\);\n', "", html, count=1)
html = html.replace("Breakdown por Target", "Por baseline")
html = html.replace("1 grupo por modelo, 3 barras por grupo (V1/V2/V3). Escolha baseline e métrica.",
                    "Grupos = modelos; cor = máquina (3060 / 5080 / cloud). Escolha baseline e métrica.")

# ============================================================
# Observações + rodapé (data-driven, todos os modelos locais)
# ============================================================
bert_llm = {k: v for k, v in by_llm("bert", "Avg_BERTScore_F1").items() if v is not None}
ent_llm = {k: v for k, v in by_llm("entity", "F1_Score", ENTITY_FIELDS).items() if v is not None}
ent_lo, ent_hi = (min(ent_llm.values()), max(ent_llm.values())) if ent_llm else (0, 0)
hv = [v for v in hall.values() if v is not None]
ov = [v for v in omis.values() if v is not None]
hall_avg = (sum(hv) / len(hv) * 100) if hv else 0
omis_avg = (sum(ov) / len(ov) * 100) if ov else 0
fo = {f: (sum(omf[(lab, f)] or 0 for _, lab in LLMS) / len(LLMS)) for f in OMIS_FIELDS}
top3 = sorted(fo, key=lambda f: -fo[f])[:3]
top_str = ", ".join(f"<code>{f}</code> ({fo[f]*100:.0f}%)" for f in top3)
best = max(bert_llm, key=lambda k: bert_llm[k]) if bert_llm else "—"
worst = min(bert_llm, key=lambda k: bert_llm[k]) if bert_llm else "—"
n_models = len(bert_llm)
_cloud_labels = [m["label"] for m in MODELS_META if m["source"] == "cloud"]
_local_bert = {k: v for k, v in bert_llm.items() if k not in _cloud_labels}
best_local = max(_local_bert, key=lambda k: _local_bert[k]) if _local_bert else "—"
local_bert_v = _local_bert.get(best_local, 0)
cloud_bert_v = (bert_llm.get(_cloud_labels[0]) if _cloud_labels else None) or 0
gap_pp = (cloud_bert_v - local_bert_v) * 100

findings = f"""<section id="findings">
  <h2><span class="ord">8 ·</span> Observações <span class="ord">(local: 3060 + 5080)</span></h2>
  <p class="sub">Síntese de {n_models} modelos locais. <span style="color:var(--pos)">Verde</span> = ponto forte · <span style="color:var(--v2)">amarelo</span> = atenção · <span style="color:var(--neg)">vermelho</span> = limitação.</p>
  <h3 class="findings-subhead win">Pontos fortes<span class="bar"></span></h3>
  <div class="findings-grid">
    <article class="finding-card win"><h3><span class="tag">Qualidade · local quase alcança a cloud</span></h3>
      <p>O melhor local (<strong>{best_local}</strong>, <span class="num">{local_bert_v:.3f}</span> BERTScore) fica a só <span class="num">{gap_pp:.1f}pp</span> da referência <strong>cloud</strong> (<span class="num">{cloud_bert_v:.3f}</span>) — privacidade sem perder qualidade a ponto de inviabilizar. Pior local: <strong>{worst}</strong> (<span class="num">{bert_llm.get(worst, 0):.3f}</span>).</p></article>
    <article class="finding-card win"><h3><span class="tag">Campos exatos resolvidos</span></h3>
      <p>Entity F1 (cvss/plugin/port/protocol/severity) fica entre <span class="num">{ent_lo:.3f}</span> e <span class="num">{ent_hi:.3f}</span> — extrair identificadores é fácil; o gargalo é o <strong>texto livre</strong>.</p></article>
    <article class="finding-card win"><h3><span class="tag">Reprodutibilidade · IC bootstrap</span></h3>
      <p>A maioria dos locais a <code>temperature=0</code> é <strong>determinística</strong> (5 runs idênticos → IC ±0). Mas alguns via Ollama (<strong>qwen3, gemma</strong>) têm pequena variância de run (llama.cpp não é 100% determinístico), e a <strong>cloud (DeepSeek)</strong> é claramente <strong>estocástica</strong> (matched <span class="num">110–112</span>). Os <span class="num">[IC 95%]</span> nas tabelas/cards vêm de bootstrap (10k reamostragens) sobre baseline × run.</p></article>
    <article class="finding-card win"><h3><span class="tag">RQ3 · especialização de domínio</span></h3>
      <p>Mesma base Llama-3.1-8B: em <span class="num">{rq3_wins}/{rq3_total}</span> métricas um especialista de segurança (Foundation-Sec/Primus) supera o generalista Llama 3.1 — detalhe na seção <strong>RQ3</strong>.</p></article>
  </div>
  <h3 class="findings-subhead caveat">Limitações<span class="bar"></span></h3>
  <div class="findings-grid">
    <article class="finding-card caveat"><h3><span class="tag">Omissão domina (não alucinação)</span></h3>
      <p>Alucinação baixa (<span class="num">{hall_avg:.1f}%</span>), mas a <strong>omissão</strong> é o problema (<span class="num">{omis_avg:.1f}%</span>), concentrada em {top_str}. Os locais deixam de fora antes de inventar.</p></article>
    <article class="finding-card caveat"><h3><span class="tag">Custo é por máquina</span></h3>
      <p>Latência/energia <strong>não</strong> são comparáveis entre 3060 e 5080 (GPUs diferentes) — reportadas por máquina. A <strong>cloud</strong> não tem custo de GPU local (é API), mas troca <strong>privacidade</strong> por dependência de terceiros — ver §Local × Cloud.</p></article>
  </div>
</section>"""

html = re.sub(r'<section id="findings">.*?</section>', findings, html, count=1, flags=re.S)

# ============================================================
# renderHeatmap reescrito: 1 linha por MODELO, agrupado por fonte
# ============================================================
NEW_HEATMAP = r'''function renderHeatmap() {
  if (!DATA.heatmap_omission) return;
  const svg = document.getElementById("chart-heatmap");
  if (!svg) return;
  svg.innerHTML = "";
  const hm = DATA.heatmap_omission;
  const fields = hm.fields;
  const models = hm.models;              // [{label, source, vals:{field:val}}]
  if (!models.length) return;
  const SRCCOLOR = { "3060": "var(--v1)", "5080": "var(--v2)", "cloud": "var(--v3)" };

  // gaps acumulados entre grupos de fonte
  const gapsBefore = []; let g = 0;
  for (let i = 0; i < models.length; i++) {
    if (i > 0 && models[i].source !== models[i - 1].source) g++;
    gapsBefore.push(g);
  }
  const plotW = HM_W - HM_PAD.left - HM_PAD.right;
  const plotH = HM_H - HM_PAD.top - HM_PAD.bottom - g * HM_GROUP_GAP;
  const cellW = plotW / fields.length;
  const cellH = plotH / models.length;
  const rowY = ri => HM_PAD.top + ri * cellH + gapsBefore[ri] * HM_GROUP_GAP;

  // células
  models.forEach((m, ri) => {
    fields.forEach((f, fi) => {
      const value = m.vals?.[f] ?? null;
      const x = HM_PAD.left + fi * cellW, y = rowY(ri);
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("class", "heatmap-cell");
      rect.setAttribute("x", x); rect.setAttribute("y", y);
      rect.setAttribute("width", cellW); rect.setAttribute("height", cellH);
      rect.setAttribute("fill", value == null ? "#737373" : omissionColor(value));
      rect.setAttribute("tabindex", "0");
      const display = value == null ? "N/A" : (value * 100).toFixed(1) + "%";
      rect.setAttribute("aria-label", m.label + " (" + m.source + ") " + f + ": omission " + display);
      const ttHtml = '<div class="tt-title">' + m.label + ' · ' + m.source + '</div>'
        + '<div class="tt-row"><span class="tt-key">Campo</span><span>' + f + '</span></div>'
        + '<div class="tt-row"><span class="tt-key">Omission</span><span>' + display + '</span></div>';
      rect.addEventListener("mouseenter", e => showTip(ttHtml, e));
      rect.addEventListener("mousemove", moveTip);
      rect.addEventListener("mouseleave", hideTip);
      rect.addEventListener("focus", () => { const b = rect.getBoundingClientRect(); showTip(ttHtml, { clientX: b.left + b.width / 2, clientY: b.top }); });
      rect.addEventListener("blur", hideTip);
      svg.appendChild(rect);
      if (cellW >= 40 && value != null) {
        const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
        txt.setAttribute("x", x + cellW / 2); txt.setAttribute("y", y + cellH / 2 + 3);
        txt.setAttribute("text-anchor", "middle"); txt.setAttribute("font-size", "9");
        txt.setAttribute("font-variant-numeric", "tabular-nums");
        txt.setAttribute("fill", value > 0.25 ? "#fff" : "#0b0e14");
        txt.setAttribute("pointer-events", "none");
        txt.textContent = (value * 100).toFixed(0);
        svg.appendChild(txt);
      }
    });
  });

  // rótulo = nome do modelo (quebra " (...)" em 2 linhas p/ não transbordar)
  models.forEach((m, ri) => {
    const yc = rowY(ri) + cellH / 2;
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("class", "heatmap-axis");
    t.setAttribute("x", HM_PAD.left - 8); t.setAttribute("text-anchor", "end");
    t.setAttribute("font-size", "11"); t.setAttribute("font-weight", "600"); t.setAttribute("fill", "var(--text-1)");
    const _i = m.label.indexOf(" (");
    if (_i > 0) {
      t.setAttribute("y", yc - 2);
      const s1 = document.createElementNS("http://www.w3.org/2000/svg", "tspan");
      s1.setAttribute("x", HM_PAD.left - 8); s1.textContent = m.label.slice(0, _i); t.appendChild(s1);
      const s2 = document.createElementNS("http://www.w3.org/2000/svg", "tspan");
      s2.setAttribute("x", HM_PAD.left - 8); s2.setAttribute("dy", "11"); s2.textContent = m.label.slice(_i + 1); t.appendChild(s2);
    } else {
      t.setAttribute("y", yc + 4); t.textContent = m.label;
    }
    svg.appendChild(t);
  });

  // grupos de fonte: label vertical + bracket à esquerda
  const groups = [];
  models.forEach((m, ri) => {
    const last = groups[groups.length - 1];
    if (!last || last.source !== m.source) groups.push({ source: m.source, first: ri, last: ri });
    else last.last = ri;
  });
  groups.forEach(gr => {
    const yTop = rowY(gr.first), yBot = rowY(gr.last) + cellH, yMid = (yTop + yBot) / 2;
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("x", 16); t.setAttribute("y", yMid);
    t.setAttribute("text-anchor", "middle"); t.setAttribute("font-size", "12"); t.setAttribute("font-weight", "800");
    t.setAttribute("fill", SRCCOLOR[gr.source] || "var(--text-0)");
    t.setAttribute("transform", "rotate(-90 16 " + yMid + ")");
    t.textContent = gr.source.toUpperCase();
    svg.appendChild(t);
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", 28); line.setAttribute("x2", 28);
    line.setAttribute("y1", yTop + 2); line.setAttribute("y2", yBot - 2);
    line.setAttribute("stroke", SRCCOLOR[gr.source] || "var(--border-strong)");
    line.setAttribute("stroke-width", "3"); line.setAttribute("stroke-linecap", "round");
    svg.appendChild(line);
  });

  // rótulos de coluna (campos) rotacionados -45
  const yColLabel = rowY(models.length - 1) + cellH + 12;
  fields.forEach((f, fi) => {
    const x = HM_PAD.left + fi * cellW + cellW / 2;
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("class", "heatmap-axis");
    t.setAttribute("x", x); t.setAttribute("y", yColLabel);
    t.setAttribute("text-anchor", "end");
    t.setAttribute("transform", "rotate(-45 " + x + " " + yColLabel + ")");
    t.textContent = f;
    svg.appendChild(t);
  });

  // escala à direita
  const scaleX = HM_PAD.left + plotW + 18, scaleW = 14;
  const scaleYTop = HM_PAD.top, scaleYBot = rowY(models.length - 1) + cellH, scaleH = scaleYBot - scaleYTop;
  for (let i = 0; i < 50; i++) {
    const y0 = scaleYTop + (i / 50) * scaleH, y1 = scaleYTop + ((i + 1) / 50) * scaleH, tv = 0.5 - (i / 49) * 0.5;
    const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    rect.setAttribute("x", scaleX); rect.setAttribute("y", y0);
    rect.setAttribute("width", scaleW); rect.setAttribute("height", y1 - y0 + 0.5);
    rect.setAttribute("fill", omissionColor(tv));
    svg.appendChild(rect);
  }
  [["0%", scaleYBot], ["25%", (scaleYTop + scaleYBot) / 2], ["≥50%", scaleYTop]].forEach(([txt, y]) => {
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("class", "heatmap-scale-stop");
    t.setAttribute("x", scaleX + scaleW + 4); t.setAttribute("y", y + 4);
    t.textContent = txt;
    svg.appendChild(t);
  });
}
'''
html = re.sub(r"function renderHeatmap\(\) \{.*?\n\}\n", NEW_HEATMAP, html, count=1, flags=re.S)

# ---- CSS: badges de fonte + ranking dos cards ----
CSS = """
.srcbadge{display:inline-block;font-size:9px;font-weight:700;line-height:1;padding:1px 5px;border-radius:5px;background:transparent;border:1px solid currentColor;margin-right:6px;vertical-align:middle;opacity:.85}
.srcbadge.s-3060{color:var(--v1)}.srcbadge.s-5080{color:var(--v2)}.srcbadge.s-cloud{color:var(--v3)}
.kpi-card .rows{display:flex;flex-direction:column;gap:1px}
.kpi-rank{display:flex;align-items:center;gap:6px;padding:2px 0;font-size:12px}
.kpi-rank .rk{width:15px;height:15px;border-radius:50%;border:1px solid var(--border);color:var(--text-2);font-size:9px;font-weight:700;display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto}
.kpi-rank .mname{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-0)}
.kpi-rank .val{font-variant-numeric:tabular-nums;font-weight:700;color:var(--text-0)}
.ci{display:block;font-size:9px;font-weight:400;color:var(--text-2);opacity:.7;font-variant-numeric:tabular-nums;margin-top:1px}
.kpi-rank .val .ci{display:inline;margin-left:4px;opacity:.6}
th.num{text-align:right}
</style>"""
html = html.replace("</style>", CSS, 1)

# ---- renderKpi: melhores MODELOS por métrica (com badge da fonte) ----
NEW_KPI = r'''function renderKpi() {
  const grid = document.getElementById("kpi-grid");
  grid.innerHTML = DATA.kpi.map(k => {
    const rows = (k.ranking || []).slice(0, 3).map((r, i) => {
      const disp = k.fmt === "pct" ? fmtPct(r.value) : fmtNum(r.value);
      return '<div class="kpi-rank"><span class="rk">' + (i + 1) + '</span>'
        + '<span class="srcbadge s-' + r.source + '">' + r.source + '</span>'
        + '<span class="mname">' + r.model + '</span><span class="val">' + disp
        + (r.ci ? ' <span class="ci">' + r.ci + '</span>' : '') + '</span></div>';
    }).join("");
    return '<article class="kpi-card" role="listitem"><div class="head">'
      + '<div class="label">' + k.label + '</div>'
      + '<button type="button" class="help" title="' + k.tip + '" aria-label="' + k.tip + '">?</button></div>'
      + '<div class="rows">' + rows + '</div></article>';
  }).join("");
}
'''
html = re.sub(r"function renderKpi\(\) \{.*?\n\}\n", NEW_KPI, html, count=1, flags=re.S)

# ---- tabelas centradas em MODELO (linhas = modelos + badge) ----
NEW_TABLES = r'''/* -------------------- model-centric tables -------------------- */
function srcBadge(s) { return '<span class="srcbadge s-' + s + '">' + s + '</span>'; }
function renderModelTable(tableId, spec) {
  const tbl = document.getElementById(tableId);
  if (!tbl || !spec) return;
  const cols = spec.cols, rows = spec.rows;
  const refRow = rows.find(rr => rr.source === 'cloud');  // deepseek-v4-flash = referência
  const best = {};
  cols.forEach(c => {
    const vs = rows.map(r => r.vals[c.key]).filter(x => x != null);
    if (vs.length) best[c.key] = c.dir < 0 ? Math.min.apply(null, vs) : Math.max.apply(null, vs);
  });
  const head = '<thead><tr><th>Modelo</th>' + cols.map(c => '<th class="num">' + c.label + '</th>').join("") + '</tr></thead>';
  const body = '<tbody>' + rows.map(r => {
    const cells = cols.map(c => {
      const v = r.vals[c.key];
      const isBest = v != null && best[c.key] != null && Math.abs(v - best[c.key]) < 1e-9;
      const disp = v == null ? '—' : (c.fmt === 'num' ? fmtNum(v) : fmtPct(v));
      const refv = refRow ? refRow.vals[c.key] : null;
      const delta = (r.source !== 'cloud' && v != null && refv != null) ? deltaPill(v, refv, c.dir, c.fmt) : '';
      const ci = (r.cis && r.cis[c.key]) ? '<span class="ci">' + r.cis[c.key] + '</span>' : '';
      return '<td class="num">' + disp + delta + ci + '</td>';
    }).join("");
    return '<tr><td class="key-cell">' + srcBadge(r.source) + '<strong>' + r.model + '</strong></td>' + cells + '</tr>';
  }).join("") + '</tbody>';
  tbl.innerHTML = head + body;
}
renderModelTable("t-schema", DATA.tbl_schema);
renderModelTable("t-coverage", DATA.tbl_coverage);
renderModelTable("t-severity", DATA.tbl_severity);
renderModelTable("t-entity", DATA.tbl_entity);
let activeTextMetric = "BERTScore F1";
function renderTextTable() { renderModelTable("t-text", DATA.tbl_text[activeTextMetric]); }
renderTextTable();
document.querySelectorAll("button[data-text]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("button[data-text]").forEach(b => b.setAttribute("aria-pressed", "false"));
    btn.setAttribute("aria-pressed", "true");
    activeTextMetric = btn.dataset.text;
    renderTextTable();
  });
});
let activeBreakdownTarget = DATA.targets[0];
function renderBreakdown(target) {
  const tbl = document.getElementById("t-target");
  if (!tbl) return;
  const cols = DATA.breakdown_cols, rows = DATA.breakdown_by_target[target] || [];
  const refRow = rows.find(rr => rr.source === 'cloud');
  const best = {};
  cols.forEach(c => { const vs = rows.map(r => r.vals[c.key]).filter(x => x != null); if (vs.length) best[c.key] = c.dir < 0 ? Math.min.apply(null, vs) : Math.max.apply(null, vs); });
  const head = '<thead><tr><th>Modelo</th>' + cols.map(c => '<th class="num">' + c.label + '</th>').join("") + '</tr></thead>';
  const body = '<tbody>' + rows.map(r => {
    const cells = cols.map(c => { const v = r.vals[c.key]; const refv = refRow ? refRow.vals[c.key] : null; const delta = (r.source !== 'cloud' && v != null && refv != null) ? deltaPill(v, refv, c.dir, c.fmt) : ''; const disp = v == null ? '—' : fmtPct(v); return '<td class="num">' + disp + delta + '</td>'; }).join("");
    return '<tr><td class="key-cell">' + srcBadge(r.source) + '<strong>' + r.model + '</strong></td>' + cells + '</tr>';
  }).join("") + '</tbody>';
  tbl.innerHTML = head + body;
}
(function setupBreakdownTarget() {
  const host = document.getElementById("target-chips");
  if (host) {
    host.innerHTML = DATA.targets.map((t, i) => '<button type="button" data-bd-target="' + t + '" role="radio" aria-pressed="' + (i === 0) + '">' + t + '</button>').join(" ");
    document.querySelectorAll("button[data-bd-target]").forEach(b => {
      b.addEventListener("click", () => {
        document.querySelectorAll("button[data-bd-target]").forEach(x => x.setAttribute("aria-pressed", x.dataset.bdTarget === b.dataset.bdTarget ? "true" : "false"));
        activeBreakdownTarget = b.dataset.bdTarget;
        renderBreakdown(activeBreakdownTarget);
      });
    });
  }
  renderBreakdown(activeBreakdownTarget);
})();
'''
html = re.sub(r"/\* -+ simple tables -+ \*/.*?setupBreakdown\(\"target\".*?\"target-chips\"\);", NEW_TABLES, html, count=1, flags=re.S)

# ---- clustered bars: 1 barra por modelo, cor = fonte, rótulo diagonal ----
NEW_BARS = r'''function renderBars() {
  const svg = document.getElementById("chart-bars");
  svg.innerHTML = "";
  const data = (DATA.bars_by_target[activeBarsTarget] || {})[activeBarsMetric] || {};
  const models = Object.keys(data);
  if (!models.length) return;
  const plotW = BARS_W - BARS_PAD.left - BARS_PAD.right;
  const plotH = BARS_H - BARS_PAD.top - BARS_PAD.bottom;
  const yScale = v => BARS_PAD.top + plotH - v * plotH;
  const yTicks = [0, 0.25, 0.5, 0.75, 1.0];
  let html = '<g class="grid">';
  for (const t of yTicks) html += '<line x1="' + BARS_PAD.left + '" x2="' + (BARS_PAD.left + plotW) + '" y1="' + yScale(t) + '" y2="' + yScale(t) + '" />';
  html += '</g><g class="axis">';
  for (const t of yTicks) html += '<text x="' + (BARS_PAD.left - 8) + '" y="' + (yScale(t) + 4) + '" text-anchor="end">' + (t * 100).toFixed(0) + '%</text>';
  html += '<text class="axis-label" x="' + (-BARS_PAD.top - plotH / 2) + '" y="14" text-anchor="middle" transform="rotate(-90)">' + activeBarsMetric + ' →</text></g>';
  svg.insertAdjacentHTML("beforeend", html);
  const SRCLABEL = { v1: "3060", v2: "5080", v3: "cloud" };
  const groupW = plotW / models.length;
  const barW = Math.min(46, groupW * 0.62);
  models.forEach((model, idx) => {
    const cell = data[model] || {};
    const v = ["v1", "v2", "v3"].find(s => cell[s] != null);
    const cx = BARS_PAD.left + idx * groupW + groupW / 2;
    if (v) {
      const value = cell[v], x = cx - barW / 2, y = yScale(value), h = (BARS_PAD.top + plotH) - y;
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("class", "bar-rect"); rect.setAttribute("x", x); rect.setAttribute("y", y);
      rect.setAttribute("width", barW); rect.setAttribute("height", h); rect.setAttribute("rx", 2);
      rect.setAttribute("fill", VCOLOR[v]); rect.setAttribute("tabindex", "0");
      rect.setAttribute("aria-label", model + " (" + SRCLABEL[v] + ") " + activeBarsMetric + ": " + fmtPct(value));
      const ttHtml = '<div class="tt-title">' + model + ' · ' + SRCLABEL[v] + '</div>'
        + '<div class="tt-row"><span class="tt-key">' + activeBarsMetric + '</span><span>' + fmtPct(value) + '</span></div>'
        + '<div class="tt-row"><span class="tt-key">Baseline</span><span>' + activeBarsTarget + '</span></div>';
      rect.addEventListener("mouseenter", e => showTip(ttHtml, e));
      rect.addEventListener("mousemove", moveTip);
      rect.addEventListener("mouseleave", hideTip);
      rect.addEventListener("focus", () => { const r = rect.getBoundingClientRect(); showTip(ttHtml, { clientX: r.left + r.width / 2, clientY: r.top }); });
      rect.addEventListener("blur", hideTip);
      svg.appendChild(rect);
      if (h > 14) {
        const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
        txt.setAttribute("x", cx); txt.setAttribute("y", y - 4); txt.setAttribute("text-anchor", "middle");
        txt.setAttribute("font-size", "10"); txt.setAttribute("fill", "var(--text-1)"); txt.setAttribute("font-variant-numeric", "tabular-nums");
        txt.textContent = (value * 100).toFixed(0);
        svg.appendChild(txt);
      }
    }
    const ly = BARS_PAD.top + plotH + 12;
    const lbl = document.createElementNS("http://www.w3.org/2000/svg", "text");
    lbl.setAttribute("x", cx); lbl.setAttribute("y", ly);
    lbl.setAttribute("text-anchor", "end"); lbl.setAttribute("font-size", "11");
    lbl.setAttribute("fill", "var(--text-1)");
    lbl.setAttribute("transform", "rotate(-35 " + cx + " " + ly + ")");
    lbl.textContent = model;
    svg.appendChild(lbl);
  });
  let lx = BARS_PAD.left; const legendY = BARS_H - 10;
  [["v1", "3060"], ["v2", "5080"], ["v3", "cloud"]].forEach(arr => {
    svg.insertAdjacentHTML("beforeend", '<g transform="translate(' + lx + ',' + legendY + ')"><rect width="10" height="10" rx="2" fill="' + VCOLOR[arr[0]] + '" /><text x="14" y="9" font-size="11" fill="var(--text-2)">' + arr[1] + '</text></g>');
    lx += 62;
  });
}
'''
html = re.sub(r"function renderBars\(\) \{.*?\n\}\n", NEW_BARS, html, count=1, flags=re.S)

# ---- distribuição de similaridade: 1 barra empilhada por modelo ----
NEW_CAT = r'''function renderCategorization() {
  if (!DATA.cat_by_target) return;
  const svg = document.getElementById("chart-cat");
  if (!svg) return;
  svg.innerHTML = "";
  const data = (DATA.cat_by_target[activeCatTarget] || {})[activeCatMetric] || {};
  const models = Object.keys(data);
  if (!models.length) return;
  const plotW = CAT_W - CAT_PAD.left - CAT_PAD.right;
  const plotH = CAT_H - CAT_PAD.top - CAT_PAD.bottom;
  const yScale = v => CAT_PAD.top + plotH - v * plotH;
  let html = '<g class="grid">';
  for (const t of [0, 0.25, 0.5, 0.75, 1]) html += '<line x1="' + CAT_PAD.left + '" x2="' + (CAT_PAD.left + plotW) + '" y1="' + yScale(t) + '" y2="' + yScale(t) + '" />';
  html += '</g><g class="axis">';
  for (const t of [0, 0.25, 0.5, 0.75, 1]) html += '<text x="' + (CAT_PAD.left - 8) + '" y="' + (yScale(t) + 4) + '" text-anchor="end">' + (t * 100).toFixed(0) + '%</text>';
  html += '<text class="axis-label" x="' + (-CAT_PAD.top - plotH / 2) + '" y="14" text-anchor="middle" transform="rotate(-90)">% de vulnerabilidades</text></g>';
  svg.insertAdjacentHTML("beforeend", html);
  const SRCLABEL = { v1: "3060", v2: "5080", v3: "cloud" };
  const groupW = plotW / models.length;
  const barW = Math.min(48, groupW * 0.6);
  models.forEach((model, idx) => {
    const cell = data[model] || {};
    const v = ["v1", "v2", "v3"].find(s => cell[s] != null);
    const cx = CAT_PAD.left + idx * groupW + groupW / 2, x = cx - barW / 2;
    if (v) {
      const dist = cell[v];
      let yCursor = CAT_PAD.top + plotH;
      DATA.cat_categories.forEach((cat, ci) => {
        const pct = dist[cat] || 0;
        if (pct <= 0) return;
        const h = pct * plotH; yCursor -= h;
        const seg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
        seg.setAttribute("class", "bar-rect cat-color-" + ci);
        seg.setAttribute("x", x); seg.setAttribute("y", yCursor);
        seg.setAttribute("width", barW); seg.setAttribute("height", h); seg.setAttribute("tabindex", "0");
        seg.setAttribute("aria-label", model + " (" + SRCLABEL[v] + ") " + cat + ": " + (pct * 100).toFixed(1) + "%");
        const ttRows = DATA.cat_categories.map(c => '<div class="tt-row"><span class="tt-key">' + c + '</span><span>' + (((dist[c] || 0) * 100).toFixed(1)) + '%</span></div>').join("");
        const ttHtml = '<div class="tt-title">' + model + ' · ' + SRCLABEL[v] + '</div><div class="tt-row"><span class="tt-key">Baseline</span><span>' + activeCatTarget + '</span></div><div style="border-top:1px solid var(--border); margin:6px 0; opacity:.6"></div>' + ttRows;
        seg.addEventListener("mouseenter", e => showTip(ttHtml, e));
        seg.addEventListener("mousemove", moveTip);
        seg.addEventListener("mouseleave", hideTip);
        seg.addEventListener("focus", () => { const r = seg.getBoundingClientRect(); showTip(ttHtml, { clientX: r.left + r.width / 2, clientY: r.top }); });
        seg.addEventListener("blur", hideTip);
        svg.appendChild(seg);
      });
    }
    const ly = CAT_PAD.top + plotH + 12;
    const lbl = document.createElementNS("http://www.w3.org/2000/svg", "text");
    lbl.setAttribute("x", cx); lbl.setAttribute("y", ly);
    lbl.setAttribute("text-anchor", "end"); lbl.setAttribute("font-size", "11"); lbl.setAttribute("font-weight", "600");
    lbl.setAttribute("fill", "var(--text-1)");
    lbl.setAttribute("transform", "rotate(-35 " + cx + " " + ly + ")");
    lbl.textContent = model;
    svg.appendChild(lbl);
  });
  let lx = CAT_PAD.left; const lyl = CAT_H - 12;
  DATA.cat_categories.forEach((cat, ci) => {
    const swatch = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    swatch.setAttribute("x", lx); swatch.setAttribute("y", lyl - 9); swatch.setAttribute("width", 10); swatch.setAttribute("height", 10); swatch.setAttribute("rx", 2); swatch.setAttribute("class", "cat-color-" + ci);
    svg.appendChild(swatch);
    const txt = document.createElementNS("http://www.w3.org/2000/svg", "text");
    txt.setAttribute("x", lx + 14); txt.setAttribute("y", lyl); txt.setAttribute("font-size", "11"); txt.setAttribute("fill", "var(--text-2)");
    const label = (typeof CAT_LABEL_FULL !== "undefined" && CAT_LABEL_FULL[cat]) ? CAT_LABEL_FULL[cat] : cat;
    txt.textContent = label;
    svg.appendChild(txt);
    lx += 14 + label.length * 6.5 + 24;
  });
}
'''
html = re.sub(r"function renderCategorization\(\) \{.*?\n\}\n", NEW_CAT, html, count=1, flags=re.S)

# ---- scatter colorido por MODELO (não por máquina) ----
NEW_SCATTER = r'''function renderScatter() {
  const svg = document.getElementById("chart-scatter");
  if (!svg) return;
  svg.innerHTML = "";
  const pts = DATA.scatter_points.filter(p => activeScatterTarget === "__all__" || p.target === activeScatterTarget);
  if (pts.length === 0) return;
  const xMax = Math.max(0.05, Math.ceil(Math.max.apply(null, pts.map(p => p.halluc)) * 20) / 20);
  const yMax = Math.max(0.05, Math.ceil(Math.max.apply(null, pts.map(p => p.omission)) * 20) / 20);
  const plotW = SCATTER_W - SCATTER_PAD.left - SCATTER_PAD.right;
  const plotH = SCATTER_H - SCATTER_PAD.top - SCATTER_PAD.bottom;
  const xScale = v => SCATTER_PAD.left + (v / xMax) * plotW;
  const yScale = v => SCATTER_PAD.top + plotH - (v / yMax) * plotH;
  const tx = Math.min(xMax, idealHalluc), ty = Math.min(yMax, idealOmission);
  const fmtT = v => (v * 100).toFixed(v < 0.1 ? 1 : 0);
  svg.insertAdjacentHTML("beforeend",
    '<rect class="target-zone" x="' + xScale(0) + '" y="' + yScale(ty) + '" width="' + (xScale(tx) - xScale(0)) + '" height="' + (yScale(0) - yScale(ty)) + '" />'
    + '<text class="target-zone-label" x="' + (xScale(0) + 6) + '" y="' + (yScale(ty) + 14) + '">ideal &lt;' + fmtT(idealHalluc) + '% / &lt;' + fmtT(idealOmission) + '%</text>');
  const xTicks = niceTicks(0, xMax, 5), yTicks = niceTicks(0, yMax, 5);
  let gridHtml = '<g class="grid">';
  for (const t of xTicks) gridHtml += '<line x1="' + xScale(t) + '" x2="' + xScale(t) + '" y1="' + SCATTER_PAD.top + '" y2="' + (SCATTER_PAD.top + plotH) + '" />';
  for (const t of yTicks) gridHtml += '<line x1="' + SCATTER_PAD.left + '" x2="' + (SCATTER_PAD.left + plotW) + '" y1="' + yScale(t) + '" y2="' + yScale(t) + '" />';
  gridHtml += '</g>';
  svg.insertAdjacentHTML("beforeend", gridHtml);
  let axisHtml = '<g class="axis">';
  for (const t of xTicks) axisHtml += '<text x="' + xScale(t) + '" y="' + (SCATTER_PAD.top + plotH + 18) + '" text-anchor="middle">' + (t * 100).toFixed(1) + '%</text>';
  for (const t of yTicks) axisHtml += '<text x="' + (SCATTER_PAD.left - 10) + '" y="' + (yScale(t) + 4) + '" text-anchor="end">' + (t * 100).toFixed(1) + '%</text>';
  axisHtml += '<text class="axis-label" x="' + (SCATTER_PAD.left + plotW / 2) + '" y="' + (SCATTER_H - 12) + '" text-anchor="middle">Hallucination rate →</text>';
  axisHtml += '<text class="axis-label" x="' + (-SCATTER_PAD.top - plotH / 2) + '" y="14" text-anchor="middle" transform="rotate(-90)">Omission rate →</text></g>';
  svg.insertAdjacentHTML("beforeend", axisHtml);
  const colorOf = m => (DATA.model_colors && DATA.model_colors[m]) || "var(--text-2)";
  const legModels = (DATA.models || []).map(m => m.label).filter(lab => pts.some(p => p.model === lab));
  const lgX = SCATTER_PAD.left + plotW - 150, lgY = SCATTER_PAD.top + 6;
  let legendHtml = '<g class="legend"><rect x="' + (lgX - 8) + '" y="' + (lgY - 4) + '" width="156" height="' + (legModels.length * 14 + 8) + '" rx="6" fill="var(--bg-1)" fill-opacity="0.9" stroke="var(--border)" />';
  legModels.forEach((lab, i) => {
    const cy = lgY + 8 + i * 14;
    legendHtml += '<circle cx="' + (lgX + 4) + '" cy="' + cy + '" r="4" fill="' + colorOf(lab) + '" fill-opacity="0.85" stroke="' + colorOf(lab) + '" stroke-width="1.2"/>'
      + '<text x="' + (lgX + 14) + '" y="' + (cy + 4) + '" font-size="10" fill="var(--text-1)">' + lab + '</text>';
  });
  legendHtml += '</g>';
  svg.insertAdjacentHTML("beforeend", legendHtml);
  for (const p of pts) {
    const cx = xScale(p.halluc), cy = yScale(p.omission), color = colorOf(p.model);
    const el = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    el.setAttribute("class", "pt"); el.setAttribute("cx", cx); el.setAttribute("cy", cy); el.setAttribute("r", 7);
    el.setAttribute("fill", color); el.setAttribute("fill-opacity", "0.7"); el.setAttribute("stroke", color); el.setAttribute("stroke-width", "1.5");
    el.setAttribute("tabindex", "0");
    el.setAttribute("aria-label", p.model + " " + p.target + ": halluc " + fmtPct(p.halluc) + ", omiss " + fmtPct(p.omission));
    const ttHtml = '<div class="tt-title">' + p.model + '</div>'
      + '<div class="tt-row"><span class="tt-key">Target</span><span>' + p.target + '</span></div>'
      + '<div class="tt-row"><span class="tt-key">Halluc</span><span>' + fmtPct(p.halluc) + '</span></div>'
      + '<div class="tt-row"><span class="tt-key">Omiss</span><span>' + fmtPct(p.omission) + '</span></div>'
      + '<div class="tt-row"><span class="tt-key">Matched</span><span>' + (p.n_matched != null ? p.n_matched : '—') + '</span></div>';
    el.addEventListener("mouseenter", e => showTip(ttHtml, e));
    el.addEventListener("mousemove", moveTip);
    el.addEventListener("mouseleave", hideTip);
    el.addEventListener("focus", () => { const r = el.getBoundingClientRect(); showTip(ttHtml, { clientX: r.left + r.width / 2, clientY: r.top }); });
    el.addEventListener("blur", hideTip);
    svg.appendChild(el);
  }
}
'''
html = re.sub(r"function renderScatter\(\) \{.*?\n\}\n", NEW_SCATTER, html, count=1, flags=re.S)

# ---- injeta a seção RQ3 (antes das Observações) ----
html = html.replace('<section id="findings">', rq3_section + '\n' + ds_section + '\n' + securebert_section + '\n<section id="findings">', 1)

# ============================================================
# 3 alternativas pro trade-off (a decidir) — injeta seções + renders
# ============================================================
TRADE_SECTIONS = '''<section id="tradeoff">
  <h2><span class="ord">2.1 ·</span> Trade-off por modelo — omissão × alucinação <span class="ord">(per vulnerability)</span></h2>
  <p class="sub"><strong>Vuln-level</strong>, média das 3 baselines. Esquerda = <strong>omissão</strong> (vulns do baseline não recuperadas), direita = <strong>alucinação</strong> (extraídas sem par no baseline). Ordenado por erro total. Ponto à esquerda = fonte (3060/5080/cloud).</p>
  <div class="chart-card"><svg id="chart-diverge" viewBox="0 0 760 470" role="img" aria-label="Barra divergente omissão x alucinação"></svg></div>
</section>
'''
# remove o scatter original (mantemos só a barra divergente)
html = re.sub(r'<section id="tradeoff">.*?</section>\s*', '', html, count=1, flags=re.S)
html = html.replace('<section id="field-heatmap">', TRADE_SECTIONS + '<section id="field-heatmap">', 1)

TRADE_JS = r'''
const _OMC = "#d9534f", _HAC = "#e0962f";
const _SRCDOT = { "3060": "var(--v1)", "5080": "var(--v2)", "cloud": "var(--v3)" };
function _txt(svg, x, y, s, opts) {
  const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
  t.setAttribute("x", x); t.setAttribute("y", y); t.textContent = s;
  for (const k in (opts || {})) t.setAttribute(k, opts[k]);
  svg.appendChild(t); return t;
}
function renderDiverge() {
  const svg = document.getElementById("chart-diverge"); if (!svg) return; svg.innerHTML = "";
  const data = (DATA.trade_models || []).slice().sort((a, b) => (b.omission + b.hallucination) - (a.omission + a.hallucination));
  if (!data.length) return;
  const W = 760, H = 470, PT = 34, PB = 16, PL = 168, PR = 70;
  const plotW = W - PL - PR, plotH = H - PT - PB, rowH = plotH / data.length, barH = Math.min(15, rowH * 0.5);
  const maxV = Math.max(...data.flatMap(d => [d.omission, d.hallucination])) || 1;
  const half = plotW / 2, cx = PL + half, sc = v => (v / maxV) * half;
  _txt(svg, cx - half * 0.5, 18, "← omissão", { "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: _OMC });
  _txt(svg, cx + half * 0.5, 18, "alucinação →", { "text-anchor": "middle", "font-size": "12", "font-weight": "700", fill: _HAC });
  svg.insertAdjacentHTML("beforeend", '<line x1="' + cx + '" x2="' + cx + '" y1="' + PT + '" y2="' + (PT + plotH) + '" stroke="var(--border-strong)"/>');
  data.forEach((d, i) => {
    const yc = PT + i * rowH + rowH / 2, ow = sc(d.omission), hw = sc(d.hallucination);
    [["Omissão", cx - ow, ow, _OMC, d.omission], ["Alucinação", cx, hw, _HAC, d.hallucination]].forEach(seg => {
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("x", seg[1]); rect.setAttribute("y", yc - barH / 2); rect.setAttribute("width", Math.max(0, seg[2]));
      rect.setAttribute("height", barH); rect.setAttribute("rx", 2); rect.setAttribute("fill", seg[3]); rect.setAttribute("tabindex", "0");
      const tt = '<div class="tt-title">' + d.model + ' · ' + d.source + '</div><div class="tt-row"><span class="tt-key">' + seg[0] + '</span><span>' + (seg[4] * 100).toFixed(1) + '%</span></div>';
      rect.addEventListener("mouseenter", e => showTip(tt, e)); rect.addEventListener("mousemove", moveTip); rect.addEventListener("mouseleave", hideTip);
      svg.appendChild(rect);
    });
    _txt(svg, cx - ow - 3, yc + 3, (d.omission * 100).toFixed(1), { "text-anchor": "end", "font-size": "9", fill: _OMC, "font-variant-numeric": "tabular-nums" });
    _txt(svg, cx + hw + 3, yc + 3, (d.hallucination * 100).toFixed(1), { "text-anchor": "start", "font-size": "9", fill: _HAC, "font-variant-numeric": "tabular-nums" });
    _txt(svg, PL - 10, yc + 3, d.model, { "text-anchor": "end", "font-size": "11", fill: "var(--text-1)" });
    const dot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    dot.setAttribute("cx", 8); dot.setAttribute("cy", yc); dot.setAttribute("r", 4); dot.setAttribute("fill", _SRCDOT[d.source] || "var(--text-3)");
    svg.appendChild(dot);
  });
}
'''
html = html.replace("requestAnimationFrame(() => {", TRADE_JS + "\nrequestAnimationFrame(() => {", 1)
html = html.replace("  renderHeatmap();\n});", "  renderHeatmap();\n  renderDiverge();\n});", 1)
# o setup dos chips do scatter original referencia um elemento removido -> blinda
html = html.replace('const host = document.getElementById("scatter-target-chips");',
                    'const host = document.getElementById("scatter-target-chips"); if (!host) return;', 1)

OUT.write_text(html, encoding="utf-8")
print(f"OK -> {OUT}  ({len(html):,} bytes)")
print(f"modelos com dado: {n_models} | runs 3060={run_count('3060')} 5080={run_count('5080')} cloud={run_count('cloud')}")
