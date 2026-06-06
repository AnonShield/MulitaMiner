"""TEMP — gera 2 PNGs para o paper, replicando os gráficos do report
(wticg/relatorio_local.html): cores, ordenação e escala idênticas.

  1) fig_tradeoff.png         — Per-model trade-off (tornado / diverging bars):
                                omission (left, red) x hallucination (right, amber),
                                per vulnerability, sorted by total error,
                                machine dot on the left (3060 / 5080 / cloud).
  2) fig_omission_heatmap.png — Per-field omission rate (matched vulns),
                                EXCLUINDO os 3 campos cinzas (instances, plugin,
                                plugin_details = NaN p/ todos). Linhas agrupadas
                                por máquina, com separação igual ao HTML.

Títulos/legendas em inglês. Saída em wticg/paper/.
Run: python wticg/analysis/make_paper_charts.py   (from repo root)
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap, Normalize
from matplotlib.transforms import blended_transform_factory
import numpy as np
import pandas as pd

WTICG = Path(__file__).resolve().parents[1]
OUT = WTICG / "paper"
OUT.mkdir(exist_ok=True)

# --- paleta idêntica ao report ---
SRC_COLOR = {"3060": "#f47174", "5080": "#e6b800", "cloud": "#4fb6e4"}
SRC_LABEL = {"3060": "RTX 3060 (12 GB)", "5080": "RTX 5080 (16 GB)", "cloud": "Cloud (284B)"}
OM_COLOR, HA_COLOR = "#d9534f", "#e0962f"  # omission / hallucination (report)
# gradiente de omissão do report: t = v/0.5 ; 0 verde, 0.5 âmbar, 1 vermelho
OMIS_CMAP = LinearSegmentedColormap.from_list(
    "omission", [(0.0, "#1f6644"), (0.5, "#e6b800"), (1.0, "#9a2424")])
OMIS_NORM = Normalize(vmin=0.0, vmax=0.5, clip=True)
GREY = "#737373"

# ordem dos modelos = report (3060, depois 5080, depois cloud)
MODELS = [
    ("gemma4", "3060"), ("ministral3", "3060"), ("qwen3_local", "3060"),
    ("llama31_local", "5080"), ("phi4", "5080"), ("foundation_sec", "5080"),
    ("primus", "5080"), ("gpt_oss", "5080"), ("deepseek_local", "5080"),
    ("deepseek", "cloud"),
]
# rótulos consistentes com a Tabela 2 do paper
LABEL = {
    "gemma4": "Gemma 4 E4B", "ministral3": "Ministral 3", "qwen3_local": "Qwen3",
    "llama31_local": "Llama 3.1", "phi4": "Phi-4", "foundation_sec": "Foundation-Sec",
    "primus": "Primus", "gpt_oss": "gpt-oss", "deepseek_local": "DeepSeek-Coder-V2",
    "deepseek": "deepseek-v4-flash",
}
DROP_FIELDS = {"instances", "plugin", "plugin_details"}  # cinzas (NaN p/ todos)


def load_long():
    return pd.concat(
        [pd.read_excel(WTICG / r / "aggregated_metrics.xlsx", sheet_name="Long")
         for r in ("3060", "5080", "cloud")], ignore_index=True)


def tradeoff(L):
    cov = L[(L.source == "coverage") & (L.field == "_overall")]
    piv = cov.pivot_table(index=["target", "model", "run"], columns="metric", values="value")
    piv["om"] = piv["n_baseline_unmatched"] / (piv["n_matched_pairs"] + piv["n_baseline_unmatched"])
    piv["ha"] = piv["n_extraction_unmatched"] / (piv["n_matched_pairs"] + piv["n_extraction_unmatched"])
    g = piv.groupby("model")[["om", "ha"]].mean() * 100.0

    rows = [(mid, src, float(g.loc[mid, "om"]), float(g.loc[mid, "ha"])) for mid, src in MODELS]
    rows.sort(key=lambda r: -(r[2] + r[3]))           # erro total desc (maior no topo)
    n = len(rows)
    mx = max(max(om, ha) for _, _, om, ha in rows)
    y = np.arange(n)

    fig, ax = plt.subplots(figsize=(8.0, 5.0), dpi=300)
    ax.axvline(0, color="#9aa0a6", lw=1.0, zorder=1)
    for yi, (mid, src, om, ha) in zip(y, rows):
        ax.barh(yi, -om, height=0.6, color=OM_COLOR, zorder=2)
        ax.barh(yi, ha, height=0.6, color=HA_COLOR, zorder=2)
        ax.text(-om - mx * 0.02, yi, f"{om:.1f}", ha="right", va="center",
                fontsize=10.5, color=OM_COLOR)
        ax.text(ha + mx * 0.02, yi, f"{ha:.1f}", ha="left", va="center",
                fontsize=10.5, color=HA_COLOR)
    ax.set_yticks(y)
    ax.set_yticklabels([LABEL[mid] for mid, _, _, _ in rows], fontsize=12.5)
    ax.set_xlim(-mx * 1.22, mx * 1.22)
    ax.set_ylim(n - 0.4, -1.3)                          # espaço p/ headers no topo
    ax.set_xticks([])
    for sp in ("top", "right", "bottom", "left"):
        ax.spines[sp].set_visible(False)
    ax.tick_params(length=0)
    ax.text(-mx * 0.5, -1.0, "← omission", ha="center", va="center",
            fontsize=13.5, weight="bold", color=OM_COLOR)
    ax.text(mx * 0.5, -1.0, "hallucination →", ha="center", va="center",
            fontsize=13.5, weight="bold", color=HA_COLOR)
    ax.set_title("Per-model trade-off: omission vs. hallucination (per vulnerability)",
                 fontsize=12.5, weight="bold", pad=16)
    fig.tight_layout()
    fig.savefig(OUT / "tradeoff.png", bbox_inches="tight")
    plt.close(fig)
    print("wrote", OUT / "tradeoff.png")


def omission_heatmap(L):
    omr = L[(L.source == "coverage") & (L.metric == "omission_rate") & (L.field != "_overall")]
    fields = [f for f in omr.field.unique() if f not in DROP_FIELDS]
    M = np.full((len(MODELS), len(fields)), np.nan)
    for i, (mid, _) in enumerate(MODELS):
        for j, f in enumerate(fields):
            v = omr[(omr.model == mid) & (omr.field == f)]["value"].dropna()
            if len(v):
                M[i, j] = v.mean()
    order = np.argsort(-np.nan_to_num(np.nanmean(M, axis=0)))   # omissão média desc
    fields = [fields[k] for k in order]
    M = M[:, order]
    ncol = len(fields)

    # posição vertical de cada linha, com GAP entre grupos de máquina (igual HTML)
    GAP = 0.55
    srcs = [s for _, s in MODELS]
    ytop, grp = [], 0
    for i in range(len(MODELS)):
        if i > 0 and srcs[i] != srcs[i - 1]:
            grp += 1
        ytop.append(i + grp * GAP)
    total_h = (len(MODELS) - 1) + grp * GAP + 1

    fig, ax = plt.subplots(figsize=(12.6, 6.4), dpi=300)
    for i in range(len(MODELS)):
        for j in range(ncol):
            v = M[i, j]
            color = GREY if np.isnan(v) else OMIS_CMAP(OMIS_NORM(v))
            ax.add_patch(plt.Rectangle((j, ytop[i]), 1, 1, facecolor=color,
                                       edgecolor="white", lw=1.2))
            if not np.isnan(v):
                lum = 0.299 * color[0] + 0.587 * color[1] + 0.114 * color[2]
                ax.text(j + 0.5, ytop[i] + 0.5, f"{v*100:.0f}", ha="center", va="center",
                        fontsize=11, color="white" if lum < 0.6 else "#222")
    # rótulos de modelo (NÃO coloridos)
    for i, (mid, _) in enumerate(MODELS):
        ax.text(-0.2, ytop[i] + 0.5, LABEL[mid], ha="right", va="center",
                fontsize=13, color="#222")
    # separação por máquina: colchete colorido + rótulo da fonte à esquerda
    bx = blended_transform_factory(ax.transData, ax.transData)
    groups = []
    for i, (_, s) in enumerate(MODELS):
        if groups and groups[-1][0] == s:
            groups[-1][2] = i
        else:
            groups.append([s, i, i])
    for s, a, b in groups:
        y0, y1 = ytop[a], ytop[b] + 1
        ax.plot([-4.4, -4.4], [y0 + 0.06, y1 - 0.06], color=SRC_COLOR[s], lw=3.2,
                solid_capstyle="round", transform=bx, clip_on=False)
        ax.text(-5.0, (y0 + y1) / 2, s.upper(), rotation=90, ha="center", va="center",
                fontsize=13, weight="bold", color=SRC_COLOR[s])
    ax.set_xlim(-5.4, ncol)
    ax.set_ylim(total_h, 0)                              # topo = primeira linha
    ax.set_xticks(np.arange(ncol) + 0.5)
    ax.set_xticklabels([f.replace("_", " ") for f in fields], fontsize=11,
                       rotation=35, ha="right", rotation_mode="anchor")
    ax.set_yticks([])
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title("Per-field omission rate (% of matched vulnerabilities)",
                 fontsize=12.5, weight="bold", pad=12)
    cb = fig.colorbar(plt.cm.ScalarMappable(norm=OMIS_NORM, cmap=OMIS_CMAP), ax=ax,
                      fraction=0.025, pad=0.02, ticks=[0, 0.25, 0.5])
    cb.ax.set_yticklabels(["0%", "25%", "≥50%"], fontsize=11)
    cb.outline.set_visible(False)
    fig.tight_layout()
    fig.savefig(OUT / "heatmap.png", bbox_inches="tight")
    plt.close(fig)
    print("wrote", OUT / "heatmap.png", "| fields:", fields)


def main():
    L = load_long()
    tradeoff(L)
    omission_heatmap(L)


if __name__ == "__main__":
    main()
