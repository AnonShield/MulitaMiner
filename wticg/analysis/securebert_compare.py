"""Standalone — NÃO modifica nenhum script do pipeline (só lê).

Compara o BERTScore genérico (distilBERT, cru) com o SecureBERT (domínio cyber,
cru) nos MESMOS pares extração↔baseline, reusando (apenas lendo) o alinhamento
do pipeline. Gera um xlsx POR FONTE, juntando os modelos daquela fonte:

  wticg/3060/securebert_metrics_3060.xlsx    (gemma4, ministral3, qwen3_local)
  wticg/5080/securebert_metrics_5080.xlsx    (phi4, foundation_sec, primus, llama31, gpt_oss, deepseek_local)
  wticg/cloud/securebert_metrics_cloud.xlsx  (deepseek)

Base JUSTA: os dois backbones rodam com rescale_with_baseline=False (SecureBERT
não tem baseline pré-computado), então a diferença isola o MODELO, não o rescale.
Usa run1 por (modelo×baseline) — locais são determinísticos; cloud é 1 amostra.

Run:  python wticg/analysis/securebert_compare.py   (from repo root)
"""
import glob
import os
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
import torch
from bert_score import BERTScorer

WTICG = Path(__file__).resolve().parents[1]      # wticg/  (dados: wticg/{3060,5080,cloud})
REPO = Path(__file__).resolve().parents[2]       # raiz do repo (baselines/, metrics/)
sys.path.insert(0, str(REPO))

# reuso READ-ONLY dos helpers do pipeline (não altera nada)
from metrics.common.io import load_baseline, load_extraction
from metrics.common.aligner import align
from metrics.pipelines.compare_extractions import _common_fields

DEV = "cuda" if torch.cuda.is_available() else "cpu"
ROOTS = ["3060", "5080", "cloud"]


def baseline_for(target):
    return str(REPO / "baselines" / "openvas" / f"{target}.xlsx")


def batch_f1(scorer, preds, refs):
    if not preds:
        return []
    _, _, F = scorer.score(preds, refs, batch_size=64, verbose=False)
    return [max(0.0, min(1.0, float(x))) for x in F]


def collect_run(ext_file, base_file):
    """Pares (pred,ref) não-vazios por campo + total de pares casados (denominador)."""
    base = load_baseline(base_file)
    ext = load_extraction(ext_file)
    res = align(base, ext, method="greedy", allow_duplicates=True)
    pairs = dict(res.pairs)
    fields = _common_fields(base, ext)
    fp = {f: [] for f in fields}
    ft = {f: 0 for f in fields}
    for ext_idx, ext_row in ext.iterrows():
        if ext_idx not in pairs:
            continue
        brow = base.loc[pairs[ext_idx]]
        for f in fields:
            ft[f] += 1
            p = str(ext_row[f]).strip()
            r = str(brow[f]).strip()
            if p and r and p.lower() != "nan" and r.lower() != "nan":
                fp[f].append((p, r))
    return fp, ft


def main():
    print(f"device = {DEV}")
    print("carregando SecureBERT (ehsanaghaei/SecureBERT)...")
    sb = BERTScorer(model_type="ehsanaghaei/SecureBERT", num_layers=10, lang="en",
                    rescale_with_baseline=False, device=DEV)
    print("carregando distilBERT cru (base de comparação)...")
    db = BERTScorer(model_type="distilbert-base-uncased", lang="en",
                    rescale_with_baseline=False, device=DEV)

    for root in ROOTS:
        rootdir = str(WTICG / root)
        if not os.path.isdir(rootdir):
            print(f"[{root}] pasta não existe, pulando")
            continue
        flat_pred, flat_ref, flat_key = [], [], []
        totals = defaultdict(int)  # (model, target, field) -> nº de pares casados

        for tdir in sorted(glob.glob(os.path.join(rootdir, "*"))):
            target = os.path.basename(tdir)
            if not os.path.isdir(tdir) or not target.lower().startswith("openvas"):
                continue
            for mdir in sorted(glob.glob(os.path.join(tdir, "*"))):
                if not os.path.isdir(mdir):
                    continue
                model = os.path.basename(mdir)
                run1 = os.path.join(mdir, "run1")
                exts = [f for f in glob.glob(os.path.join(run1, "*.json"))
                        if not os.path.basename(f).startswith("schema_report")]
                if not exts:
                    continue
                try:
                    fp, ft = collect_run(exts[0], baseline_for(target))
                except Exception as e:
                    print(f"  [skip] {model}/{target}: {e}")
                    continue
                for f in ft:
                    totals[(model, target, f)] += ft[f]
                    for (p, r) in fp[f]:
                        flat_pred.append(p)
                        flat_ref.append(r)
                        flat_key.append((model, target, f))

        if not flat_pred:
            print(f"[{root}] nenhum par encontrado, pulando")
            continue
        print(f"[{root}] {len(flat_pred):,} pares — pontuando (SecureBERT + distilBERT)...")
        sb_scores = batch_f1(sb, flat_pred, flat_ref)
        db_scores = batch_f1(db, flat_pred, flat_ref)

        sb_sum, db_sum = defaultdict(float), defaultdict(float)
        for k, a, b in zip(flat_key, sb_scores, db_scores):
            sb_sum[k] += a
            db_sum[k] += b

        rows = []
        for (model, target, f), n in sorted(totals.items()):
            rows.append({
                "target": target, "model": model, "field": f, "n_matched": n,
                "securebert_f1": (sb_sum[(model, target, f)] / n) if n else 0.0,
                "distil_raw_f1": (db_sum[(model, target, f)] / n) if n else 0.0,
            })
        df = pd.DataFrame(rows)
        df["diff_secure_minus_distil"] = df["securebert_f1"] - df["distil_raw_f1"]
        out = os.path.join(rootdir, f"securebert_metrics_{root}.xlsx")
        df.to_excel(out, index=False)
        print(f"[{root}] -> {out}  ({len(df)} linhas, {df['model'].nunique()} modelos)")

    print("DONE")


if __name__ == "__main__":
    main()
