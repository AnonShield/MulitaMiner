"""Design tokens for the metrics report — dark/neon (page) + saturated chart palette.

Single source of truth for colors *that are shared* between the two
renderers. The page is intentionally cyberpunk-y (deep near-black
surfaces, neon accents); chart fills mirror the page palette so the
embedded figures feel native to the report.

═══════════════════════════════════════════════════════════════════════
Renderer-specific palettes (intentional divergence)
═══════════════════════════════════════════════════════════════════════

Most tokens here are consumed by BOTH renderers (Chart.js in the HTML
template, matplotlib in ``png.py``). A few intentionally diverge because
HTML lives on a dark surface and PNG lives on a white paper background —
the same hex doesn't read the same way on both.

  Token                    HTML (dark bg)          PNG (white bg)
  ──────────────────────   ─────────────────────   ──────────────────────
  ``MODEL_PALETTE``        shared                  shared
  ``STATUS``               shared                  shared
  ``SEQUENTIAL_STOPS``     used                    not used
  ``SEQUENTIAL_STOPS_LIGHT`` not used              used
  ``SIMILARITY_COLORS``    used (neon brand-tone)  not used — see below

The PNG renderer (``png.py``) overrides ``SIMILARITY_COLORS`` with a
legacy darker palette (``#185542 / #1543a5 / #e6a70a / #a81e1e /
#d3d5d8``) because the original paper-figure tradition uses those
exact tones and the print version reads better with them than with
the HTML neon variant. That override lives in ``png.py`` so this file
stays the single source of truth for the HTML report.
"""
from __future__ import annotations

from typing import Mapping


# Surface tokens — matches the template's :root.
SURFACE = {
    "bg":        "#0A0A0E",
    "panel":     "#1F1F2A",   # surface-2 — main chart background
    "panel_2":   "#28283A",   # surface-3 — hover/elevated
    "border":    "#2A2A3A",
    "border_2":  "#3A3A4A",
}

TEXT = {
    "primary":   "#F5F5FA",
    "secondary": "#C7C7D0",
    "muted":     "#8B8BA3",
}


# Categorical model palette — vibrant neon for cyberpunk-y dark page.
# Saturated enough to pop through 70% alpha without losing identity.
MODEL_PALETTE = [
    "#FF7A1A",  # neon orange (brand primary)
    "#5A009E",  # neon purple
    "#0FB371",  # neon mint-green
    "#2409BD",  # electric blue
    "#FFD43B",  # cyber yellow
    "#972274",  # hot pink
    "#50C2C2",  # neon cyan
    "#9B162E",  # neon red
]

STATUS = {
    "good":    "#2EE59D",
    "warn":    "#FFD43B",
    "bad":     "#FF4D6D",
    "neutral": "#8B8BA3",
}

# Sequential ramp for heatmaps on DARK bg (HTML report). Indigo → deep
# blue → cyan, kept on the saturated/dark side so it doesn't wash out
# against the page's near-black surfaces.
SEQUENTIAL_STOPS = [
    (0.0,  "#1F1F2A"),  # surface-2 — invisible cell == background
    (0.25, "#1E1B4B"),  # deep indigo
    (0.50, "#1E40AF"),  # navy blue
    (0.75, "#0E7490"),  # dark teal
    (1.0,  "#22D3EE"),  # saturated cyan (high-contrast peak)
]

# Sequential ramp for heatmaps on LIGHT bg (PNG paper figures). Same hue
# family flipped to read low→high as off-white→deep navy.
SEQUENTIAL_STOPS_LIGHT = [
    (0.0,  "#F0F6FA"),  # off-white
    (0.25, "#A5D8FF"),  # light cyan
    (0.50, "#29B6FF"),  # electric blue
    (0.75, "#0369A1"),  # deep blue
    (1.0,  "#0B1F3A"),  # dark navy
]

# Similarity bucket palette — saturated neon, brand-orange-tone (HSL high
# saturation, mid-low lightness). Avoids the candy/pastel feel.
# NOTE: HTML-only. ``png.py`` defines its own (legacy paper-figure) variant.
SIMILARITY_COLORS = {
    "Highly Similar":     "#2A9D8F",  # emerald teal — pairs with navy via the cyan-blue family
    "Moderately Similar": "#064789",  # deep sky blue
    "Slightly Similar":   "#F6B53C",  # brand-tone amber-orange
    "Divergent":          "#fe4a49",  # vivid red
    "Absent":             "#c7cedb",  # border-strong (muted dark)
}


# Per-metric chart fill colors. Used by both renderers (Chart.js in the
# template, matplotlib in png.py) — single source so adding a new scorer
# means adding one entry here.
METRIC_COLORS: Mapping[str, str] = {
    "Precision":  "#811378",  # neon mint-green
    "Recall":     "#18668D",  # electric blue
    "F1":         "#F3C33D",  # cyber yellow
    "BERTScore":  "#C05377",  # electric blue (semantic scorer)
    "ROUGE":      "#EB6969",  # neon purple   (lexical scorer)
    "Token-F1":   "#57B48F",  # neon mint-green (token-overlap scorer)
}

# CSS-token mirror for JS consumers (Chart.js defaults, contrast helpers).
# Whatever lives here MUST match the template's :root block — both are
# "the dark page theme", just emitted in different syntaxes.
THEME_TOKENS: Mapping[str, str] = {
    "text":          "#F5F5FA",  # --text
    "text_2":        "#C7C7D0",  # --text-2
    "surface_2":     "#1F1F2A",  # --surface-2
    "surface_3":     "#28283A",  # --surface-3
    "border":        "#2A2A3A",  # --border
    "border_strong": "#3A3A4A",  # --border-strong
}


METRIC_THRESHOLDS: Mapping[str, tuple[float, float, float]] = {
    "bertscore_f1": (0.70, 0.60, 0.40),
    "rouge_l":      (0.50, 0.35, 0.20),
    "token_f1":     (0.60, 0.45, 0.30),
    "presence":     (0.95, 0.85, 0.70),
    "f1":           (0.80, 0.65, 0.50),
    "precision":    (0.80, 0.65, 0.50),
    "recall":       (0.80, 0.65, 0.50),
}


def categorize(value: float, metric: str) -> str:
    excellent, good, fair = METRIC_THRESHOLDS.get(metric, (0.7, 0.6, 0.4))
    if value >= excellent: return "excellent"
    if value >= good:      return "good"
    if value >= fair:      return "fair"
    return "weak"


CATEGORY_COLORS = {
    "excellent": STATUS["good"],
    "good":      "#22d3a8",
    "fair":      STATUS["warn"],
    "weak":      STATUS["bad"],
}


def model_color(model: str, all_models: list[str]) -> str:
    if model not in all_models:
        return STATUS["neutral"]
    idx = sorted(all_models).index(model)
    return MODEL_PALETTE[idx % len(MODEL_PALETTE)]
