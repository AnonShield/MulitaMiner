"""Export specific charts from comparison_v1_v2_v3_en.html to standalone PDFs.

Outputs (in sbseg-tp/pdf/):
  01_tradeoff_all.pdf                 — Trade-off Hallucination × Omission (target=All)
  02_heatmap_omission.pdf             — Omission by Field heatmap
  03+_categories_bertscore_<base>.pdf — Similarity categories (BERTScore F1), one per baseline

Pre-req:
  pip install playwright
  playwright install chromium
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "sbseg-tp" / "comparison_v1_v2_v3_en.html").resolve()
OUT_DIR = ROOT / "sbseg-tp" / "pdf"
OUT_DIR.mkdir(exist_ok=True)

ISOLATE_JS = """
(sectionId) => {
  const sec = document.getElementById(sectionId);
  if (!sec) return;
  // Strip subtitle, filter/button rows, and section numbering — title + chart only.
  sec.querySelectorAll('.sub, .filters').forEach(el => el.remove());
  sec.querySelectorAll('h2 .ord').forEach(el => el.remove());
  // Replace body with just the target section so nothing else can affect flow/pagination.
  // Inline styles (background, padding) reset the page chrome.
  document.body.innerHTML = '';
  document.body.style.background = '#fff';
  document.body.style.margin = '0';
  document.body.style.padding = '16px 20px';
  document.body.appendChild(sec);
  // Section margin-bottom is irrelevant now; zero it out so bbox is tight.
  sec.style.marginBottom = '0';
  // Center the title.
  const h2 = sec.querySelector('h2');
  if (h2) { h2.style.justifyContent = 'center'; h2.style.textAlign = 'center'; }
  // Strip the chart-card frame (border + background + padding) — chart only.
  sec.querySelectorAll('.chart-card').forEach(c => {
    c.style.border = 'none';
    c.style.background = 'transparent';
    c.style.padding = '0';
  });
}
"""

def new_page(browser):
    page = browser.new_page(viewport={"width": 1200, "height": 800})
    page.emulate_media(color_scheme="light")
    page.goto(HTML.as_uri())
    page.wait_for_load_state("networkidle")
    # Charts render via requestAnimationFrame; give a beat after load.
    page.wait_for_timeout(400)
    return page


def isolate_and_pdf(page, section_id, out_path):
    """Isolate one section, measure its rendered box, and emit a PDF sized to fit it.

    Sizing the PDF to the section guarantees a single page with no pagination
    artifacts (title-on-previous-page, etc.).
    """
    page.evaluate(ISOLATE_JS, section_id)
    page.wait_for_timeout(300)
    box = page.evaluate(
        """() => ({
            w: Math.max(document.body.scrollWidth, document.documentElement.scrollWidth),
            h: Math.max(document.body.scrollHeight, document.documentElement.scrollHeight),
        })"""
    )
    page.pdf(
        path=str(out_path),
        width=f"{box['w']}px",
        height=f"{box['h']}px",
        print_background=True,
        margin={"top": "0", "bottom": "0", "left": "0", "right": "0"},
    )
    print(f"  -> {out_path.name}  ({box['w']}x{box['h']}px)")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()

        # 1. Trade-off scatter (target=All is the default chip).
        page = new_page(browser)
        isolate_and_pdf(page, "tradeoff", OUT_DIR / "01_tradeoff_all.pdf")
        page.close()

        # 2. Field-level omission heatmap.
        page = new_page(browser)
        isolate_and_pdf(page, "field-heatmap", OUT_DIR / "02_heatmap_omission.pdf")
        page.close()

        # 3+. Similarity categories per baseline (BERTScore F1 is the default metric).
        page = new_page(browser)
        baselines = page.evaluate(
            "Array.from(document.querySelectorAll('[data-cat-target]'))"
            ".map(b => b.dataset.catTarget)"
        )
        page.close()

        for i, baseline in enumerate(baselines, start=3):
            page = new_page(browser)
            # Click the baseline chip and let the chart re-render.
            page.click(f"[data-cat-target='{baseline}']")
            page.wait_for_timeout(400)
            safe = baseline.replace("/", "_").replace(" ", "_")
            isolate_and_pdf(
                page,
                "text-categories",
                OUT_DIR / f"{i:02d}_categories_bertscore_{safe}.pdf",
            )
            page.close()

        browser.close()

    print(f"\nDone. PDFs em {OUT_DIR}")


if __name__ == "__main__":
    main()
