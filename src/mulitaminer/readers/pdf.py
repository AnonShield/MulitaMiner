"""PDF input reader.

Wraps the PDF extraction backends (pdfplumber / marker) and the visual-layout
dump into the format-agnostic :class:`RawDocument` contract.
"""
from __future__ import annotations

from typing import Optional

from mulitaminer.readers.base import InputReader, RawDocument, register
from mulitaminer.utils.extractors import get_extractor
from mulitaminer.utils.pdf_loader import save_visual_layout


@register
class PdfReader(InputReader):
    extensions = ('.pdf',)

    def read(self, path: str, scanner: Optional[str] = None,
             output_dir: Optional[str] = None, use_markdown: bool = False,
             **opts) -> Optional[RawDocument]:
        extractor = get_extractor(use_markdown)
        print(f"[PDF] Using extractor: {extractor.__class__.__name__}")
        result = extractor.extract(path, scanner)
        if result is None:
            return None

        # Write the visual layout (summary) so scanner strategies that need
        # visual context can read it back by path.
        visual_path = save_visual_layout(
            result.summary.page_content, path,
            output_ext=result.output_ext, output_dir=output_dir,
        )
        return RawDocument(
            text=result.extraction.page_content,
            visual_layout_path=visual_path,
            output_ext=result.output_ext,
            source_format="pdf",
        )
