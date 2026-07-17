"""
PDF extraction backends.

Each extractor encapsulates one way of turning a PDF into a (summary,
extraction) pair of Documents, plus the file extension that best
reflects its output format. Downstream code (block_creation, scanner
strategies) stays agnostic to the backend — it just receives an
`ExtractionResult` and threads `output_ext` through to filenames.

Adding a new backend = new subclass + entry in `get_extractor`.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from langchain_core.documents import Document


@dataclass
class ExtractionResult:
    summary: Document
    extraction: Document
    output_ext: str  # "txt", "md", ...


class PdfExtractor(ABC):
    output_ext: str = "txt"

    @abstractmethod
    def extract(self, pdf_path: str, scanner: Optional[str] = None) -> Optional[ExtractionResult]:
        ...


class PdfplumberExtractor(PdfExtractor):
    output_ext = "txt"

    def extract(self, pdf_path, scanner=None):
        from mulitaminer.readers.pdf_loader import extract_visual_layout_from_pdf
        docs = extract_visual_layout_from_pdf(pdf_path, scanner=scanner)
        if not docs or len(docs) < 2:
            return None
        return ExtractionResult(summary=docs[0], extraction=docs[1], output_ext=self.output_ext)


class MarkerExtractor(PdfExtractor):
    output_ext = "md"

    def extract(self, pdf_path, scanner=None):
        from mulitaminer.readers.pdf_loader import load_pdf_with_marker
        docs = load_pdf_with_marker(pdf_path, scanner=scanner)
        if not docs or len(docs) < 2:
            return None
        return ExtractionResult(summary=docs[0], extraction=docs[1], output_ext=self.output_ext)


def get_extractor(use_markdown: bool) -> PdfExtractor:
    return MarkerExtractor() if use_markdown else PdfplumberExtractor()
