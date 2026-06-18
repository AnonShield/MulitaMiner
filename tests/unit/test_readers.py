import pytest

from mulitaminer.readers import RawDocument, get_reader
from mulitaminer.readers.pdf import PdfReader


def test_get_reader_pdf_dispatch():
    assert isinstance(get_reader("some/where/report.pdf"), PdfReader)


def test_get_reader_case_insensitive_extension():
    assert isinstance(get_reader("REPORT.PDF"), PdfReader)


def test_get_reader_unknown_extension_raises():
    with pytest.raises(ValueError):
        get_reader("data.csv")


def test_rawdocument_defaults():
    doc = RawDocument(text="body")
    assert doc.text == "body"
    assert doc.visual_layout_path is None
    assert doc.output_ext == "txt"
    assert doc.source_format == "unknown"
